package main

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/mail"
	"net/smtp"
	"os"
	"sync"
	"time"
	"flag"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
	"gopkg.in/yaml.v2"
	auth "github.com/abbot/go-http-auth"
)

var globalconf config

var conf_path = flag.String("conf_path", "/etc/mailprober.conf", "config-file to use")
var useTLS = flag.Bool("tls", true, "use TLS for metrics-endpoint")
var useAuth = flag.Bool("auth", true, "use HTTP-Basic-Auth for metrics-endpoint")

var ErrMailNotFound = errors.New("no corresponding mail found")

var content_length int = 7

// to be filled during main()
var monitoringInterval time.Duration
var startupOffsetTime time.Duration
var mailCheckTimeout time.Duration

// prometheus-instrumentation
var deliver_ok = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "mail_deliver_success",
		Help: "indicatior whether last mail was delivered successfully",
	},
	[]string{"configname"})

func init() {
	prometheus.MustRegister(deliver_ok)
}

// holds a configuration of external server to send test mails
type config struct {
	Crt_path string
	Key_path string
	Auth_user string
	Auth_pw string

	Monitoring_interval string
	Startup_offset_time string
	Mail_check_timeout string

	Servers []map[string]string
}

// holds an email with the corresponding file name
type email struct {
	filename string
	content  *mail.Message
}

func parse_conf(path string) error {

	content, err := ioutil.ReadFile(path)

	if err != nil {
		return err
	}

	err = yaml.Unmarshal(content, &globalconf)

	if err != nil {
		return err
	}


	// yaml-lib in use cannot parse ints unfortunately, just strings
	// therefore this is for the moment the least PITA-solution
	// as we want to have at least a properly parsable config

	// convert to int
	var monitoringInterval_int, startupOffsetTime_int, mailCheckTimeout_int int
	errs := make([]error, 3)
	monitoringInterval_int, errs[0] = strconv.Atoi(globalconf.Monitoring_interval)
	startupOffsetTime_int, errs[1] = strconv.Atoi(globalconf.Startup_offset_time)
	mailCheckTimeout_int, errs[2] = strconv.Atoi(globalconf.Mail_check_timeout)

	parsingErrors := false
	for _, e := range errs {
		if e != nil {
			fmt.Println(err)
			parsingErrors = true
		}
	}

	if parsingErrors {
		return errors.New("parsing errors in configuration")
	}

	// now convert to duration
	monitoringInterval = time.Duration(monitoringInterval_int) * time.Minute
	startupOffsetTime  = time.Duration(startupOffsetTime_int) * time.Second
	mailCheckTimeout   = time.Duration(mailCheckTimeout_int) * time.Second


	return nil

}

// looks into the specified detectiondir to find and parse all mails in that dir
func parse_mails(c map[string]string) []email {

	// get entries of directory
	files, _ := ioutil.ReadDir(c["Detectiondir"])

	// allocate space to store the parsed mails
	mails := make([]email, 0, len(files))

	// loop over all non-dir-files and try to parse mails
	// return a slice of those files that are parsable as mail
	for _, f := range files {

		if !f.IsDir() {

			// try parsing
			content, _ := ioutil.ReadFile(c["Detectiondir"] + "/" + f.Name())
			mail, err := mail.ReadMessage(bytes.NewReader(content))

			// save if parsable
			if err == nil {
				mails = append(mails, email{f.Name(), mail})
			}

		}

	}

	return mails
}

// send email over SMTP-server specified in config
func send(c map[string]string, msg string) {

	//fmt.Println("sending mail")
	a := smtp.PlainAuth("", c["Login"], c["Passphrase"], c["Server"])
	err := smtp.SendMail(c["Server"]+":"+c["Port"], a, c["From"], []string{c["To"]}, []byte(msg))

	if err != nil {
		fmt.Println(err)
	}
}

// take a bunch of mails and filter for the one that actually has the
// correct text in it
func filter(msg string, mails []email) (email, error) {

	stuff := make([]byte, content_length)

	for _, m := range mails {
		m.content.Body.Read(stuff)
		if string(stuff) == msg {
			return m, nil
		}
	}

	return email{}, ErrMailNotFound
}

// returns a random string to prepare the send mail for finding
// it later in the maildir (and not mistake another one for it)
// does also return unprintable characters in returned string,
// which is actually appreciated to implicitly monitor that
// mail gets through unchanged
func randstring(length int) string {

	stuff := make([]byte, content_length)

	for i := range stuff {
		stuff[i] = byte(rand.Int())
	}

	return string(stuff)
}

// delete the given mail to not leave an untidied maildir
func delmail(c map[string]string, m email) {
	os.Remove(c["Detectiondir"] + "/" + m.filename)
	//fmt.Println("rm ", c["Detectiondir"]+"/"+m.filename)
}

// probe if mail gets through (main monitoring component)
func probe(c map[string]string) {

	content := randstring(content_length)

	// constant, non-random string for testing purposes
	content = "shaboom"

	send(c, content)

	timeout := time.After(mailCheckTimeout)

	// now wait for mail to arrive
	// subject to change, might get changed to fsnotify or so
	seekingMail := true
	for seekingMail {
		select {
		default:
			//fmt.Println("getting mail...")
			mails := parse_mails(c)

			mail, err := filter(content, mails)

			if err == nil {
				//fmt.Println("mail found")
				delmail(c, mail)
				seekingMail = false
				deliver_ok.WithLabelValues(c["Name"]).Set(1)
			}

		case <-timeout:
			//fmt.Println("getting mail timed out")
			seekingMail = false
			deliver_ok.WithLabelValues(c["Name"]).Set(0)
		}

		time.Sleep(5 * time.Millisecond)

	}
}

// probe every couple of δt if mail still gets through
func monitor(c map[string]string, wg *sync.WaitGroup) {
	for {
		probe(c)
		time.Sleep(monitoringInterval)
	}
	wg.Done()
}

// secret for basic http-auth
func Secret(user, realm string) string {
	if user == globalconf.Auth_user {
		return globalconf.Auth_pw
	}
	return ""
}

func main() {

	start := time.Now()

	flag.Parse()

	err := parse_conf(*conf_path)

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}


	wg := new(sync.WaitGroup)
	wg.Add(len(globalconf.Servers))

	// now fire up the monitoring jobs
	for i, c := range globalconf.Servers {
		fmt.Println("starting monitoring for config", i)
		go monitor(c, wg)

		// keep a timedelta between monitoring jobs to avoid strong interference
		time.Sleep(startupOffsetTime)
	}

	elapsed := time.Since(start)
	fmt.Println(elapsed)

	fmt.Println("starting HTTP-endpoint")
	if *useAuth {
		authenticator := auth.NewBasicAuthenticator("prometheus", Secret)
		http.HandleFunc("/metrics", auth.JustCheck(authenticator, prometheus.Handler().ServeHTTP))
	} else {
		http.Handle("/metrics", prometheus.Handler())
	}


	if *useTLS {
		err = http.ListenAndServeTLS(":8080", globalconf.Crt_path, globalconf.Key_path,  nil)
	} else {
		err = http.ListenAndServe(":8080",  nil)
	}

	if err != nil {
		fmt.Println(err)
	}

	// wait for goroutines to exit
	// otherwise main would terminate and the goroutines would be killed
	wg.Wait()

}
