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

	"github.com/prometheus/client_golang/prometheus"
	"gopkg.in/yaml.v2"
	auth "github.com/abbot/go-http-auth"
)

var globalconf config

// global compiled configuration parameters
var conf_path string = "./config.yml"
var content_length int = 7
var ErrMailNotFound = errors.New("no corresponding mail found")
var mailCheckTimeout = 10 * time.Second
var monitoringInterval = 1 * time.Minute
var numberConfigOptions = 8
var antiInterferenceInterval = 15 * time.Second

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
	Auth_user string
	Auth_pw string
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

	err := parse_conf(conf_path)

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
		time.Sleep(antiInterferenceInterval)
	}


	authenticator := auth.NewBasicAuthenticator("prometheus", Secret)

	elapsed := time.Since(start)
	fmt.Println(elapsed)

	fmt.Println("starting HTTP-endpoint")
	http.HandleFunc("/metrics", auth.JustCheck(authenticator, prometheus.Handler().ServeHTTP))
	http.ListenAndServe(":8080", nil)

	// wait for goroutines to exit
	// otherwise main would terminate and the goroutines would be killed
	wg.Wait()

}
