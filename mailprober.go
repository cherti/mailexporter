package main

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/mail"
	"net/smtp"
	"os"
	"strings"
	"sync"
	"time"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
)

// global compiled configuration parameters
var conf_path string = "./conf"
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
	name         string
	server       string
	port         string
	login        string
	passphrase   string
	from         string
	to           string
	detectiondir string
}

// holds an email with the corresponding file name
type email struct {
	filename string
	content  *mail.Message
}

// very basic configuration parser
func parse_conf(path string) []config {

	content, _ := ioutil.ReadFile(path)

	sc := strings.Split(string(content), "\n")

	configcount := len(sc) / numberConfigOptions
	configs := make([]config, configcount)

	for i := 0; i < configcount; i++ {
		j := i * numberConfigOptions
		configs[i] = config{sc[j+0], sc[j+1], sc[j+2], sc[j+3], sc[j+4], sc[j+5], sc[j+6], sc[j+7]}
	}
	//fmt.Println("confnumber:", len(configs))

	return configs

}

// looks into the specified detectiondir to find and parse all mails in that dir
func parse_mails(c config) []email {

	// get entries of directory
	files, _ := ioutil.ReadDir(c.detectiondir)

	// allocate space to store the parsed mails
	mails := make([]email, 0, len(files))

	// loop over all non-dir-files and try to parse mails
	// return a slice of those files that are parsable as mail
	for _, f := range files {

		if !f.IsDir() {

			// try parsing
			content, _ := ioutil.ReadFile(c.detectiondir + "/" + f.Name())
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
func send(c config, msg string) {

	//fmt.Println("sending mail")
	a := smtp.PlainAuth("", c.login, c.passphrase, c.server)
	err := smtp.SendMail(c.server+":"+c.port, a, c.from, []string{c.to}, []byte(msg))

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
func delmail(c config, m email) {
	os.Remove(c.detectiondir + "/" + m.filename)
	//fmt.Println("rm ", c.detectiondir+"/"+m.filename)
}

// probe if mail gets through (main monitoring component)
func probe(c config) {

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
				deliver_ok.WithLabelValues(c.name).Set(1)
			}

		case <-timeout:
			//fmt.Println("getting mail timed out")
			seekingMail = false
			deliver_ok.WithLabelValues(c.name).Set(0)
		}

		time.Sleep(5 * time.Millisecond)

	}
}

// probe every couple of δt if mail still gets through
func monitor(c config, wg *sync.WaitGroup) {
	for {
		probe(c)
		time.Sleep(monitoringInterval)
	}
	wg.Done()
}

func main() {


	start := time.Now()

	configs := parse_conf(conf_path)

	wg := new(sync.WaitGroup)
	wg.Add(len(configs))

	// now fire up the monitoring jobs
	for i, c := range configs {
		fmt.Println("starting monitoring for config", i)
		go monitor(c, wg)

		// keep a timedelta between monitoring jobs to avoid strong interference
		time.Sleep(antiInterferenceInterval)
	}

	elapsed := time.Since(start)
	fmt.Println(elapsed)

	fmt.Println("starting HTTP-endpoint")
	http.Handle("/metrics", prometheus.Handler())
	http.ListenAndServe(":8080", nil)

	// wait for goroutines to exit
	// otherwise main would terminate and the goroutines would be killed
	wg.Wait()

}
