package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/mail"
	"net/smtp"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	auth "github.com/abbot/go-http-auth"
	"github.com/prometheus/client_golang/prometheus"
	"gopkg.in/fsnotify.v1"
	"gopkg.in/yaml.v2"
)

var globalconf config
var contentLength = 40 // length of payload for probing-mails

// holds a configuration of external server to send test mails
type config struct {
	CrtPath      string
	KeyPath      string
	AuthUser     string
	AuthPass     string
	HTTPPort     string
	HTTPEndpoint string

	MonitoringInterval time.Duration
	StartupOffset time.Duration
	MailCheckTimeout  time.Duration

	Servers []SMTPServerConfig
	//Servers []map[string]string
}

type SMTPServerConfig struct {
	Name string
	Server string
	Port string
	Login string
	Passphrase string
	From string
	To string
	Detectiondir string
}

// cli-flags
var confPath = flag.String("config-file", "./mailexporter.conf", "config-file to use")
var useTLS = flag.Bool("tls", true, "use TLS for metrics-endpoint")
var useAuth = flag.Bool("auth", true, "use HTTP-Basic-Auth for metrics-endpoint")

// errors
var ErrMailNotFound = errors.New("no corresponding mail found")
var ErrNotOurDept = errors.New("no mail of ours")

// holds information about probing-email with the corresponding file name
type email struct {
	Filename string
	Name     string
	Token    string
	T_sent   int64
	T_recv   int64
}

// prometheus-instrumentation
var deliver_ok = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "mail_deliver_success",
		Help: "indicatior whether last mail was delivered successfully",
	},
	[]string{"configname"})

var last_mail_deliver_time = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "last_mail_deliver_time",
		Help: "timestamp (in s) of detection of last correctly received testmail",
	},
	[]string{"configname"})

var last_mail_deliver_duration = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "last_mail_deliver_duration",
		Help: "duration (in ms) of delivery of last correctly received testmail",
	},
	[]string{"configname"})

var late_mails = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "late_mails",
		Help: "number of probing-mails received after their respective timeout",
	},
	[]string{"configname"})

var mail_deliver_durations = prometheus.NewHistogramVec(
	prometheus.HistogramOpts{
		Name: "mail_deliver_durations",
		Help: "durations (in ms) of mail delivery",
		Buckets: histBuckets(100e3, 50),
	},
	[]string{"configname"})

func histBuckets(upperBound float64, binsize float64) []float64 {
	bins := int(upperBound)/int(binsize)

	buckets := make([]float64, bins)
	binborder := binsize
	for i := 0; i < bins; i++ {
		buckets[i] = binborder
		binborder += binsize
	}
	return buckets
}

func init() {
	prometheus.MustRegister(deliver_ok)
	prometheus.MustRegister(last_mail_deliver_time)
	prometheus.MustRegister(late_mails)
	prometheus.MustRegister(last_mail_deliver_duration)
	prometheus.MustRegister(mail_deliver_durations)
}

// parse configuration file and make sure we are ready to rumble
func parseConfig(path string) error {

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

// send email over SMTP-server specified in config c
func send(c SMTPServerConfig, msg string) {

	//fmt.Println("sending mail")
	a := smtp.PlainAuth("", c.Login, c.Passphrase, c.Server)
	err := smtp.SendMail(c.Server+":"+c.Port, a, c.From, []string{c.To}, []byte(msg))

	if err != nil {
		fmt.Println(err)
		fmt.Println(c.Server+":"+c.Port)
	}
}

// returns a random string to pad the send mail with for identifying
// it later in the maildir (and not mistake another one for it)
// does also return unprintable characters in returned string,
// which is actually appreciated to implicitly monitor that
// mail gets through unchanged
// although, if you would print those unprintable characters,
// be aware of funny side-effects like terminal commands being
// triggered and stuff like that
func randstring(length int) string {

	stuff := make([]byte, length)

	for i := range stuff {
		stuff[i] = byte(rand.Int())
	}

	rstr := string(stuff)

	// ensure no "-" are in the returned string
	// as "-" is used later as a field splitter
	rstr = strings.Replace(rstr, "-", "X", -1)

	// ensure no ":" are in the returned string
	// otherwise our payload might be made a header
	// instead of the mailbody by mail.Send()
	rstr = strings.Replace(rstr, ":", "X", -1)

	return rstr
}

// delete the given mail to not leave an untidied maildir
func delmail(m email) {
	err := os.Remove(m.Filename)
	if err != nil {
		fmt.Println(err)
	}
	//fmt.Println("rm ", m.Filename)
}

// compose a payload to be used in probing mails for identification
// consisting of config name, unix time and padding of appropriate length
func composePayload(name string, unixtimestamp int64) (string, string) {
	timestampstr := strconv.FormatInt(unixtimestamp, 10)
	remainingLength := contentLength - len(name) - len(timestampstr) - 2 // 2 for two delimiters

	// now get the token to have a unique token and use it to pad to full contentLength
	token := randstring(remainingLength)

	payload := name + "-" + token + "-" + timestampstr
	//fmt.Println("composed payload:", payload)

	return payload, token
}

// return the config name and unix timestamp as appropriate types
// from given payload
func decomposePayload(payload []byte) (string, string, int64, error) {

	// is the length correct?
	if len(payload) != contentLength {
		return "", "", -1, ErrNotOurDept
	}

	//fmt.Println("payload to decompose:", payload)

	decomp := strings.Split(string(payload), "-")

	// is it correctly parsable?
	if len(decomp) != 3 {
		//fmt.Println("no fitting decomp")
		return "", "", -1, ErrNotOurDept
	}

	extractedUnixtime, err := strconv.ParseInt(decomp[2], 10, 64)

	// is the last one a unix-timestamp?
	if err != nil {
		//fmt.Println("unix-timestamp-parse-error")
		return "", "", -1, ErrNotOurDept
	}

	return decomp[0], decomp[1], extractedUnixtime, nil
}

// log mails that have been so late that they timed out
func lateMail(m email) {
	//fmt.Println("got late mail via", m.Name)
	late_mails.WithLabelValues(m.Name).Inc()
}

// probe if mail gets through the entire chain from specified SMTP into Maildir
func probe(c SMTPServerConfig, reportChans map[string]chan email) {

	payload, token := composePayload(c.Name, time.Now().UnixNano())
	send(c, payload)

	timeout := time.After(globalconf.MailCheckTimeout)

	// "for seekingMail" is needed to account for mails that are coming late
	// otherwise, a late mail would trigger the first case and stop us from
	// being able to detect the mail we are actually waiting for
	seekingMail := true
	for seekingMail {
		select {
		case mail := <-reportChans[c.Name]:
			//fmt.Println("getting mail...")

			// timestamps are in nanoseconds
			// last_mail_deliver_time shall be standard unix-timestamp
			// last_mail_deliver_duration shall be milliseconds for higher resolution
			deliverTime := float64(mail.T_recv/int64(time.Second))
			deliverDuration := float64((mail.T_recv - mail.T_sent)/int64(time.Millisecond))
			last_mail_deliver_time.WithLabelValues(c.Name).Set(deliverTime)
			last_mail_deliver_duration.WithLabelValues(c.Name).Set(deliverDuration)
			mail_deliver_durations.WithLabelValues(c.Name).Observe(deliverDuration)

			if mail.Token == token {
				// we obtained the expected mail
				deliver_ok.WithLabelValues(c.Name).Set(1)
				delmail(mail)
				seekingMail = false

			} else {
				// it was another mail with unfitting token, probably late
				lateMail(mail)
			}

		case <-timeout:
			//fmt.Println("getting mail timed out")
			deliver_ok.WithLabelValues(c.Name).Set(0)
			seekingMail = false
		}

	}
}

// probe every couple of δt if mail still gets through
func monitor(c SMTPServerConfig, wg *sync.WaitGroup, reportChans map[string]chan email) {
	fmt.Println("started monitoring for config", c.Name)
	for {
		probe(c, reportChans)
		time.Sleep(globalconf.MonitoringInterval)
	}
	wg.Done()
}

// return secret for basic http-auth
func Secret(user, realm string) string {
	if user == globalconf.AuthUser {
		return globalconf.AuthPass
	}
	return ""
}

// monitor Detectiondirs and report mails that come in
func detectMail(watcher *fsnotify.Watcher, reportChans map[string]chan email) {

	fmt.Println("started mail-detection")

	for {
		select {
		case event := <-watcher.Events:
			if event.Op&fsnotify.Create == fsnotify.Create {
				mail, err := parseMail(event.Name)

				if err == nil {
					reportChans[mail.Name] <- mail
				}
			}
		case err := <-watcher.Errors:
			fmt.Println("watcher-error:", err)
		}
	}

}

// read a mailfile's content and parse it into a mail-struct if one of ours
func parseMail(path string) (email, error) {

	// to date the mails found
	t := time.Now().UnixNano()

	// try parsing
	content, _ := ioutil.ReadFile(path)
	mail, err := mail.ReadMessage(bytes.NewReader(content))

	payload := make([]byte, contentLength)
	mail.Body.Read(payload)

	name, token, unixtime, err := decomposePayload(payload)

	// return if parsable
	// (non-parsable mails are not sent by us (or broken) and therefore not needed
	if err == nil {
		return email{path, name, token, unixtime, t}, nil
	} else {
		return email{}, ErrNotOurDept
	}

}

func main() {

	flag.Parse()


	// seed the RNG, otherwise we would have same randomness on every startup
	// which should not, but might in worst case interfere with leftover-mails
	// from earlier starts of the binary
	rand.Seed(time.Now().Unix())

	err := parseConfig(*confPath)

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// initialize Metrics that will be used seldom so that they actually get exported with a metric
	for _, c := range globalconf.Servers {
		late_mails.GetMetricWithLabelValues(c.Name)
	}


	fswatcher, err := fsnotify.NewWatcher()

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	defer fswatcher.Close()

	reportChans := make(map[string]chan email)
	for _, c := range globalconf.Servers {
		fswatcher.Add(c.Detectiondir) // deduplication is done within fsnotify
		reportChans[c.Name] = make(chan email)
		//fmt.Println("adding path to watcher:", c.Detectiondir)
	}

	go detectMail(fswatcher, reportChans)

	wg := new(sync.WaitGroup)
	wg.Add(len(globalconf.Servers))

	// now fire up the monitoring jobs
	for _, c := range globalconf.Servers {
		go monitor(c, wg, reportChans)

		// keep a timedelta between monitoring jobs to reduce interference
		// (although that shouldn't be an issue)
		time.Sleep(globalconf.StartupOffset)
	}

	fmt.Println("starting HTTP-endpoint")
	if *useAuth {
		authenticator := auth.NewBasicAuthenticator("prometheus", Secret)
		http.HandleFunc(globalconf.HTTPEndpoint, auth.JustCheck(authenticator, prometheus.Handler().ServeHTTP))
	} else {
		http.Handle(globalconf.HTTPEndpoint, prometheus.Handler())
	}

	if *useTLS {
		err = http.ListenAndServeTLS(":"+globalconf.HTTPPort, globalconf.CrtPath, globalconf.KeyPath, nil)
	} else {
		err = http.ListenAndServe(":"+globalconf.HTTPPort, nil)
	}

	if err != nil {
		fmt.Println(err)
	}

	// wait for goroutines to exit
	// otherwise main would terminate and the goroutines monitoring would be killed
	wg.Wait()

}
