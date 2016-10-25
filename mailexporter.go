package main

import (
	"bytes"
	"errors"
	"flag"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"net/mail"
	"net/smtp"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	promlog "github.com/prometheus/log"
	"gopkg.in/fsnotify.v1"
	"gopkg.in/yaml.v2"
)

var tokenLength = 40 // length of token for probing-mails
const tokenChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// muxer is used to map probe-tokens to channels where the detection-goroutine should put the found mails.
var muxer = make(map[string]chan email)

// dispose token is used in probe to announce which tokens are no longer used for waiting for mails
var disposeToken = make(chan string)

type payload struct {
	configname string
	token      string
	timestamp  int64
}

// newPayload composes a payload to be used in probing mails for identification consisting
// of config name, unix time and a unique token for identification and returns it.
func newPayload(confname string) payload {
	//timestamp := strconv.FormatInt(time.Now().UnixNano(), 10)

	// Now get the token to have a unique token.
	token := generateToken(tokenLength)

	//payload = strings.Join([]string{name, token, time.Now().UnixNano()}, "-")
	p := payload{confname, token, time.Now().UnixNano()}
	promlog.Debug("composed payload:", p)

	return p
}

func (p payload) String() string {
	return strings.Join([]string{p.configname, p.token, p.timestring()}, "-")
}

func (p payload) timestring() string {
	return strconv.FormatInt(p.timestamp, 10)
}

// decomposePayload returns the config name and unix timestamp as appropriate types
// from given payload.
func decomposePayload(input []byte) (payload, error) {
	promlog.Debug("payload to decompose:", input)

	decomp := strings.Split(string(input), "-")
	// is it correctly parsable?
	if len(decomp) != 3 {
		promlog.Debug("no fitting decomp")
		return payload{}, errNotOurDept
	}

	extractedUnixTime, err := strconv.ParseInt(decomp[2], 10, 64)
	// is the last one a unix-timestamp?
	if err != nil {
		promlog.Debug("unix-timestamp-parse-error")
		return payload{}, errNotOurDept
	}

	return payload{decomp[0], decomp[1], extractedUnixTime}, nil
}

// holds a configuration of external server to send test mails
var globalconf struct {
	// The time to wait between probe-attempts.
	MonitoringInterval time.Duration
	// The time between start of monitoring-goroutines.
	StartupOffset time.Duration
	// The time to wait until mail_deliver_success = 0 is reported.
	MailCheckTimeout time.Duration

	// SMTP-Servers used for probing.
	Servers []smtpServerConfig
}

type smtpServerConfig struct {
	// The name the probing attempts via this server are classified with.
	Name string
	// The address of the SMTP-server.
	Server string
	// The port of the SMTP-server.
	Port string
	// The username for the SMTP-server.
	Login string
	// The SMTP-user's passphrase.
	Passphrase string
	// The sender-address for the probing mails.
	From string
	// The destination the probing-mails are sent to.
	To string
	// The directory in which mails sent by this server will end up if delivered correctly.
	Detectiondir string
}

var (
	// cli-flags
	confPath         = flag.String("config-file", "./mailexporter.conf", "config-file to use")
	webListenAddress = flag.String("web.listen-address", ":8080", "colon separated address and port mailexporter shall listen on")
	httpEndpoint     = flag.String("web.metrics-endpoint", "/metrics", "HTTP endpoint for serving metrics")

	// errors
	errNotOurDept = errors.New("no mail of ours")

	// listen-address
)

// holds information about probing-email with the corresponding file name
type email struct {
	// filename of the mailfile
	filename string
	// name of the configuration the mail originated from
	configname string
	// unique token to identify the mail even if timings and name are exactly the same
	token string
	// time the mail was sent as unix-timestamp
	tSent time.Time
	// time the mail was detected as unix-timestamp
	tRecv time.Time
}

// prometheus-instrumentation

var deliverOk = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "mail_deliver_success",
		Help: "indicatior whether last mail was delivered successfully",
	},
	[]string{"configname"},
)

var lastMailDeliverTime = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "mail_last_deliver_time",
		Help: "timestamp (in s) of detection of last correctly received testmail",
	},
	[]string{"configname"},
)

var lastMailDeliverDuration = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "mail_last_deliver_duration",
		Help: "duration (in ms) of delivery of last correctly received testmail",
	},
	[]string{"configname"},
)

var lateMails = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "mail_late_mails",
		Help: "number of probing-mails received after their respective timeout",
	},
	[]string{"configname"},
)

var mailSendFails = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "mail_send_fails",
		Help: "number of failed attempts to send a probing mail via specified SMTP-server",
	},
	[]string{"configname"},
)

var mailDeliverDurations = prometheus.NewHistogramVec(
	prometheus.HistogramOpts{
		Name:    "mail_deliver_durations",
		Help:    "durations (in ms) of mail delivery",
		Buckets: histBuckets(100e3, 50),
	},
	[]string{"configname"},
)

// histBuckets returns a linearly spaced []float64 to be used as Buckets in a prometheus.Histogram.
func histBuckets(upperBound float64, binSize float64) []float64 {
	bins := int(upperBound) / int(binSize)

	buckets := make([]float64, bins)
	binBorder := binSize
	for i := 0; i < bins; i++ {
		buckets[i] = binBorder
		binBorder += binSize
	}
	return buckets
}

func init() {
	prometheus.MustRegister(deliverOk)
	prometheus.MustRegister(lastMailDeliverTime)
	prometheus.MustRegister(lateMails)
	prometheus.MustRegister(lastMailDeliverDuration)
	prometheus.MustRegister(mailDeliverDurations)
	prometheus.MustRegister(mailSendFails)
}

func milliseconds(d time.Duration) int64 {
	return d.Nanoseconds() / int64(time.Millisecond)
}

// parseConfig parses configuration file and tells us if we are ready to rumble.
func parseConfig(r io.Reader) error {
	content, err := ioutil.ReadAll(r)
	if err != nil {
		return err
	}

	return yaml.Unmarshal(content, &globalconf)
}

// send sends a probing-email over SMTP-server specified in config c to be waited for on the receiving side.
func send(c smtpServerConfig, msg string) error {
	promlog.Debug("sending mail")
	fromheader := "From: " + c.From
	subjectheader := "Subject: " + "mailexporter-probe"
	fullmail := fromheader + "\n" + subjectheader + "\n" + msg

	var a smtp.Auth
	if c.Login == "" && c.Passphrase == "" { // if login and passphrase are left empty, skip authentication
		a = nil
	} else {
		a = smtp.PlainAuth("", c.Login, c.Passphrase, c.Server)
	}

	return smtp.SendMail(c.Server+":"+c.Port, a, c.From, []string{c.To}, []byte(fullmail))
}

// generateToken returns a random string to pad the send mail with for identifying
// it later in the maildir (and not mistake another one for it)
func generateToken(length int) string {
	stuff := make([]byte, length)

	rand.Seed(time.Now().UTC().UnixNano())
	for i := 0; i < length; i++ {
		stuff[i] = tokenChars[rand.Intn(len(tokenChars))]
	}

	return string(stuff)
}

// deleteMail delete the given mail to not leave an untidied maildir.
func deleteMail(m email) {
	if err := os.Remove(m.filename); err != nil {
		promlog.Warn(err)
	}
	promlog.Debug("rm ", m.filename)
}

// handleLateMail handles mails that have been so late that they timed out
func handleLateMail(m email) {
	promlog.Debug("got late mail via %s; mail took %d ms", m.configname, milliseconds(m.tRecv.Sub(m.tSent)))
	lateMails.WithLabelValues(m.configname).Inc()
	deleteMail(m)
}

// probe probes if mail gets through the entire chain from specified SMTPServer into Maildir.
func probe(c smtpServerConfig, p payload) {
	muxer[p.token] = make(chan email)

	//send(c, string(p))
	err := send(c, p.String())
	if err != nil {
		promlog.Warnf("error sending probe-mail via %s: %s; skipping attempt", c.Name, err)
		mailSendFails.WithLabelValues(c.Name).Inc()
		disposeToken <- p.token
		return
	}

	timeout := time.After(globalconf.MailCheckTimeout)
	select {
	case mail := <-muxer[p.token]:
		promlog.Debug("checking mail for timeout")

		deliverOk.WithLabelValues(c.Name).Set(1)
		deleteMail(mail)

	case <-timeout:
		promlog.Debug("Getting mail timed out.")
		deliverOk.WithLabelValues(c.Name).Set(0)
	}

	disposeToken <- p.token
}

// monitor probes every MonitoringInterval if mail still gets through.
func monitor(c smtpServerConfig) {
	log.Println("Started monitoring for config", c.Name)
	for {
		p := newPayload(c.Name)
		go probe(c, p)
		time.Sleep(globalconf.MonitoringInterval)
	}
}

// classifyMailMetrics extracts all general mail metrics such as deliver duration etc.
// from a mail struct and sets the corresponding metrics
func classifyMailMetrics(foundMail email) {
	// timestamps are in nanoseconds
	// last_mail_deliver_time shall be standard unix-timestamp
	// last_mail_deliver_duration shall be milliseconds for higher resolution
	deliverTime := float64(foundMail.tRecv.Unix())
	deliverDuration := float64(milliseconds(foundMail.tRecv.Sub(foundMail.tSent)))
	lastMailDeliverTime.WithLabelValues(foundMail.configname).Set(deliverTime)
	lastMailDeliverDuration.WithLabelValues(foundMail.configname).Set(deliverDuration)
	mailDeliverDurations.WithLabelValues(foundMail.configname).Observe(deliverDuration)
}

// detectAndMuxMail monitors Detectiondirs, reports mails that come in to the goroutine they belong to
// and takes care of removing unneeded report channels
func detectAndMuxMail(watcher *fsnotify.Watcher) {
	log.Println("Started mail-detection.")

	for {
		select {
		case event := <-watcher.Events:
			if event.Op&fsnotify.Create == fsnotify.Create {
				if foundMail, err := parseMail(event.Name); err == nil {

					// first of all: classify the mail
					classifyMailMetrics(foundMail)

					// then hand over so the timeout is judged
					if ch, ok := muxer[foundMail.token]; ok {
						ch <- foundMail
					} else {
						handleLateMail(foundMail)
					}
				}
			}
		case err := <-watcher.Errors:
			promlog.Warn("watcher-error:", err)
		case token := <-disposeToken:
			// deletion of channels is done here to avoid interference with the report-case of this goroutine
			close(muxer[token])
			delete(muxer, token)
		}
	}
}

func fileClose(f *os.File) {
	err := f.Close()
	if err != nil {
		promlog.Warn(err)
	}
}

// parseMail reads a mailfile's content and parses it into a mail-struct if one of ours.
func parseMail(path string) (email, error) {
	// to date the mails found
	t := time.Now()

	// try parsing
	f, err := os.Open(path)
	if err != nil {
		return email{}, err
	}
	defer fileClose(f)

	mail, err := mail.ReadMessage(io.LimitReader(f, 8192))
	if err != nil {
		return email{}, err
	}

	payl, err := ioutil.ReadAll(mail.Body)
	if err != nil {
		return email{}, err
	}
	payloadbytes := bytes.TrimSpace(payl) // mostly for trailing "\n"

	p, err := decomposePayload(payloadbytes)
	// return if parsable
	// (non-parsable mails are not sent by us (or broken) and therefore not needed
	if err != nil {
		return email{}, errNotOurDept
	}

	return email{path, p.configname, p.token, time.Unix(0, p.timestamp), t}, nil
}

func watcherClose(w *fsnotify.Watcher) {
	err := w.Close()
	if err != nil {
		promlog.Warn(err)
	}
}

func main() {
	flag.Parse()

	// seed the RNG, otherwise we would have same randomness on every startup
	// which should not, but might in worst case interfere with leftover-mails
	// from earlier starts of the binary
	rand.Seed(time.Now().Unix())

	f, err := os.Open(*confPath)
	if err != nil {
		promlog.Fatal(err)
	}
	defer fileClose(f)

	err = parseConfig(f)
	if err != nil {
		promlog.Fatal(err)
	}

	// initialize Metrics that will be used seldom so that they actually get exported with a metric
	for _, c := range globalconf.Servers {
		lateMails.WithLabelValues(c.Name)
		mailSendFails.WithLabelValues(c.Name)
	}

	fswatcher, err := fsnotify.NewWatcher()
	if err != nil {
		promlog.Fatal(err)
	}
	defer watcherClose(fswatcher)

	for _, c := range globalconf.Servers {
		promlog.Debug("adding path to watcher:", c.Detectiondir)
		errAdd := fswatcher.Add(c.Detectiondir) // deduplication is done within fsnotify
		if errAdd != nil {
			promlog.Warn(errAdd)
		}
	}

	go detectAndMuxMail(fswatcher)

	// now fire up the monitoring jobs
	for _, c := range globalconf.Servers {
		go monitor(c)

		// keep a timedelta between monitoring jobs to reduce interference
		// (although that shouldn't be an issue)
		time.Sleep(globalconf.StartupOffset)
	}

	log.Println("Starting HTTP-endpoint")
	http.Handle(*httpEndpoint, prometheus.Handler())

	promlog.Fatal(http.ListenAndServe(*webListenAddress, nil))
}
