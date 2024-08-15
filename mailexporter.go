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
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"gopkg.in/fsnotify.v1"
	"gopkg.in/yaml.v2"
)

var (
	logInfo  = log.New(os.Stdout, "", 0)
	logWarn  = log.New(os.Stdout, "WARNING: ", 0)
	logDebug = log.New(os.Stdout, "DEBUG: ", 0)
	logError = log.New(os.Stdout, "ERROR: ", 0)
)

var tokenLength = 40 // length of token for probing-mails
const tokenChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// muxer is used to map probe-tokens to channels where the detection-goroutine should put the found mails.
var muxer = make(map[string]chan email)

// disposeToken is used in probe to announce which tokens are no longer used for waiting for mails
var disposeToken = make(chan string)

type payload struct {
	token      string
	timestamp  int64
	configname string
}

// newPayload composes a payload to be used in probing mails for identification consisting
// of config name, unix time and a unique token for identification and returns it.
func newPayload(confname string) payload {
	//timestamp := strconv.FormatInt(time.Now().UnixNano(), 10)

	// Now get the token to have a unique token.
	token := generateToken(tokenLength)

	//payload = strings.Join([]string{name, token, time.Now().UnixNano()}, "-")
	p := payload{token, time.Now().UnixNano(), confname}
	logDebug.Println("composed payload:", p)

	return p
}

func (p payload) String() string {
	return strings.Join([]string{p.token, p.timestring(), p.configname}, "-")
}

func (p payload) timestring() string {
	return strconv.FormatInt(p.timestamp, 10)
}

// decomposePayload returns the config name and unix timestamp as appropriate types
// from given payload.
func decomposePayload(input []byte) (payload, error) {
	logDebug.Println("payload to decompose:", input)

	decomp := strings.SplitN(string(input), "-", 3)
	// is it correctly parsable?
	if len(decomp) != 3 {
		logDebug.Println("no fitting decomp")
		return payload{}, errNotOurDept
	}

	extractedUnixTime, err := strconv.ParseInt(decomp[1], 10, 64)
	// is the last one a unix-timestamp?
	if err != nil {
		logDebug.Println("unix-timestamp-parse-error")
		return payload{}, errNotOurDept
	}

	return payload{decomp[0], extractedUnixTime, decomp[2]}, nil
}

// holds a configuration of external server to send test mails
var globalconf struct {
	// The time to wait between probe-attempts.
	MonitoringInterval time.Duration
	// The time to wait until mail_deliver_success = 0 is reported.
	MailCheckTimeout time.Duration
	// Disables deletion of probing-mails found
	DisableFileDeletion bool

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
	version          = flag.Bool("version", false, "Print version information")
	confPath         = flag.String("config.file", "/etc/mailexporter.conf", "Mailexporter configuration file to use.")
	logTimestamps    = flag.Bool("log.timestamps", false, "Enable timestamps for logging to stdout.")
	webListenAddress = flag.String("web.listen-address", ":9225", "Colon separated address and port to listen on for the telemetry.")
	httpEndpoint     = flag.String("web.telemetry-path", "/metrics", "Path under which to expose metrics.")
	verbosity        = flag.Int("v", 1, "verbosity; higher means more output")

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

type durationMetric struct {
	gauge *prometheus.GaugeVec
	hist  *prometheus.HistogramVec
}

func (m durationMetric) process(configname string, value float64) {
	m.gauge.WithLabelValues(configname).Set(value)
	m.hist.WithLabelValues(configname).Observe(value)
}

func (m durationMetric) register() {
	prometheus.MustRegister(m.gauge)
	prometheus.MustRegister(m.hist)
}

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
		Help: "unix-timestamp of detection of last correctly received mailprobe",
	},
	[]string{"configname"},
)

var lateMails = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "mail_late_mails_total",
		Help: "number of probing-mails received after their respective timeout",
	},
	[]string{"configname"},
)

var mailSendFails = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "mail_send_fails_total",
		Help: "number of failed attempts to send a probing mail via specified SMTP-server",
	},
	[]string{"configname"},
)

var (
	// mail_deliver_durations is linearly bucketed for low roundtrip-times and exponential for higher ones, to
	// inexpensively catch really all late-comers. Therefore we first build the linear part of the buckets and
	// afterwards we build larger buckets in an exponential fashion. Both are combined in the declaration of
	// mailDeliverDurations.

	delDurHistogramStart float64   = 0.25
	delDurLinSpacing     float64   = 0.25
	delDurLinBucketCount int       = 20
	delDurLinBuckets     []float64 = prometheus.LinearBuckets(delDurHistogramStart, delDurLinSpacing, delDurLinBucketCount)

	delDurExpFactor      float64   = 1.11
	delDurExpAreaStart   float64   = delDurLinBuckets[delDurLinBucketCount-1] * delDurExpFactor
	delDurExpBucketCount int       = 35
	delDurExpBuckets     []float64 = prometheus.ExponentialBuckets(delDurExpAreaStart, delDurExpFactor, delDurExpBucketCount)

	deliverDurationHist = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "mail_deliver_durations_seconds",
			Help:    "durations of mail delivery",
			Buckets: append(delDurLinBuckets, delDurExpBuckets...),
		},
		[]string{"configname"},
	)

	deliverDurationGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "mail_last_deliver_duration_seconds",
			Help: "duration of delivery of last correctly received mailprobe",
		},
		[]string{"configname"},
	)

	mailDeliverDuration = durationMetric{deliverDurationGauge, deliverDurationHist}
)

var (
	// same game for last_send_duration as for last_deliver_duration above

	sendDurHistogramStart float64   = 0.1
	sendDurLinSpacing     float64   = 0.1
	sendDurLinBucketCount int       = 10
	sendDurLinBuckets     []float64 = prometheus.LinearBuckets(sendDurHistogramStart, sendDurLinSpacing, sendDurLinBucketCount)

	sendDurExpFactor      float64   = 1.3
	sendDurExpAreaStart   float64   = sendDurLinBuckets[sendDurLinBucketCount-1] * sendDurExpFactor
	sendDurExpBucketCount int       = 25
	sendDurExpBuckets     []float64 = prometheus.ExponentialBuckets(sendDurExpAreaStart, sendDurExpFactor, sendDurExpBucketCount)

	sendDurationHist = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "mail_send_durations_seconds",
			Help:    "durations of valid mail handovers to exernal SMTP-servers",
			Buckets: append(sendDurLinBuckets, sendDurExpBuckets...),
		},
		[]string{"configname"},
	)

	sendDurationGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "mail_last_send_duration_seconds",
			Help: "duration of last valid mail handover to external SMTP-server",
		},
		[]string{"configname"},
	)

	mailSendDuration = durationMetric{sendDurationGauge, sendDurationHist}
)

func init() {
	prometheus.MustRegister(deliverOk)
	prometheus.MustRegister(lastMailDeliverTime)
	prometheus.MustRegister(lateMails)
	prometheus.MustRegister(mailSendFails)
	mailDeliverDuration.register()
	mailSendDuration.register()

}

// parseConfig parses configuration file and tells us if we are ready to rumble.
func parseConfig(r io.Reader) error {
	content, err := ioutil.ReadAll(r)
	if err != nil {
		return err
	}

	return yaml.Unmarshal(content, &globalconf)
}

func createMsgId(c smtpServerConfig, msg string) string {
	addrParts := strings.Split(c.From, "@")
	if len(addrParts) > 1 {
		return msg + "@" + addrParts[1]
	} else {
		return msg + "-" + c.From
	}
}

// send sends a probing-email over SMTP-server specified in config c to be waited for on the receiving side.
func send(c smtpServerConfig, msg string) error {
	logDebug.Println("sending mail")
	fullmail := "From: " + c.From + "\r\n"
	fullmail += "To: " + c.To + "\r\n"
	fullmail += "Subject: mailexporter-probe" + "\r\n"
	fullmail += "Content-Type: text/plain" + "\r\n"
	fullmail += "Message-Id: <" + createMsgId(c, msg) + ">\r\n"

	fullmail += "Date: " + time.Now().Format(time.RFC3339) + "\r\n"

	fullmail += "\r\n" + msg

	var a smtp.Auth
	if c.Login == "" && c.Passphrase == "" { // if login and passphrase are left empty, skip authentication
		a = nil
	} else {
		a = smtp.PlainAuth("", c.Login, c.Passphrase, c.Server)
	}

	t1 := time.Now()
	err := smtp.SendMail(c.Server+":"+c.Port, a, c.From, []string{c.To}, []byte(fullmail))
	t2 := time.Now()
	diff := t2.Sub(t1)

	sendDuration := float64(diff.Seconds())
	mailSendDuration.process(c.Name, sendDuration)

	return err
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
func deleteMailIfEnabled(m email) {
	if globalconf.DisableFileDeletion {
		logDebug.Println("file deletion disabled in config, not touching", m.filename)
	} else {
		if err := os.Remove(m.filename); err != nil {
			logWarn.Println("deletion error:", err)
		}
		logDebug.Println("rm ", m.filename)
	}
}

// handleLateMail handles mails that have been so late that they timed out
func handleLateMail(m email) {
	logDebug.Printf("got late mail via %s; mail took %d\n", m.configname, m.tRecv.Sub(m.tSent))
	lateMails.WithLabelValues(m.configname).Inc()
	deleteMailIfEnabled(m)
}

// probe probes if mail gets through the entire chain from specified SMTPServer into Maildir.
func probe(c smtpServerConfig, p payload) {
	muxer[p.token] = make(chan email)

	//send(c, string(p))
	err := send(c, p.String())
	if err != nil {
		logWarn.Printf("error sending probe-mail via %s: %s; skipping attempt\n", c.Name, err)
		mailSendFails.WithLabelValues(c.Name).Inc()
		disposeToken <- p.token
		return
	}

	timeout := time.After(globalconf.MailCheckTimeout)
	select {
	case mail := <-muxer[p.token]:
		logDebug.Println("checking mail for timeout")

		deliverOk.WithLabelValues(c.Name).Set(1)
		deleteMailIfEnabled(mail)

	case <-timeout:
		logWarn.Println("Delivery-Timeout, Message-ID: " + createMsgId(c, p.String()))
		deliverOk.WithLabelValues(c.Name).Set(0)
	}

	disposeToken <- p.token
}

// monitor probes every MonitoringInterval if mail still gets through.
func monitor(c smtpServerConfig) {
	//delay start of monitoring randomly to desync the probing of the monitoring-coroutines
	time.Sleep(time.Duration(rand.Int()%20000) * time.Millisecond)
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
	// last_mail_deliver_duration shall be seconds (SI-Units)
	deliverTime := float64(foundMail.tRecv.Unix())
	deliverDuration := foundMail.tRecv.Sub(foundMail.tSent).Seconds()
	lastMailDeliverTime.WithLabelValues(foundMail.configname).Set(deliverTime)
	mailDeliverDuration.process(foundMail.configname, deliverDuration)
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
			logWarn.Println("watcher-error:", err)
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
		logWarn.Println("error when closing file:", err)
	}
}

// parseMail reads a mailfile's content and parses it into a mail-struct if one of ours.
func parseMail(path string) (email, error) {
	// to date the mails found
	t := time.Now()

	// try parsing
	b, err := os.ReadFile(path)
	if err != nil {
		return email{}, err
	}

	mail, err := mail.ReadMessage(bytes.NewReader(b))
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
		logWarn.Println("error when closing watcher:", err)
	}
}

func main() {
	flag.Parse()
	if *version {
		logInfo.Println("Prometheus-Mailexporter")
		logInfo.Printf(" :: version %s", "dev")
		logInfo.Printf(" :: Go-version: %s", runtime.Version())
		os.Exit(0)
	}

	// handle log-verbosity
	if *verbosity < 1 {
		// disable everything except error logs
		logInfo.SetOutput(ioutil.Discard)
		logWarn.SetOutput(ioutil.Discard)
	}
	if *verbosity < 2 {
		// disable Debug-logs (default)
		logDebug.SetOutput(ioutil.Discard)
	}

	// handle log-timestamping
	if *logTimestamps {
		logInfo.SetFlags(3)
		logWarn.SetFlags(3)
		logDebug.SetFlags(3)
		logError.SetFlags(3)
	}

	// seed the RNG, otherwise we would have same randomness on every startup
	// which should not, but might in worst case interfere with leftover-mails
	// from earlier starts of the binary
	rand.Seed(time.Now().Unix())

	f, err := os.Open(*confPath)
	if err != nil {
		logError.Fatal(err)
	}
	defer fileClose(f)

	err = parseConfig(f)
	if err != nil {
		logError.Fatal(err)
	}

	// initialize Metrics that will be used seldom so that they actually get exported with a metric
	for _, c := range globalconf.Servers {
		lateMails.WithLabelValues(c.Name)
		mailSendFails.WithLabelValues(c.Name)
	}

	fswatcher, err := fsnotify.NewWatcher()
	if err != nil {
		logError.Fatal(err)
	}
	defer watcherClose(fswatcher)

	for _, c := range globalconf.Servers {
		logDebug.Println("adding path to watcher:", c.Detectiondir)
		errAdd := fswatcher.Add(c.Detectiondir) // deduplication is done within fsnotify
		if errAdd != nil {
			logWarn.Printf("error adding filesystem-watcher to %s: %s\n", c.Detectiondir, errAdd)
		}
	}

	go detectAndMuxMail(fswatcher)

	//starts monitoring goroutines for specified SMTP-server
	for _, c := range globalconf.Servers {
		go monitor(c)
	}

	log.Println("Starting HTTP-endpoint")
	http.Handle(*httpEndpoint, promhttp.Handler())

	logError.Fatal(http.ListenAndServe(*webListenAddress, nil))
}
