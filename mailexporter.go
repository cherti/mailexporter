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

	auth "github.com/abbot/go-http-auth"
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

// composePayload composes a payload to be used in probing mails for identification
// consisting of config name, unix time and a unique token for identification.
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
		return payload{}, ErrNotOurDept
	}

	extractedUnixTime, err := strconv.ParseInt(decomp[2], 10, 64)
	// is the last one a unix-timestamp?
	if err != nil {
		promlog.Debug("unix-timestamp-parse-error")
		return payload{}, ErrNotOurDept
	}

	return payload{decomp[0], decomp[1], extractedUnixTime}, nil
}

// holds a configuration of external server to send test mails
var globalconf struct {
	// The path to the TLS-Public-Key.
	CrtPath string
	// The path to the TLS-Private-Key.
	KeyPath string
	// The username for HTTP Basic Auth.
	AuthUser string
	// The passphrase for HTTP Basic Auth.
	AuthPass string
	// The hashvalue to be used in HTTP Basic Auth (filled in parseConfig).
	authHash string
	// The port to listen on for Prometheus-Endpoint.
	HTTPPort string
	// The URL for prometheus' metrics-endpoint.
	HTTPEndpoint string

	// The time to wait between probe-attempts.
	MonitoringInterval time.Duration
	// The time between start of monitoring-goroutines.
	StartupOffset time.Duration
	// The time to wait until mail_deliver_success = 0 is reported.
	MailCheckTimeout time.Duration

	// SMTP-Servers used for probing.
	Servers []SMTPServerConfig
}

type SMTPServerConfig struct {
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
	confPath = flag.String("config-file", "./mailexporter.conf", "config-file to use")
	useTLS   = flag.Bool("tls", true, "use TLS for metrics-endpoint")
	useAuth  = flag.Bool("auth", true, "use HTTP-Basic-Auth for metrics-endpoint")

	// errors
	ErrMailNotFound = errors.New("no corresponding mail found")
	ErrNotOurDept   = errors.New("no mail of ours")
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
	t_sent time.Time
	// time the mail was detected as unix-timestamp
	t_recv time.Time
}

// prometheus-instrumentation

var deliver_ok = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "mail_deliver_success",
		Help: "indicatior whether last mail was delivered successfully",
	},
	[]string{"configname"},
)

var last_mail_deliver_time = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "last_mail_deliver_time",
		Help: "timestamp (in s) of detection of last correctly received testmail",
	},
	[]string{"configname"},
)

var last_mail_deliver_duration = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "last_mail_deliver_duration",
		Help: "duration (in ms) of delivery of last correctly received testmail",
	},
	[]string{"configname"},
)

var late_mails = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "late_mails",
		Help: "number of probing-mails received after their respective timeout",
	},
	[]string{"configname"},
)

var mail_send_fails = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "mail_send_fails",
		Help: "number of failed attempts to send a probing mail via specified SMTP-server",
	},
	[]string{"configname"},
)

var mail_deliver_durations = prometheus.NewHistogramVec(
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
	prometheus.MustRegister(deliver_ok)
	prometheus.MustRegister(last_mail_deliver_time)
	prometheus.MustRegister(late_mails)
	prometheus.MustRegister(last_mail_deliver_duration)
	prometheus.MustRegister(mail_deliver_durations)
	prometheus.MustRegister(mail_send_fails)
}

func milliseconds(d time.Duration) int64 {
	return d.Nanoseconds()/int64(time.Millisecond)
}

// parseConfig parses configuration file and tells us if we are ready to rumble.
func parseConfig(r io.Reader) error {
	content, err := ioutil.ReadAll(r)
	if err != nil {
		return err
	}

	err = yaml.Unmarshal(content, &globalconf)
	if err != nil {
		return err
	}

	// the basic HTTP-Auth-Lib doesn't support Plaintext-passwords up to now, therefore precompute an md5-hash for that
	globalconf.authHash = string(auth.MD5Crypt([]byte(globalconf.AuthPass), []byte("salt"), []byte("$magic$")))

	return nil
}

// send sends a probing-email over SMTP-server specified in config c to be waited for on the receiving side.
func send(c SMTPServerConfig, msg string) error {
	promlog.Debug("sending mail")
	a := smtp.PlainAuth("", c.Login, c.Passphrase, c.Server)
	err := smtp.SendMail(c.Server+":"+c.Port, a, c.From, []string{c.To}, []byte(msg))

	if err != nil {
		return err
	}

	return nil
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

// lateMail logs mails that have been so late that they timed out
func lateMail(m email) {
	promlog.Debug("got late mail via %s; mail took %d ms", m.configname, milliseconds(m.t_recv.Sub(m.t_sent)))
	late_mails.WithLabelValues(m.configname).Inc()
}

// probe probes if mail gets through the entire chain from specified SMTPServer into Maildir.
func probe(c SMTPServerConfig, p payload) {
	muxer[p.token] = make(chan email)

	//send(c, string(p))
	err := send(c, p.String())
	if err != nil {
		promlog.Warnf("error sending probe-mail via %s: %s; skipping attempt", c.Name, err)
		mail_send_fails.WithLabelValues(c.Name).Inc()
		disposeToken <- p.token
		return
	}

	timeout := time.After(globalconf.MailCheckTimeout)
	select {
	case mail := <-muxer[p.token]:
		promlog.Debug("checking mail for timeout")

		deliver_ok.WithLabelValues(c.Name).Set(1)
		deleteMail(mail)

	case <-timeout:
		promlog.Debug("Getting mail timed out.")
		deliver_ok.WithLabelValues(c.Name).Set(0)
	}

	disposeToken <- p.token
}

// monitor probes every MonitoringInterval if mail still gets through.
func monitor(c SMTPServerConfig) {
	log.Println("Started monitoring for config", c.Name)
	for {
		p := newPayload(c.Name)
		go probe(c, p)
		time.Sleep(globalconf.MonitoringInterval)
	}
}

// secret returns secret for basic http-auth
func secret(user, realm string) string {
	if user == globalconf.AuthUser {
		return globalconf.authHash
	}
	return ""
}

// classifyMailMetrics extracts all general mail metrics such as deliver duration etc.
// from a mail struct and sets the corresponding metrics
func classifyMailMetrics(foundMail email) {
	// timestamps are in nanoseconds
	// last_mail_deliver_time shall be standard unix-timestamp
	// last_mail_deliver_duration shall be milliseconds for higher resolution
	deliverTime := float64(foundMail.t_recv.Unix())
	deliverDuration := float64(milliseconds(foundMail.t_recv.Sub(foundMail.t_sent)))
	last_mail_deliver_time.WithLabelValues(foundMail.configname).Set(deliverTime)
	last_mail_deliver_duration.WithLabelValues(foundMail.configname).Set(deliverDuration)
	mail_deliver_durations.WithLabelValues(foundMail.configname).Observe(deliverDuration)
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
						lateMail(foundMail)
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

// parseMail reads a mailfile's content and parses it into a mail-struct if one of ours.
func parseMail(path string) (email, error) {
	// to date the mails found
	t := time.Now()

	// try parsing
	f, err := os.Open(path)
	if err != nil {
		return email{}, err
	}
	defer f.Close()

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
		return email{}, ErrNotOurDept
	}

	return email{path, p.configname, p.token, time.Unix(0, p.timestamp), t}, nil
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

	err = parseConfig(f)
	f.Close()
	if err != nil {
		promlog.Fatal(err)
	}

	// initialize Metrics that will be used seldom so that they actually get exported with a metric
	for _, c := range globalconf.Servers {
		late_mails.GetMetricWithLabelValues(c.Name)
		mail_send_fails.GetMetricWithLabelValues(c.Name)
	}

	fswatcher, err := fsnotify.NewWatcher()
	if err != nil {
		promlog.Fatal(err)
	}

	defer fswatcher.Close()

	for _, c := range globalconf.Servers {
		promlog.Debug("adding path to watcher:", c.Detectiondir)
		fswatcher.Add(c.Detectiondir) // deduplication is done within fsnotify
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
	if *useAuth {
		authenticator := auth.NewBasicAuthenticator("prometheus", secret)
		http.HandleFunc(globalconf.HTTPEndpoint, auth.JustCheck(authenticator, prometheus.Handler().ServeHTTP))
	} else {
		http.Handle(globalconf.HTTPEndpoint, prometheus.Handler())
	}

	if *useTLS {
		promlog.Fatal(http.ListenAndServeTLS(":"+globalconf.HTTPPort, globalconf.CrtPath, globalconf.KeyPath, nil))
	} else {
		promlog.Fatal(http.ListenAndServe(":"+globalconf.HTTPPort, nil))
	}
}
