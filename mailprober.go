package main

import(
	"fmt"
	"net/smtp"
	"io/ioutil"
	"strings"
	"net/mail"
	"bytes"
	"time"
	"math/rand"
	"os"
	"errors"
	"sync"
)

var conf_path string = "./conf"
var content_length int = 7
var ErrMailNotFound = errors.New("no corresponding mail found")
var mailCheckTimeout = 10*time.Second
var monitoringInterval = 1*time.Minute
var numberConfigOptions = 7
var antiInterferenceInterval = 15*time.Second

type Config struct {
	Server string
	Port string
	Login string
	Password string
	From string
	To string
	Detectiondir string
}

type email struct {
	Filename string
	Content *mail.Message
}

func parse_conf(path string) []Config {

	content, _ := ioutil.ReadFile(path)

	sc := strings.Split(string(content), "\n")

	configcount := len(sc) / numberConfigOptions
	configs := make([]Config, configcount)

	for i := 0; i < configcount; i++ {
		j := i*numberConfigOptions
		configs[i] = Config{sc[j+0], sc[j+1], sc[j+2], sc[j+3], sc[j+4], sc[j+5], sc[j+6]}
	}
	fmt.Println("confnumber:", len(configs))

	return configs

}

func parse_mails(c Config) []email {
	// get entries of directory
	files, _ := ioutil.ReadDir(c.Detectiondir)

	// allocate space to store the parsed mails
	mails := make([]email, 0, len(files))

	for _, f := range files {
		if !f.IsDir() {

			// try parsing
			content, _ := ioutil.ReadFile(c.Detectiondir + "/" + f.Name())
			mail, err := mail.ReadMessage(bytes.NewReader(content))

			// save if parsable
			if err == nil {
				mails = append(mails, email{f.Name(), mail})
			}

		}

	}

	return mails
}


func send(c Config, msg string) {

	fmt.Println("sending mail")
	a := smtp.PlainAuth("", c.Login, c.Password, c.Server)
	err := smtp.SendMail(c.Server + ":" + c.Port, a, c.From, []string{c.To}, []byte(msg))

	if err != nil {
		fmt.Println(err)
	}
}

func filter(msg string, mails []email) (email, error) {

	stuff := make([]byte, content_length)

	for _, m := range mails {
		m.Content.Body.Read(stuff)
		if string(stuff) == msg {
			return m, nil
		}
	}

	return email{}, ErrMailNotFound
}

func randstring(length int) string {
	// does also return unprintable characters in returned string,
	// which is actually appreciated to implicitly monitor that
	// mail gets through unchanged

	stuff := make([]byte, content_length)

	for i := range stuff {
		stuff[i] = byte(rand.Int())
	}

	return string(stuff)
}

func delmail(c Config, m email) {
	os.Remove(c.Detectiondir + "/" + m.Filename)
	fmt.Println("rm ", c.Detectiondir + "/" + m.Filename)
}


func probe(c Config) {

	content := randstring(content_length)
	content = "shaboom"

	send(c, content)

	timeout := time.After(mailCheckTimeout)

	seekingMail := true
	for seekingMail {
		select {
		default:
			//fmt.Println("getting mail...")
			mails := parse_mails(c)

			mail, err := filter(content, mails)

			if err == nil {
				fmt.Println("mail found")
				delmail(c, mail)
				seekingMail = false
			}

		case <- timeout:
			fmt.Println("getting mail timed out")
			seekingMail = false
		}

		time.Sleep(5*time.Millisecond)

	}
}

func monitor(c Config, wg *sync.WaitGroup) {
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

	for i, c := range configs {
		fmt.Println("starting monitor for config", i)
		go monitor(c, wg)

		// keep a timedelta between monitoring jobs to avoid interference
		time.Sleep(antiInterferenceInterval)
	}

	elapsed := time.Since(start)
	fmt.Println(elapsed)

	wg.Wait()

}
