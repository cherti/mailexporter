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
)

var conf_path string = "./conf"
var content_length int = 7
var ErrMailNotFound = errors.New("no corresponding mail found")
var mailCheckTimeout = 10 * time.Second
var monitoringInterval = 1 * time.Minute
var numberConfigOptions = 7
var antiInterferenceInterval = 15 * time.Second

type config struct {
	server       string
	port         string
	login        string
	passphrase   string
	from         string
	to           string
	detectiondir string
}

type email struct {
	filename string
	content  *mail.Message
}

func parse_conf(path string) []config {

	content, _ := ioutil.ReadFile(path)

	sc := strings.Split(string(content), "\n")

	configcount := len(sc) / numberConfigOptions
	configs := make([]config, configcount)

	for i := 0; i < configcount; i++ {
		j := i * numberConfigOptions
		configs[i] = config{sc[j+0], sc[j+1], sc[j+2], sc[j+3], sc[j+4], sc[j+5], sc[j+6]}
	}
	fmt.Println("confnumber:", len(configs))

	return configs

}

func parse_mails(c config) []email {
	// get entries of directory
	files, _ := ioutil.ReadDir(c.detectiondir)

	// allocate space to store the parsed mails
	mails := make([]email, 0, len(files))

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

func send(c config, msg string) {

	fmt.Println("sending mail")
	a := smtp.PlainAuth("", c.login, c.passphrase, c.server)
	err := smtp.SendMail(c.server+":"+c.port, a, c.from, []string{c.to}, []byte(msg))

	if err != nil {
		fmt.Println(err)
	}
}

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

func delmail(c config, m email) {
	os.Remove(c.detectiondir + "/" + m.filename)
	fmt.Println("rm ", c.detectiondir+"/"+m.filename)
}

func probe(c config) {

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

		case <-timeout:
			fmt.Println("getting mail timed out")
			seekingMail = false
		}

		time.Sleep(5 * time.Millisecond)

	}
}

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
