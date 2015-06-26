package main

import(
	"fmt"
	"net/smtp"
	"io/ioutil"
	"strings"
	"net/mail"
	"bytes"
	"time"
)

// configuration implementation temporary

var conf_path string = "./conf"
var content_length int = 7

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

func parse_conf(path string) Config {

	content, _ := ioutil.ReadFile(path)
	sc := strings.Split(string(content), "\n")
	c := Config{sc[0], sc[1], sc[2], sc[3], sc[4], sc[5], sc[6]}
	return c

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

	a := smtp.PlainAuth("", c.Login, c.Password, c.Server)
	err := smtp.SendMail(c.Server + ":" + c.Port, a, c.From, []string{c.To}, []byte(msg))

	if err != nil {
		fmt.Println(err)
	}
}

func filter(msg string, mails []email) {

	stuff := make([]byte, content_length)

	for _, m := range mails {
		m.Content.Body.Read(stuff)
		if string(stuff) == msg {
			fmt.Println("match:", m.Filename)
		}
	}
}

func main() {
	start := time.Now()

	fmt.Println(string([]byte("shaboom")))

	c := parse_conf(conf_path)

	send(c, "shaboom")

	mails := parse_mails(c)

	filter("shaboom", mails)

	elapsed := time.Since(start)
	fmt.Println(elapsed)

}
