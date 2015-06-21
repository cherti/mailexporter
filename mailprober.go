package main

import(
	"fmt"
	"net/smtp"
	"io/ioutil"
	"strings"
)

// configuration implementation temporary

var conf_path string = "./conf"

type Config struct {
	Server string
	Port string
	Login string
	Password string
	From string
	To string
}

func parse_conf(path string) Config {

	content, _ := ioutil.ReadFile(path)
	sc := strings.Split(string(content), "\n")
	c := Config{sc[0], sc[1], sc[2], sc[3], sc[4], sc[5]}
	return c

}

//func send() {

//}

func main() {
	c := parse_conf(conf_path)

	fmt.Println("parsed config")

	content := []byte("shaboom")
	a := smtp.PlainAuth("", c.Login, c.Password, c.Server)
	fmt.Println("prepared auth")
	err := smtp.SendMail(c.Server + ":" + c.Port, a, c.From, []string{c.To}, content)
	fmt.Println("SendMail called")

	fmt.Println(err)

}
