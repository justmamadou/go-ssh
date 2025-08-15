package main

import (
	"log"
	"os"

	"github.com/justmamadou/go-ssh"
)

func main() {
	var (
		err error
	)
	authorizedKeys, err := os.ReadFile("mykey.pub")
	if err != nil {
		log.Fatal("failed to read authorized keys: ", err)
	}
	privateKey, err := os.ReadFile("server.pem")
	if err != nil {
		log.Fatal("failed to read private key: ", err)
	}
	if err := ssh.StartServer(privateKey, authorizedKeys); err != nil {
		log.Fatal("failed to start SSH server: ", err)
	}
}
