package main

import (
	"fmt"
	"os"

	ssh "github.com/justmamadou/go-ssh"
)

func main() {
	var (
		privateKey []byte
		publicKey  []byte
		err        error
	)

	if privateKey, publicKey, err = ssh.Generatekeys(); err != nil {
		fmt.Printf("Error: %s\n", err)
		os.Exit(1)
	}
	if err = os.WriteFile("mykey.pem", privateKey, 0640); err != nil {
		fmt.Printf("Error while writing private key to pem file: %s\n", err)
		os.Exit(1)
	}
	if err = os.WriteFile("mykey.pub", publicKey, 0640); err != nil {
		fmt.Printf("Error while writing public key to pem file: %s\n", err)
		os.Exit(1)
	}
}
