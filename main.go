package main

import (
	"fmt"
	ssh "github.com/justmamadou/go-ssh/cmd/keygen"
	"os"
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
	if err = os.WriteFile("mykeyp.pub", publicKey, 0640); err != nil {
		fmt.Printf("Error while writing public key to pem file: %s\n", err)
		os.Exit(1)
	}
}
