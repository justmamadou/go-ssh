package ssh

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"golang.org/x/crypto/ssh"
)

func Generatekeys() ([]byte, []byte, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, fmt.Errorf("GenerateKey error: %s", err)
	}
	privateKeyPem := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	publicKey, err := ssh.NewPublicKey(&privateKey.PublicKey)
	return pem.EncodeToMemory(privateKeyPem), ssh.MarshalAuthorizedKey(publicKey), nil
}
