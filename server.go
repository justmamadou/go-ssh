package ssh

import (
	"fmt"
	"net"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

func StartServer(privateKey []byte, authorizedKeys []byte) error {
	authorizedKeysMap := map[string]bool{}
	for len(authorizedKeys) > 0 {
		pubKey, _, _, rest, err := ssh.ParseAuthorizedKey(authorizedKeys)
		if err != nil {
			return fmt.Errorf("failed to parse authorized key: %w", err)
		}

		authorizedKeysMap[string(pubKey.Marshal())] = true
		authorizedKeys = rest
	}

	config := &ssh.ServerConfig{
		PublicKeyCallback: func(c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			if authorizedKeysMap[string(pubKey.Marshal())] {
				return &ssh.Permissions{
					// Record the public key used for authentication.
					Extensions: map[string]string{
						"pubkey-fp": ssh.FingerprintSHA256(pubKey),
					},
				}, nil
			}
			return nil, fmt.Errorf("unknown public key for %q", c.User())
		},
	}
	private, err := ssh.ParsePrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("failed to parse private key: %w", err)
	}
	config.AddHostKey(private)

	listener, err := net.Listen("tcp", "0.0.0.0:2022")
	if err != nil {
		return fmt.Errorf("failed to listen for connection: %w", err)
	}

	for {
		nConn, err := listener.Accept()
		if err != nil {
			fmt.Printf("failed to accept incoming connection: %v\n", err)
		}

		// Before use, a handshake must be performed on the incoming
		// net.Conn.
		conn, chans, reqs, err := ssh.NewServerConn(nConn, config)
		if err != nil {
			fmt.Printf("failed to handshake: %v\n", err)
		}
		if conn != nil && conn.Permissions != nil {
			fmt.Printf("logged in with key %s\n", conn.Permissions.Extensions["pubkey-fp"])
		}

		go ssh.DiscardRequests(reqs)

		go handleConnections(conn, chans)
	}

}

func handleConnections(conn *ssh.ServerConn, chans <-chan ssh.NewChannel) {
	for newChannel := range chans {
		// Channels have a type, depending on the application level
		// protocol intended. In the case of a shell, the type is
		// "session" and ServerShell may be used to present a simple
		// terminal interface.
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}
		channel, requests, err := newChannel.Accept()
		if err != nil {
			fmt.Printf("Could not accept channel: %v", err)
		}

		// Sessions have out-of-band requests such as "shell",
		// "pty-req" and "env".  Here we handle only the
		// "shell" request.

		go func(in <-chan *ssh.Request) {
			for req := range in {
				fmt.Printf("Received Type made by client: %s\n", req.Type)
				switch req.Type {
				case "shell":
					req.Reply(true, nil)
				case "pty-req":
					createTerminal(conn, channel)
				default:
					req.Reply(false, nil)
				}
			}
		}(requests)
	}
}

func createTerminal(conn *ssh.ServerConn, channel ssh.Channel) {
	// Create a new terminal
	term := term.NewTerminal(channel, "> ")

	go func() {
		defer channel.Close()
		for {
			line, err := term.ReadLine()
			if err != nil {
				break
			}
			//fmt.Printf("Received command: %s\n", line)
			switch line {
			case "exit":
				term.Write([]byte("Goodbye!\n"))
				return
			case "whoami":
				term.Write([]byte("You are logged in as " + conn.User() + "\n"))
			case "":
			default:
				term.Write([]byte(fmt.Sprintf("Unknown command: %s\n", line)))
			}
		}
	}()
}
