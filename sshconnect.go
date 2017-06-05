package main

import (
	"bytes"
	"fmt"
	"time"

	"golang.org/x/crypto/ssh"
)

func connect(user, password, host string, port int) (*ssh.Session, error) {
	var (
		auth         []ssh.AuthMethod
		addr         string
		clientConfig *ssh.ClientConfig
		client       *ssh.Client
		config       ssh.Config
		session      *ssh.Session
		err          error
	)
	// get auth method
	auth = make([]ssh.AuthMethod, 0)
	auth = append(auth, ssh.Password(password))

	config = ssh.Config{
		Ciphers: []string{"aes128-cbc", "3des-cbc", "aes192-cbc", "aes256-cbc"},
	}

	clientConfig = &ssh.ClientConfig{
		User:    user,
		Auth:    auth,
		Timeout: 30 * time.Second,
		Config:  config,
	}

	// connet to ssh
	addr = fmt.Sprintf("%s:%d", host, port)

	if client, err = ssh.Dial("tcp", addr, clientConfig); err != nil {
		return nil, err
	}

	// create session
	if session, err = client.NewSession(); err != nil {
		return nil, err
	}

	return session, nil
}

func dossh(username, password, ip string, cmdlist []string, port int, ch chan string) {
	session, err := connect(username, password, ip, port)
	if err != nil {
		ch <- fmt.Sprintf("<%s>", err.Error())
		return
	}
	defer session.Close()

	//	cmd := "ls;date;exit"

	stdinBuf, _ := session.StdinPipe()

	var bt bytes.Buffer
	session.Stdout = &bt

	//	session.Stderr = os.Stderr
	//	session.Stdin = os.Stdin
	err = session.Shell()
	for _, c := range cmdlist {
		c = c + "\n"
		stdinBuf.Write([]byte(c))
	}
	session.Wait()
	ch <- bt.String()
	return

}
