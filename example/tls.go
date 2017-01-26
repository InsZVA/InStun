package main

import (
	"github.com/inszva/instun"
	"strconv"
	"crypto/tls"
)

func dtls() {
	cert, err := tls.LoadX509KeyPair("server.pem", "server.key")
	if err != nil {
		panic(err)
		return
	}
	config := &tls.Config{Certificates: []tls.Certificate{cert}}

	listener, err := tls.Listen("tcp4", *instun.FlagIP + ":" +
		strconv.Itoa(*instun.FlagPort), config)
	if err != nil {
		panic(err)
	}

	_ := &instun.Stun{}.Run(listener)
}
