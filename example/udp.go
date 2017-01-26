package main

import (
	"github.com/inszva/instun"
	"net"
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

	(&instun.Stun{}).Run(listener)
}

func tcp() {
	laddr, err := net.ResolveTCPAddr("tcp4", *instun.FlagIP + ":" +
		strconv.Itoa(*instun.FlagPort))
	if err != nil {
		panic(err)
	}

	listener, err := net.ListenTCP("tcp4", laddr)
	if err != nil {
		panic(err)
	}

	(&instun.Stun{}).Run(listener)
}

func main() {
	//go tcp()
	//go dtls()

	laddr, err := net.ResolveUDPAddr("udp4", *instun.FlagIP + ":" +
		strconv.Itoa(*instun.FlagPort))
	if err != nil {
		panic(err)
	}

	listener, err := net.ListenUDP("udp4", laddr)
	if err != nil {
		panic(err)
	}

	(&instun.Stun{}).RunUDP(listener)
}