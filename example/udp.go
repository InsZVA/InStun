package main

import (
	"github.com/inszva/instun"
	"net"
	"strconv"
)

func main() {
	go tcp()
	go dtls()

	laddr, err := net.ResolveUDPAddr("udp4", *instun.FlagIP + ":" +
		strconv.Itoa(*instun.FlagPort))
	if err != nil {
		panic(err)
	}

	listener, err := net.ListenUDP("udp4", laddr)
	if err != nil {
		panic(err)
	}

	_ = &instun.Stun{}.RunUDP(listener)
}