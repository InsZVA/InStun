package main

import (
	"net"
	"github.com/inszva/instun"
	"strconv"
)

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

	_ := &instun.Stun{}.Run(listener)
}
