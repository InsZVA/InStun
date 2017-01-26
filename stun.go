package instun

import (
	"errors"
	"net"
	"bytes"
)

var (
	ERROR_NIL_READER = errors.New("InStun: nil reader.")
)

const (
	STUN_CLASS_INDICATION = 0x1
	STUN_CLASS_SUCCESS_RESP = 0x2
	STUN_CLASS_ERROR_RESP = 0x3
)

type Stun struct {

}

func (stun *Stun) Run(listener net.Listener) error {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}

		go func (conn net.Conn) {
			data := make([]byte, 1024)
			for {
				if n, e := conn.Read(data); n > 20 && e == nil {
					ctx := &StunMsgCtx{}
					reader := NewStunReaderFromBytes(data[:n])
					msg, err := DecodeStunMsg(reader, &ctx.ua)
					if err != nil {
						continue
					}

					BindingHandler(ctx, conn, msg)
				}
			}
		} (conn)
	}
}

func (stun *Stun) RunUDP(conn *net.UDPConn) error {
	data := make([]byte, 1024)
	for {
		if n, e := conn.Read(data); n > 20 && e == nil {
			ctx := &StunMsgCtx{}
			reader := NewStunReaderFromBytes(data[:n])
			msg, err := DecodeStunMsg(reader, &ctx.ua)
			if err != nil {
				continue
			}

			BindingHandler(ctx, conn, msg)
		}
	}
}