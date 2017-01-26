package instun

import (
	"errors"
	"net"
	"time"
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

func (stun *Stun) RunUDP(listener *net.UDPConn) error {
	data := make([]byte, 1024)
	for {
		if n, addr, e := listener.ReadFromUDP(data); n > 20 && e == nil {
			conn := &StunUDP{
				conn: listener,
				raddr: addr,
			}
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

type StunUDP struct {
	conn *net.UDPConn
	raddr *net.UDPAddr
}

func (udp *StunUDP) Write(b []byte) (int, error) {
	return udp.conn.WriteTo(b, udp.raddr)
}

func (udp *StunUDP) Read(b []byte) (int, error) {
	return 0, nil
}


func (udp *StunUDP) Close() error {
	return nil
}

func (udp *StunUDP) LocalAddr() net.Addr {
	return udp.conn.LocalAddr()
}

func (udp *StunUDP) RemoteAddr() net.Addr {
	return udp.raddr
}

func (udp *StunUDP) SetDeadline(t time.Time) error {
	return udp.SetDeadline(t)
}

func (udp *StunUDP) SetReadDeadline(t time.Time) error {
	return nil
}

func (udp *StunUDP) SetWriteDeadline(t time.Time) error {
	return udp.conn.SetWriteDeadline(t)
}

