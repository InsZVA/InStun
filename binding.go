package instun

import (
	"net"
	"crypto/tls"
	"strings"
	"strconv"
)

func getConnRAddress(conn net.Conn) (net.IP, int) {
	switch conn.(type) {
	case *net.TCPConn:
		return conn.RemoteAddr().(*net.TCPAddr).IP,
			conn.RemoteAddr().(*net.TCPAddr).Port
	case *tls.Conn:
		return conn.RemoteAddr().(*net.TCPAddr).IP,
			conn.RemoteAddr().(*net.TCPAddr).Port
	case *net.UDPConn:
		return conn.RemoteAddr().(*net.UDPAddr).IP,
			conn.RemoteAddr().(*net.UDPAddr).Port
	default:
		raddr, _ := net.ResolveUDPAddr("udp", conn.RemoteAddr().String())
		return raddr.IP, raddr.Port
	}
}

func getConnLAddress(conn net.Conn) (net.IP, int) {
	switch conn.(type) {
	case *net.TCPConn:
		return conn.LocalAddr().(*net.TCPAddr).IP,
			conn.LocalAddr().(*net.TCPAddr).Port
	case *tls.Conn:
		return conn.LocalAddr().(*net.TCPAddr).IP,
			conn.LocalAddr().(*net.TCPAddr).Port
	case *net.UDPConn:
		return conn.LocalAddr().(*net.UDPAddr).IP,
			conn.LocalAddr().(*net.UDPAddr).Port
	default:
		raddr, _ := net.ResolveUDPAddr("udp", conn.LocalAddr().String())
		return raddr.IP, raddr.Port
	}
}

func BindingHandler(ctx *StunMsgCtx, conn net.Conn, msg *StunMsg) bool {

	tid := make([]byte, STUN_TID_SIZE)
	for i := 0; i < STUN_TID_SIZE; i++ {
		tid[i] = msg.Tid[i]
	}

	if msg.Method() != STUN_METHOD_BINDING {
		return false
	}

	debug("binding: request from", conn.RemoteAddr())

	if ctx.ua.Typec > 0 {
		rmsg := NewStunMsg(msg.Method(), STUN_CLASS_ERROR_RESP, msg.Tid)
		rmsg.AddAttr(NewStunAttr(STUN_ATTR_SOFTWARE, SOFTWARE))
		ec := &ErrorCode{
			Code: 420,
			Msg: "Unkown Attribute",
		}
		data, err := rmsg.Encode(ec, ctx.key, ctx.fp, PADDING_BYTE)
		if err != nil {
			return false
		}
		conn.Write(data)
		return true
	}

	/* Doesn't support response-port just now
	// Response-Port: change source port
	rp := msg.PeekAttr(STUN_ATTR_RESP_PORT)
	if rp != nil {
		conn.Port = int(rp.AttrValue.(uint16))
	}
    */

	cr := msg.PeekAttr(STUN_ATTR_CHANGE_REQ)
	if udpConn, ok := conn.(*net.UDPConn); cr != nil && ok {
		// Use communication TCP to indicate alternate server
		// to response with alternate IP
		if cr.AttrValue.(*ChangeRequest).IP {
			conn = &AlternateConn{
				rip:   udpConn.RemoteAddr().(*net.UDPAddr).IP,
				rport: uint16(udpConn.RemoteAddr().(*net.UDPAddr).Port),
				lport: uint16(*FlagPort),
			}

			if cr.AttrValue.(*ChangeRequest).Port {
				conn.(*AlternateConn).lport = uint16(*FlagAlternatePort)
			}
		}
	}

	/* The server MUST add a RESPONSE-ORIGIN attribute to the Binding
	   Response, containing the source address and port used to send the
	   Binding Response.
	 */
	rmsg := NewStunMsg(STUN_METHOD_BINDING, STUN_CLASS_SUCCESS_RESP, msg.Tid)

	rmsg.AddAttr(NewStunAttr(STUN_ATTR_XOR_MAPPED_ADDR,
		NewStunAddr(getConnRAddress(conn)).Xor(tid)))
	rmsg.AddAttr(NewStunAttr(STUN_ATTR_MAPPED_ADDR,
		NewStunAddr(getConnRAddress(conn))))

	alterIP := strings.Split(*FlagAlternateIP, ".")
	if len(alterIP) >= 4 && comm != nil {
		// Only alternate server is running
		// Server can response an other address
		ip := make(net.IP, 4)
		for i := 0; i < 4; i++ {
			ip[i] = uint8(strconv.Atoi(alterIP[i]))
		}
		rmsg.AddAttr(NewStunAttr(STUN_ATTR_OTHER_ADDR,
			NewStunAddr(ip, *FlagAlternatePort)))
	}

	rmsg.AddAttr(NewStunAttr(STUN_ATTR_RESP_ORIGIN,
		NewStunAddr(getConnLAddress(conn))))
	rmsg.AddAttr(NewStunAttr(STUN_ATTR_SOFTWARE,
		SOFTWARE))
	if data, err := rmsg.Encode(nil, ctx.key, ctx.fp, PADDING_BYTE); err != nil {
		conn.Write(data)
	} else {
		return false
	}
	return true
}
