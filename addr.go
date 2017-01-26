package instun

import (
	"net"
	"strconv"
	"encoding/binary"
	"errors"
	"bytes"
)

var (
	ERROR_AF_NOT_SUPPORT = errors.New("InStun: unsupported family")
	ERROR_IP_LENGTH = errors.New("InStun: ip address length error")
)

const (
	STUN_MAGIC_COOKIE = 0x2112a442
	STUN_AF_IPV4 = 0x01
	STUN_AF_IPV6 = 0x02
)

// ipEmptyString is like IP.String except that it returns
// an empty string when IP is unset.
func ipEmptyString(ip net.IP) string {
	if len(ip) == 0 {
		return ""
	}
	return ip.String()
}

type StunAddr struct {
	IP net.IP
	Port int
}

func (addr *StunAddr) Network() string {
	return "stun"
}

func (addr *StunAddr) String() string {
	if addr == nil {
		return "<nil>"
	}
	ip := ipEmptyString(addr.IP)
	return net.JoinHostPort(ip, strconv.Itoa(addr.Port))
}

func NewStunAddr(ip net.IP, port int) *StunAddr {
	return &StunAddr {
		IP: ip,
		Port: port,
	}
}

// Xor function xor produced the address and return itself
// if the address is illegal return nil otherwise
func (addr *StunAddr) Xor(tid []uint8) *StunAddr {
	if tid == nil {
		return nil
	}
	addr.Port ^= STUN_MAGIC_COOKIE >> 16

	reader := bytes.NewReader(addr.IP)
	switch len(addr.IP) {
	case 4:
		var addr4 uint32
		if binary.Read(reader, binary.BigEndian, &addr4) != nil {
			return nil
		}
		addr4 ^= STUN_MAGIC_COOKIE
		binary.BigEndian.PutUint32(addr.IP, addr4)
	case 16:
		in6_xor_tid(addr.IP.To16(), tid)
	default:
		return nil
	}
	return addr
}

func DecodeStunAddr(reader *StunReader, tid []uint8) (*StunAddr, error) {
	var family uint8
	var addr6 = make([]uint8, 16)
	var addr4 uint32
	var port uint16

	if reader == nil {
		return nil, ERROR_NIL_READER
	}
	if reader.Left() < 4 {
		return nil, ERROR_BAD_MESSAGE
	}

	reader.off += 1
	if reader.BigEndianRead(&family) != nil {
		return nil, ERROR_BAD_MESSAGE
	}
	if reader.BigEndianRead(&port) != nil {
		return nil, ERROR_BAD_MESSAGE
	}

	if tid != nil {
		port ^= STUN_MAGIC_COOKIE >> 16
	}
	switch family {
	case STUN_AF_IPV4:
		if e := reader.BigEndianRead(&addr4);e != nil {
			return nil, ERROR_BAD_MESSAGE
		}
		if tid != nil {
			addr4 ^= STUN_MAGIC_COOKIE
		}
		var ipv4 = make(net.IP, 4)
		binary.BigEndian.PutUint32(ipv4, addr4)
		return NewStunAddr(ipv4, int(port)), nil
	case STUN_AF_IPV6:
		if n, e := reader.Read(addr6);n != 16 || e != nil {
			return nil, ERROR_BAD_MESSAGE
		}
		if tid != nil {
			in6_xor_tid(addr6, tid)
		}
		return NewStunAddr(addr6, int(port)), nil
	}
	return nil, ERROR_AF_NOT_SUPPORT
}

func in6_xor_tid(in6 []uint8, tid []uint8) {

	/* XOR with Magic Cookie (alignment safe) */
	in6[0] ^= 0x21
	in6[1] ^= 0x12
	in6[2] ^= 0xa4
	in6[3] ^= 0x42

	for i := 0; i < STUN_TID_SIZE; i++ {
		in6[4+i] ^= tid[i]
	}
}

func (addr *StunAddr) Encode(tid []uint8) ([]byte, error) {
	if len(addr.IP) == 4 {
		buff := make([]byte, 4)
		buff[0] = 0
		buff[1] = STUN_AF_IPV4
		binary.BigEndian.PutUint16(buff[2:], uint16(addr.Port))
		buff = append(buff, addr.IP...)
		if len(buff) != 8 {
			return nil, ERROR_IP_LENGTH
		}
		return buff, nil
	}
	if len(addr.IP) == 16 {
		buff := make([]byte, 4)
		buff[0] = 0
		buff[1] = STUN_AF_IPV6
		binary.BigEndian.PutUint16(buff[2:], uint16(addr.Port))
		buff = append(buff, addr.IP...)
		if len(buff) != 16 {
			return nil, ERROR_IP_LENGTH
		}
		return buff, nil
	}
	return nil, ERROR_AF_NOT_SUPPORT
}