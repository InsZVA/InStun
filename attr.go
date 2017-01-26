package instun

import (
	"encoding/binary"
	"errors"
)

var (
	ERROR_UNKOWN_ATTRIBUTE = errors.New("InStun: unkown attr to encode")
)

const (
	/* Comprehension-required range (0x0000-0x7FFF) */
	STUN_ATTR_MAPPED_ADDR        = 0x0001
	STUN_ATTR_CHANGE_REQ         = 0x0003
	STUN_ATTR_USERNAME           = 0x0006
	STUN_ATTR_MSG_INTEGRITY      = 0x0008
	STUN_ATTR_ERR_CODE           = 0x0009
	STUN_ATTR_UNKNOWN_ATTR       = 0x000a
	STUN_ATTR_CHANNEL_NUMBER     = 0x000c
	STUN_ATTR_LIFETIME           = 0x000d
	STUN_ATTR_XOR_PEER_ADDR      = 0x0012
	STUN_ATTR_DATA               = 0x0013
	STUN_ATTR_REALM              = 0x0014
	STUN_ATTR_NONCE              = 0x0015
	STUN_ATTR_XOR_RELAY_ADDR     = 0x0016
	STUN_ATTR_REQ_ADDR_FAMILY    = 0x0017
	STUN_ATTR_EVEN_PORT          = 0x0018
	STUN_ATTR_REQ_TRANSPORT      = 0x0019
	STUN_ATTR_DONT_FRAGMENT      = 0x001a
	STUN_ATTR_XOR_MAPPED_ADDR    = 0x0020
	STUN_ATTR_RSV_TOKEN          = 0x0022
	STUN_ATTR_PRIORITY           = 0x0024
	STUN_ATTR_USE_CAND           = 0x0025
	STUN_ATTR_PADDING            = 0x0026
	STUN_ATTR_RESP_PORT          = 0x0027

	/* Comprehension-optional range (0x8000-0xFFFF) */
	STUN_ATTR_SOFTWARE           = 0x8022
	STUN_ATTR_ALT_SERVER         = 0x8023
	STUN_ATTR_FINGERPRINT        = 0x8028
	STUN_ATTR_CONTROLLED         = 0x8029
	STUN_ATTR_CONTROLLING        = 0x802a
	STUN_ATTR_RESP_ORIGIN        = 0x802b
	STUN_ATTR_OTHER_ADDR         = 0x802c
)

type StunAttr struct {
	AttrType  uint16
	// What to put in attrValue?
	// reference objects in general(not golang) using pointer
	// value objects in general(not golang) using value
	// Note: []byte is saved as a value
	AttrValue interface{}
}

type ChangeRequest struct {
	IP   bool
	Port bool
}

type ErrorCode struct {
	Code uint16
	Msg  string
}

type UnkownAttr struct {
	Typev []uint16
	Typec int
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////     Decode       ////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////


func DecodeStunAttr(reader *StunReader, ua *UnkownAttr, tid []uint8) (*StunAttr, error) {
	var padding = func() {
		if reader == nil {
			return
		}
		for (reader.off - reader.base) & 0x03 != 0 && reader.Left() > 0 {
			reader.off++
		}
	}
	defer padding()

	var attrType, attrLen uint16

	if reader == nil {
		return nil, ERROR_NIL_READER
	}

	reader.BigEndianRead(&attrType)
	reader.BigEndianRead(&attrLen)
	if reader.Left() < int64(attrLen) {
		return nil, ERROR_BAD_MESSAGE
	}

	switch attrType {
	case STUN_ATTR_MAPPED_ADDR: fallthrough
	case STUN_ATTR_ALT_SERVER: fallthrough
	case STUN_ATTR_RESP_ORIGIN: fallthrough
	case STUN_ATTR_OTHER_ADDR:
		tid = nil
	fallthrough
	case STUN_ATTR_XOR_PEER_ADDR: fallthrough
	case STUN_ATTR_XOR_RELAY_ADDR: fallthrough
	case STUN_ATTR_XOR_MAPPED_ADDR:
		if v, e := DecodeStunAddr(reader, tid); e == nil {
			return &StunAttr {
				AttrType: attrType,
				AttrValue:v,
			}, nil
		} else {
			return nil, ERROR_BAD_MESSAGE
		}
	case STUN_ATTR_CHANGE_REQ:
		if attrLen != 4 {
			return nil, ERROR_BAD_MESSAGE
		}

		var n uint32
		if e := reader.BigEndianRead(&n);e != nil {
			return nil, ERROR_BAD_MESSAGE
		}
		cq := &ChangeRequest{
			IP: (n >> 2) & 0x1 == 0x1,
			Port: (n >> 1) & 0x1 == 0x1,
		}
		return &StunAttr {
			AttrType: attrType,
			AttrValue: cq,
		}, nil
	case STUN_ATTR_USERNAME: fallthrough
	case STUN_ATTR_REALM: fallthrough
	case STUN_ATTR_NONCE: fallthrough
	case STUN_ATTR_SOFTWARE:
		buff := make([]byte, int(attrLen))
		if n, e := reader.Read(buff); n < int(attrLen) || e != nil {
			return nil, ERROR_BAD_MESSAGE
		} else {
			return &StunAttr {
				AttrType: attrType,
				AttrValue: string(buff),
			}, nil
		}
	case STUN_ATTR_MSG_INTEGRITY:
		if attrLen != 20 {
			return nil, ERROR_BAD_MESSAGE
		}
		buff := make([]byte, 20)
		if n, e := reader.Read(buff); n < int(attrLen) || e != nil {
			return nil, ERROR_BAD_MESSAGE
		} else {
			return &StunAttr {
				AttrType: attrType,
				AttrValue: buff,
			}, nil
		}
	case STUN_ATTR_ERR_CODE:
		if attrLen < 4 {
			return nil, ERROR_BAD_MESSAGE
		}
		reader.Next(2)
		var n uint8
		var code uint16
		if reader.BigEndianRead(&n) != nil {
			return nil, ERROR_BAD_MESSAGE
		}
		code = uint16(n & 0x7) * 100
		if reader.BigEndianRead(&n) != nil {
			return nil, ERROR_BAD_MESSAGE
		}
		code += uint16(n)
		buff := make([]byte, attrLen - 4)
		if n, e := reader.Read(buff); n != int(attrLen - 4) || e != nil {
			return nil, ERROR_BAD_MESSAGE
		} else {
			return &StunAttr{
				AttrType: attrType,
				AttrValue: &ErrorCode{
					Code: code,
					Msg:  string(buff),
				},
			}, nil
		}
	case STUN_ATTR_UNKNOWN_ATTR:
		var ua UnkownAttr
		for i := 0; i < int(attrLen/2); i++ {
			var tp uint16
			if reader.BigEndianRead(&tp) != nil {
				return nil, ERROR_BAD_MESSAGE
			}
			ua.Typev = append(ua.Typev, tp)
			ua.Typec++
		}
		return &StunAttr {
			AttrType: attrType,
			AttrValue: &ua,
		}, nil
	case STUN_ATTR_CHANNEL_NUMBER: fallthrough
	case STUN_ATTR_RESP_PORT:
		if attrLen < 2 {
			return nil, ERROR_BAD_MESSAGE
		}
		var n uint16
		if reader.BigEndianRead(&n) != nil {
			return &StunAttr {
				AttrType: attrType,
				AttrValue: n,
			}, nil
		} else {
			return nil, ERROR_BAD_MESSAGE
		}
	case STUN_ATTR_LIFETIME: fallthrough
	case STUN_ATTR_PRIORITY: fallthrough
	case STUN_ATTR_FINGERPRINT:
		if attrLen != 4 {
			return nil, ERROR_BAD_MESSAGE
		}
		var n uint32
		if reader.BigEndianRead(&n) != nil {
			return nil, ERROR_BAD_MESSAGE
		}
		return &StunAttr {
			AttrType: attrType,
			AttrValue: n,
		}, nil
	case STUN_ATTR_DATA: fallthrough
	case STUN_ATTR_PADDING:
		buff := make([]byte, attrLen)
		if n, e := reader.Read(buff); n != int(attrLen) || e != nil {
			return nil, ERROR_BAD_MESSAGE
		}
		return &StunAttr {
			AttrType: attrType,
			AttrValue: buff,
		}, nil
	case STUN_ATTR_REQ_ADDR_FAMILY: fallthrough
	case STUN_ATTR_REQ_TRANSPORT:
		if attrLen < 1 {
			return nil, ERROR_BAD_MESSAGE
		}
		var n uint8
		if reader.BigEndianRead(&n) != nil {
			return nil, ERROR_BAD_MESSAGE
		}
		return &StunAttr {
			AttrType: attrType,
			AttrValue: n,
		}, nil
	case STUN_ATTR_EVEN_PORT:
		if attrLen < 1 {
			return nil, ERROR_BAD_MESSAGE
		}
		var n uint8
		if reader.BigEndianRead(&n) != nil {
			return nil, ERROR_BAD_MESSAGE
		}
		return &StunAttr {
			AttrType: attrType,
			AttrValue: (n >> 7) & 0x1 == 0x1,
		}, nil
	case STUN_ATTR_DONT_FRAGMENT: fallthrough
	case STUN_ATTR_USE_CAND:
		if attrLen > 0 {
			return nil, ERROR_BAD_MESSAGE
		}
		/* no value */
		return &StunAttr {
			AttrType: attrType,
			AttrValue: nil,
		}, nil
	case STUN_ATTR_RSV_TOKEN: fallthrough
	case STUN_ATTR_CONTROLLING: fallthrough
	case STUN_ATTR_CONTROLLED:
		if attrLen != 8 {
			return nil, ERROR_BAD_MESSAGE
		}
		var n uint64
		if reader.BigEndianRead(&n) != nil {
			return nil, ERROR_BAD_MESSAGE
		}
		return &StunAttr {
			AttrType: attrType,
			AttrValue: n,
		}, nil
	default:
		reader.Next(int(attrLen))
		if attrType >= 0x8000 {
			break
		}
		if ua != nil {
			ua.Typev = append(ua.Typev, attrType)
			ua.Typec++
		}
	}
	return nil, nil
}

func (msg *StunMsg) PeekAttr(tp uint16) *StunAttr {
	for _, attr := range msg.Attr {
		if attr.AttrType == tp {
			return attr
		}
	}
	return nil
}

////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////       Encode        ///////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////

func NewStunAttr(attrType uint16, v interface{}) *StunAttr {
	switch v.(type) {
	case uint8:
	case uint16:
	case uint32:
	case uint64:
	case *StunAttr:
	case *ChangeRequest:
	case string:
	case []byte:
	case *ErrorCode:
	case *UnkownAttr:
	case bool:
	case nil:
		return nil
	default:
		panic("InStun: try a incompatible type.")
	}
	return &StunAttr {
		AttrType: attrType,
		AttrValue: v,
	}
}

func (attr *StunAttr) Encode(tid []uint8, paddingByte uint8) (ret []byte, err error) {
	var padding = func () {
		if ret == nil {
			return
		}
		for len(ret) & 0x03 != 0 {
			ret = append(ret, paddingByte)
		}
	}
	defer padding()

	buf := make([]byte, 4)
	binary.BigEndian.PutUint16(buf, attr.AttrType)
	// attrLen = 0 initially

	switch attr.AttrType {
	case STUN_ATTR_MAPPED_ADDR: fallthrough
	case STUN_ATTR_ALT_SERVER: fallthrough
	case STUN_ATTR_RESP_ORIGIN: fallthrough
	case STUN_ATTR_OTHER_ADDR:
		tid = nil
		fallthrough
	case STUN_ATTR_XOR_PEER_ADDR: fallthrough
	case STUN_ATTR_XOR_RELAY_ADDR: fallthrough
	case STUN_ATTR_XOR_MAPPED_ADDR:
		addr := attr.AttrValue.(*StunAddr)
		if buff, err := addr.Encode(tid); err != nil {
			binary.BigEndian.PutUint16(buf[2:], uint16(len(buff)))
			return append(buf, buff...), nil
		} else {
			return nil, err
		}
	case STUN_ATTR_CHANGE_REQ:
		ch := attr.AttrValue.(*ChangeRequest)
		var n uint32
		if ch.IP { n = 1 << 2 }
		if ch.Port { n = 1 << 1 }
		binary.BigEndian.PutUint16(buf[2:], 4)
		buff := make([]byte, 4)
		binary.BigEndian.PutUint32(buf[4:], n)
		return append(buf, buff...), nil
	case STUN_ATTR_USERNAME: fallthrough
	case STUN_ATTR_REALM: fallthrough
	case STUN_ATTR_NONCE: fallthrough
	case STUN_ATTR_SOFTWARE:
		str := attr.AttrValue.(string)
		buff := []byte(str)
		binary.BigEndian.PutUint16(buf[2:], uint16(len(buff)))
		return append(buf, buff...), nil
	case STUN_ATTR_MSG_INTEGRITY:
		buff := attr.AttrValue.([]byte)
		binary.BigEndian.PutUint16(buf[2:], uint16(len(buff)))
		return append(buf, buff...), nil
	case STUN_ATTR_ERR_CODE:
		ec := attr.AttrValue.(*ErrorCode)
		buff := make([]byte, 4)
		binary.BigEndian.PutUint16(buff, 0)
		buff[2] = uint8(ec.Code / 100)
		buff[3] = uint8(ec.Code % 100)
		buff = append(buff, []byte(ec.Msg)...)
		binary.BigEndian.PutUint16(buf[2:], uint16(len(buff)))
		return append(buf, buff...), nil
	case STUN_ATTR_UNKNOWN_ATTR:
		ua := attr.AttrValue.(*UnkownAttr)
		buff := make([]byte, int(ua.Typec * 2))
		for i := 0; i < ua.Typec; i++ {
			binary.BigEndian.PutUint16(buff[2*i:], ua.Typev[i])
		}
		binary.BigEndian.PutUint16(buf[2:], uint16(len(buff)))
		return append(buf, buff...), nil
	case STUN_ATTR_CHANNEL_NUMBER: fallthrough
	case STUN_ATTR_RESP_PORT:
		n := attr.AttrValue.(uint16)
		buff := make([]byte, 4)
		binary.BigEndian.PutUint16(buff, n)
		binary.BigEndian.PutUint16(buf[2:], uint16(len(buff)))
		return append(buf, buff...), nil
	case STUN_ATTR_LIFETIME: fallthrough
	case STUN_ATTR_PRIORITY: fallthrough
	case STUN_ATTR_FINGERPRINT:
		n := attr.AttrValue.(uint32)
		buff := make([]byte, 4)
		binary.BigEndian.PutUint32(buff, n)
		binary.BigEndian.PutUint16(buf[2:], uint16(len(buff)))
		return append(buf, buff...), nil
	case STUN_ATTR_DATA: fallthrough
	case STUN_ATTR_PADDING:
		buff := attr.AttrValue.([]byte)
		binary.BigEndian.PutUint16(buf[2:], uint16(len(buff)))
		return append(buf, buff...), nil
	case STUN_ATTR_REQ_ADDR_FAMILY: fallthrough
	case STUN_ATTR_REQ_TRANSPORT:
		n := attr.AttrValue.(uint8)
		buff := make([]byte, 4)
		buff[0] = n
		binary.BigEndian.PutUint16(buf[2:], uint16(len(buff)))
		return append(buf, buff...), nil
	case STUN_ATTR_EVEN_PORT:
		b := attr.AttrValue.(bool)
		buff := make([]byte, 4)
		if b { buff[0] = 1 << 7 }
		binary.BigEndian.PutUint16(buf[2:], uint16(len(buff)))
		return append(buf, buff...), nil
	case STUN_ATTR_DONT_FRAGMENT: fallthrough
	case STUN_ATTR_USE_CAND:
		/* no value */
		return buf, nil
	case STUN_ATTR_RSV_TOKEN: fallthrough
	case STUN_ATTR_CONTROLLING: fallthrough
	case STUN_ATTR_CONTROLLED:
		n := attr.AttrValue.(uint64)
		buff := make([]byte, 8)
		binary.BigEndian.PutUint64(buff, n)
		binary.BigEndian.PutUint16(buf[2:], uint16(len(buff)))
		return append(buf, buff...), nil
	default:
		return nil, ERROR_UNKOWN_ATTRIBUTE
	}
	return nil, nil
}