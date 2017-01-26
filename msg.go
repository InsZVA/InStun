package instun

import (
	"errors"
	"bytes"
	"io"
	"encoding/binary"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/json"
)

const (
	STUN_HEADER_LENGTH = 20
	STUN_TID_SIZE = 12
	FP_SIZE = 8
     MI_SIZE = 24
)

var (
	ERROR_BAD_MESSAGE = errors.New("InStun: bad message.")
	ERROR_PROTO_ERROR = errors.New("InStun: proto error.")

)

type StunMsg struct {
	MsgType uint16
	MsgLen  uint16
	Cookie  uint32
	Tid     [STUN_TID_SIZE]byte
	Attr    []*StunAttr
	Reader	*StunReader
}

func (msg *StunMsg) String() string {
	data, _ := json.Marshal(*msg)
	return string(data)
}

//////////////////////////////////////////////////////////////////////////////////
///////////////////////////      Decode        //////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

func DecodeStunMsg(reader *StunReader, ua *UnkownAttr) (*StunMsg, error) {
	if (reader == nil) {
		return nil, ERROR_NIL_READER
	}

	var msgType, msgLen uint16
	var cookie uint32
	tid := make([]byte, STUN_TID_SIZE)

	if reader.BigEndianRead(&msgType) != nil {
		return nil, ERROR_BAD_MESSAGE
	}
	if reader.BigEndianRead(&msgLen) != nil {
		return nil, ERROR_BAD_MESSAGE
	}
	if reader.BigEndianRead(&cookie) != nil {
		return nil, ERROR_BAD_MESSAGE
	}
	if n, e := reader.Read(tid); n != STUN_TID_SIZE || e != nil {
		return nil, ERROR_BAD_MESSAGE
	}

	msg := &StunMsg {
		MsgType: msgType,
		MsgLen:     msgLen,
		Cookie: cookie,
		Reader: reader,
	}
	for i := 0; i < len(tid); i++ {
		msg.Tid[i] = tid[i]
	}

	if reader.Left() < int64(msg.MsgLen) {
		return nil, ERROR_BAD_MESSAGE
	}

	extra := reader.Left() - int64(msg.MsgLen)
	for reader.Left() - extra > 4 {
		attr, err := DecodeStunAttr(reader, ua, tid)
		if err != nil {
			break
		}
		if attr != nil {
			msg.Attr = append(msg.Attr, attr)
		}
	}
	reader.Reset()

	return msg, nil
}

func (msg *StunMsg) Class() uint16 {
	return (msg.MsgType >> 7 | msg.MsgType >> 4) & 0x3
}

func (msg *StunMsg) Method() uint16 {
	return (msg.MsgType&0x3e00)>>2 | (msg.MsgType&0x00e0)>>1 | (msg.MsgType&0x000f)
}

func (msg *StunMsg) MakeMessageIntegrity(key []uint8) ([]byte, error) {
	var header []byte

	fp := msg.PeekAttr(STUN_ATTR_FINGERPRINT)
	if fp != nil {
		msg.MsgLen -= FP_SIZE
	}
	header = msg.EncodeHeader()

	h := hmac.New(sha1.New, key)
	h.Write(header)
	msg.Reader.Seek(STUN_HEADER_LENGTH, io.SeekStart)
	buff := make([]byte, msg.MsgLen - MI_SIZE)
	msg.Reader.Read(buff)
	h.Write(buff)
	integrity := h.Sum(nil)

	if fp != nil {
		msg.MsgLen += FP_SIZE
	}

	return integrity, nil
}

func (msg *StunMsg) CheckMessageIntegrity(key []uint8) error {
	integrity, err := msg.MakeMessageIntegrity(key)
	if err != nil {
		return err
	}

	mi := msg.PeekAttr(STUN_ATTR_MSG_INTEGRITY)
	if mi == nil {
		return ERROR_PROTO_ERROR
	}

	if bytes.Equal(integrity, mi.AttrValue.([]byte)) {
		return nil
	}
	return ERROR_BAD_MESSAGE
}

func (msg *StunMsg) CheckFingerprint() error {
	fp := msg.PeekAttr(STUN_ATTR_FINGERPRINT)
	if fp == nil {
		return ERROR_PROTO_ERROR
	}

	//TODO
	return nil
}

func (msg *StunMsg) EncodeHeader() []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint16(buf, msg.MsgType)
	binary.BigEndian.PutUint16(buf[2:], msg.MsgLen)
	binary.BigEndian.PutUint32(buf[4:], msg.Cookie)
	for i := 0; i < 12; i++ {
		buf = append(buf, msg.Tid[i])
	}
	return buf
}

////////////////////////////////////////////////////////////////////////////////////
/////////////////////////      Encode         /////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////

func NewStunMsg(method uint16, class uint8, tid [STUN_TID_SIZE]byte) *StunMsg {
	msgType := (method & 0x0f80) << 2 |
		(method & 0x0070) << 1 |
		(method & 0x000f) << 0 |
		uint16(class & 0x02) << 7 |
		uint16(class & 0x01) << 4
	return &StunMsg {
		MsgType: msgType,
		Cookie: STUN_MAGIC_COOKIE,
		Tid: tid,
	}
}

// This function can take a nil parameter,
// it will do nothing that way
func (msg *StunMsg) AddAttr(attr *StunAttr) {
	if attr == nil { return }
	msg.Attr = append(msg.Attr, attr)
}

// Encode function encoding a new-created stun msg
// to bytes
func (msg *StunMsg) Encode(ec *ErrorCode, key []uint8, fingerprint bool,
	paddingByte uint8) ([]byte, error) {

	tid := make([]byte, 12)
	for i := 0; i < 12; i++ {
		tid[i] = msg.Tid[i]
	}

	body := make([]byte, 0)

	if ec != nil {
		buff, err := NewStunAttr(STUN_ATTR_ERR_CODE, ec).Encode(tid, paddingByte)
		if err != nil {
			return nil, err
		}
		body = append(body, buff...)
		msg.MsgLen = uint16(len(body))
		goto CONTACT
	}

	for i := 0; i < len(msg.Attr); i++ {
		buff, err := msg.Attr[i].Encode(tid, paddingByte)
		if err != nil {
			return nil, err
		}
		if buff != nil {
			body = append(body, buff...)
		}
	}
	msg.MsgLen = uint16(len(body))

	if key != nil {
		msg.MsgLen += MI_SIZE
		h := hmac.New(sha1.New, key)
		header := msg.EncodeHeader()
		h.Write(header)
		h.Write(body)
		mi := h.Sum(nil)
		buff, err := NewStunAttr(STUN_ATTR_MSG_INTEGRITY, mi).Encode(tid, paddingByte)
		if err != nil {
			return nil, err
		}
		body = append(body, buff...)
	}

	if fingerprint {
		var fprnt uint32
		msg.MsgLen += FP_SIZE
		fprnt = fingerPrint(append(msg.EncodeHeader(), body...))
		buff, err := NewStunAttr(STUN_ATTR_FINGERPRINT, fprnt).Encode(tid, paddingByte)
		if err != nil {
			return nil, err
		}
		body = append(body, buff...)
	}

CONTACT:
	msg.MsgLen = uint16(len(body))
	header := msg.EncodeHeader()
	return append(header, body...), nil
}

func fingerPrint(buf []byte) uint32 {
	return crc32(0, buf) ^ 0x5354554e
}