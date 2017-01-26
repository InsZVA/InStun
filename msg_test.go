package instun

import (
	"testing"
	"encoding/json"
	"crypto/md5"
)

const (
	BINDING_SUCCESS_RESPONSE = 0x0101
)

func assert(t *testing.T, b bool, msg string) {
	if !b {
		t.Error(msg + "\n")
	}
}

var rawData = [][]byte{
	[]byte {0x01, 0x01, 0x00, 0x3c, 0x21, 0x12, 0xa4, 0x42,
			0x2f, 0x55, 0x36, 0x75, 0x66, 0x37, 0x31, 0x43, 0x37, 0x65, 0x70,
			0x31, 0x00, 0x20, 0x00, 0x08, 0x00, 0x01, 0x6e, 0x10, 0x1c, 0x8d,
			0xcc, 0xb0, 0x00, 0x06, 0x00, 0x09, 0x4f, 0x36, 0x56, 0x6c, 0x3a,
			0x4d, 0x41, 0x37, 0x4b, 0x20, 0x20, 0x20, 0x00,	0x08, 0x00, 0x14,
			0x9c, 0xfc, 0x01, 0x5a, 0x68, 0x21, 0x9c, 0x77,	0xed, 0xa5, 0x47,
			0x8d, 0x80, 0x0d, 0x7a, 0xd5, 0xde, 0xe8, 0x28,	0xc4, 0x80, 0x28,
			0x00, 0x04, 0xf5, 0x75, 0x86, 0xcf},
}

func TestDecodeStunMsg(t *testing.T) {
	// Test:
	// MsgType, MsgLength, Tid
	// Attributes: X-MAPPED-ADDRESS, USERNAME, INTEGRITY, FINGERPRINT
	rawStun := rawData[0]
	reader := NewStunReaderFromBytes(rawStun)
	var ua UnkownAttr
	msg, err := DecodeStunMsg(reader, &ua)
	if err != nil {
		t.Error(err)
	}
	assert(t, msg.MsgType == BINDING_SUCCESS_RESPONSE, "msgType error!")
	assert(t, msg.MsgLen == 60, "msgLen error!")
	assert(t, msg.Tid == [STUN_TID_SIZE]uint8{0x2f, 0x55, 0x36, 0x75, 0x66, 0x37, 0x31, 0x43, 0x37, 0x65, 0x70,
		0x31}, "tid error!")
	assert(t, len(msg.Attr) == 4, "attributes lost!")
	assert(t, msg.Attr[0].AttrType == STUN_ATTR_XOR_MAPPED_ADDR && (msg.Attr[0].AttrValue.(*StunAddr)).String() ==
	"61.159.104.242:20226", "xor_mapped_addr error!")
	assert(t, msg.Attr[1].AttrType == STUN_ATTR_USERNAME && msg.Attr[1].AttrValue.(string) == "O6Vl:MA7K",
	"username error!")
	assert(t, msg.Attr[2].AttrType == STUN_ATTR_MSG_INTEGRITY && msg.Attr[2].AttrValue.([]byte)[9] == 0xa5,
	"integrity error!")
	assert(t, msg.Attr[3].AttrType == STUN_ATTR_FINGERPRINT && msg.Attr[3].AttrValue.(uint32) == 0xf57586cf,
	"fingerprint error!")
	d, _ := json.Marshal(msg)
	t.Log(string(d))
}

/*
func TestStunMsg_CheckMessageIntegrity(t *testing.T) {
	rawStun := rawData[0]
	reader := NewStunReaderFromBytes(rawStun)
	var ua UnkownAttr
	msg, err := DecodeStunMsg(reader, &ua)
	if err != nil {
		t.Error(err)
	}
	h := md5.New()
	h.Write()
	t.Log(msg.CheckMessageIntegrity())
}*/

func TestStunMsg_MakeMessageIntegrity(t *testing.T) {
	msg := NewStunMsg(STUN_METHOD_BINDING, STUN_CLASS_REQUEST,
		[STUN_TID_SIZE]uint8{0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0x10, 0x11, 0x12})
}
