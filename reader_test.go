package instun

import (
	"testing"
)

func TestStunReader_Left(t *testing.T) {
	reader := NewStunReaderFromBytes([]byte{0x7, 0x8, 0x9, 0xa, 0x1})
	var u uint32
	reader.BigEndianRead(&u)
	if reader.Left() != 1 {
		t.Error("left test error")
	}
}