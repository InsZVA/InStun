package instun

import "net"

const (
	STUN_METHOD_BINDING    = 0x001
	STUN_METHOD_ALLOCATE   = 0x003
	STUN_METHOD_REFRESH    = 0x004
	STUN_METHOD_SEND       = 0x006
	STUN_METHOD_DATA       = 0x007
	STUN_METHOD_CREATEPERM = 0x008
	STUN_METHOD_CHANBIND   = 0x009

	STUN_CLASS_REQUEST = 0x0 /**< STUN Request          */

)

func requestHandler(ctx *StunMsgCtx, conn net.Conn, msg *StunMsg) bool {
	switch msg.Method() {
	case STUN_METHOD_BINDING:
		return BindingHandler(ctx, conn, msg)
	}
	return false
}
