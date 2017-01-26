package instun

const (
	SOFTWARE = "InStun 0.0.1"
	PADDING_BYTE = ' '
)

type StunMsgCtx struct {
	ua UnkownAttr
	key []uint8
	fp bool
}

