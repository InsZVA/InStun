package instun

type ResponseHandler func (ct *StunCTrans, err error, ec ErrorCode, msg *StunMsg)