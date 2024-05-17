package keygen

import (
	msg "tss/eddsacmp/keygen/message"
	"tss/tss"
)

// These messages were generated from Protocol Buffers definitions into eddsa-keygen.pb.go
// The following messages are registered on the Protocol Buffers "wire"

var (
	// Ensure that keygen messages implement ValidateBasic
	_ = []tss.MessageContent{
		(*msg.KGRound1Message)(nil),
		(*msg.KGRound2Message)(nil),
		(*msg.KGRound3Message)(nil),
	}
)
