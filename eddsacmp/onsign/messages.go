package onsign

import (
	m "tss/eddsacmp/onsign/message"
	"tss/tss"
)

// These messages were generated from Protocol Buffers definitions into eddsa-signing.pb.go
// The following messages are registered on the Protocol Buffers "wire"

var (
	// Ensure that signing messages implement ValidateBasic
	_ = []tss.MessageContent{
		(*m.SignRound1Message1)(nil),
		(*m.SignRound1Message2)(nil),
		(*m.SignRound2Message)(nil),
		(*m.SignRound3Message)(nil),
	}
)
