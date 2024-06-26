package onsign

//#include <stdio.h>
//#include <stdlib.h>
//#include <string.h>
import "C"

import (
	"encoding/json"
	"fmt"
	"math/big"

	"tss_sdk/common"
	m "tss_sdk/eddsacmp/onsign/message"
	"tss_sdk/tss"

	// m "tss_sdk/eddsacmp/onsign/message"

	"github.com/agl/ed25519/edwards25519"
	edwards "github.com/decred/dcrd/dcrec/edwards/v2"
)

func OnsignFinalExec(key string) (result OnsignExecResult) {
	party, ok := SignParties[key]
	if !ok {
		common.Logger.Errorf("party not found: %s", key)
		result.Err = fmt.Sprintf("party not found: %s", key)
		return
	}

	party.number = 4
	party.resetOK()

	Pi := party.PartyID()
	i := Pi.Index

	common.Logger.Infof("[sign] party: %d, party_4 start", i)

	sumS := party.temp.si
	for j := range party.params.Parties().IDs() {
		party.ok[j] = true
		if j == party.PartyID().Index {
			continue
		}

		pMsg, err := tss.ParseWireMsg(party.temp.signRound3Messages[j])
		if err != nil {
			common.Logger.Errorf("msg error, parse wire msg fail, err:%s", err.Error())
			result.Err = fmt.Sprintf("msg error, parse wire msg fail, err:%s", err.Error())
			return
		}
		r3msg := pMsg.Content().(*m.SignRound3Message)
		sjBytes := bigIntToEncodedBytes(r3msg.UnmarshalS())
		var tmpSumS [32]byte
		edwards25519.ScMulAdd(&tmpSumS, sumS, bigIntToEncodedBytes(big.NewInt(1)), sjBytes)
		sumS = &tmpSumS
	}
	s := encodedBytesToBigInt(sumS)

	// save the signature for final output
	party.data.Signature = append(bigIntToEncodedBytes(party.temp.r)[:], sumS[:]...)
	party.data.R = party.temp.r.Bytes()
	party.data.S = s.Bytes()
	if party.temp.fullBytesLen == 0 {
		party.data.M = party.temp.m.Bytes()
	} else {
		var mBytes = make([]byte, party.temp.fullBytesLen)
		party.temp.m.FillBytes(mBytes)
		party.data.M = mBytes
	}

	pk := edwards.PublicKey{
		Curve: party.params.EC(),
		X:     party.keys.EdDSAPub.X(),
		Y:     party.keys.EdDSAPub.Y(),
	}

	ok = edwards.Verify(&pk, party.data.M, party.temp.r, s)
	if !ok {
		common.Logger.Errorf("verify failed")
		result.Err = "verify failed"
		return
	}

	saveBytes, err := json.Marshal(party.data)
	if err != nil {
		common.Logger.Errorf("round_final save err: %s", err.Error())
		result.Err = fmt.Sprintf("round_final save err: %s", err.Error())
		return
	}

	result.Ok = true
	result.MsgWireBytes = saveBytes
	return result
}
