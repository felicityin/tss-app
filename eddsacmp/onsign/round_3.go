package onsign

//#include <stdio.h>
//#include <stdlib.h>
//#include <string.h>
import "C"

import (
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"math/big"

	"github.com/agl/ed25519/edwards25519"

	"tss_sdk/common"
	"tss_sdk/crypto"
	m "tss_sdk/eddsacmp/onsign/message"
	"tss_sdk/tss"
)

func OnsignRound3Exec(key string) (result OnsignExecResult) {
	party, ok := SignParties[key]
	if !ok {
		common.Logger.Errorf("party not found: %s", key)
		result.Err = fmt.Sprintf("party not found: %s", key)
		return
	}

	party.number = 3
	party.resetOK()

	i := party.PartyID().Index
	common.Logger.Infof("[sign] party: %d, party_3 start", i)

	var R edwards25519.ExtendedGroupElement
	riBytes := bigIntToEncodedBytes(party.temp.k)
	edwards25519.GeScalarMultBase(&R, riBytes)

	G, err := crypto.NewECPoint(party.params.EC(), party.params.EC().Params().Gx, party.params.EC().Params().Gy)
	if err != nil {
		common.Logger.Errorf("create base point failed")
		result.Err = "create base point failed"
		return
	}

	// verify received log proof and compute R
	for j := 0; j < len(party.temp.signRound2Messages); j++ {
		if j == i {
			continue
		}

		pMsg, err := tss.ParseWireMsg(party.temp.signRound2Messages[j])
		if err != nil {
			common.Logger.Errorf("msg error, parse wire msg fail, err:%s", err.Error())
			result.Err = fmt.Sprintf("msg error, parse wire msg fail, err:%s", err.Error())
			return
		}
		r2msg := pMsg.Content().(*m.SignRound2Message)

		logProof, err := r2msg.UnmarshalLogProof(party.params.EC())
		if err != nil {
			common.Logger.Errorf("failed to unmarshal log proof: %s, party: %d", err, j)
			result.Err = fmt.Sprintf("failed to unmarshal log proof: %s, party: %d", err, j)
			return
		}

		Rj, err := r2msg.UnmarshalR(party.params.EC())
		if err != nil {
			common.Logger.Errorf("unmarshal R failed: %s, party: %d", err, j)
			result.Err = fmt.Sprintf("unmarshal R failed: %s, party: %d", err, j)
			return
		}

		contextJ := append(party.temp.ssid, big.NewInt(int64(j)).Bytes()...)

		err = logProof.Verify(ProofParameter, contextJ, party.temp.kCiphertexts[j], party.keys.PaillierPKs[j].N,
			party.keys.RingPedersenPKs[i], Rj, G)
		if err != nil {
			common.Logger.Errorf("verify log proof failed: %s, party: %d", err, j)
			result.Err = fmt.Sprintf("verify log proof failed: %s, party: %d", err, j)
			return
		}

		Rj = Rj.EightInvEight()
		if err != nil {
			result.Err = fmt.Sprintf("Rj.EightInvEight: %s", err.Error())
			return
		}

		extendedRj := ecPointToExtendedElement(party.params.EC(), Rj.X(), Rj.Y(), party.params.Rand())
		R = addExtendedElements(R, extendedRj)
	}

	// compute lambda
	var encodedR [32]byte
	R.ToBytes(&encodedR)
	encodedPubKey := ecPointToEncodedBytes(party.keys.EdDSAPub.X(), party.keys.EdDSAPub.Y())

	// h = hash512(R || X || M)
	h := sha512.New()
	h.Reset()
	h.Write(encodedR[:])
	h.Write(encodedPubKey[:])
	if party.temp.fullBytesLen == 0 {
		h.Write(party.temp.m.Bytes())
	} else {
		var mBytes = make([]byte, party.temp.fullBytesLen)
		party.temp.m.FillBytes(mBytes)
		h.Write(mBytes)
	}

	var lambda [64]byte
	h.Sum(lambda[:0])
	var lambdaReduced [32]byte
	edwards25519.ScReduce(&lambdaReduced, &lambda)

	// compute si
	var localS [32]byte
	edwards25519.ScMulAdd(&localS, &lambdaReduced, bigIntToEncodedBytes(party.keys.PrivXi), riBytes)

	// store r3 message pieces
	party.temp.si = &localS
	party.temp.r = encodedBytesToBigInt(&encodedR)

	// broadcast si to other parties
	r3msg := m.NewSignRound3Message(party.PartyID(), encodedBytesToBigInt(&localS))
	msgWireBytes, _, err := r3msg.WireBytes()
	if err != nil {
		common.Logger.Errorf("get msg wire bytes error: %s", key)
		result.Err = fmt.Sprintf("get msg wire bytes error: %s", key)
		return
	}
	party.temp.signRound3Messages[i] = msgWireBytes

	result.Ok = true
	result.MsgWireBytes = msgWireBytes
	return result
}

func OnSignRound3MsgAccept(key string, from int, msgWireBytes string) (result OnsignResult) {
	party, ok := SignParties[key]
	if !ok {
		common.Logger.Errorf("party not found: %s", key)
		result.Err = fmt.Sprintf("party not found: %s", key)
		return
	}

	rMsgBytes, err := base64.StdEncoding.DecodeString(msgWireBytes)
	if err != nil {
		common.Logger.Errorf("msg error, msg base64 decode fail, err:%s", err.Error())
		result.Err = fmt.Sprintf("msg error, msg base64 decode fail, err:%s", err.Error())
		return
	}
	party.temp.signRound3Messages[from] = rMsgBytes

	msg, err := tss.ParseWireMsg(rMsgBytes)
	if err != nil {
		common.Logger.Errorf("msg error, parse wire msg fail, err:%s", err.Error())
		result.Err = fmt.Sprintf("msg error, parse wire msg fail, err:%s", err.Error())
		return
	}
	if _, ok := msg.Content().(*m.SignRound3Message); !ok {
		result.Err = "not SignRound3Message"
		return
	}

	result.Ok = true
	return
}

func OnSignRound3Finish(key string) (result OnsignResult) {
	party, ok := SignParties[key]
	if !ok {
		common.Logger.Errorf("party not found: %s", key)
		result.Err = fmt.Sprintf("party not found: %s", key)
		return
	}

	for j, msg := range party.temp.signRound3Messages {
		if len(msg) == 0 {
			result.Err = fmt.Sprintf("msg is null: %d", j)
			return
		}
	}
	result.Ok = true
	return
}
