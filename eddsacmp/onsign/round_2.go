package onsign

//#include <stdio.h>
//#include <stdlib.h>
//#include <string.h>
import "C"

import (
	"encoding/base64"
	"fmt"
	"math/big"

	"google.golang.org/protobuf/proto"

	"tss_sdk/common"
	"tss_sdk/crypto"
	"tss_sdk/crypto/logproof"
	m "tss_sdk/eddsacmp/onsign/message"
	"tss_sdk/tss"
)

func OnsignRound2Exec(key string) (result OnsignResult) {
	party, ok := SignParties[key]
	if !ok {
		common.Logger.Errorf("party not found: %s", key)
		result.Err = fmt.Sprintf("party not found: %s", key)
		return
	}

	party.number = 2
	party.resetOK()

	i := party.PartyID().Index
	common.Logger.Infof("[sign] party: %d, party_2 start", i)

	// Verify received enc proof
	for j := 0; j < len(party.temp.signRound1Message1s); j++ {
		if j == i {
			continue
		}

		pMsg, err := tss.ParseWireMsg(party.temp.signRound1Message1s[j])
		if err != nil {
			common.Logger.Errorf("msg error, parse wire msg1 fail, err:%s", err.Error())
			result.Err = fmt.Sprintf("msg error, parse wire msg1 fail, err:%s", err.Error())
			return
		}
		r1msg1 := pMsg.Content().(*m.SignRound1Message1)
		party.temp.kCiphertexts[j] = r1msg1.UnmarshalK()

		pMsg, err = tss.ParseWireMsg(party.temp.signRound1Message2s[j])
		if err != nil {
			common.Logger.Errorf("msg error, parse wire msg2 fail, err:%s", err.Error())
			result.Err = fmt.Sprintf("msg error, parse wire msg2 fail, err:%s", err.Error())
			return
		}
		r1msg2 := pMsg.Content().(*m.SignRound1Message2)
		encProof, err := r1msg2.UnmarshalEncProof()
		if err != nil {
			common.Logger.Errorf("unmarshal enc proof failed, party: %d", j)
			result.Err = fmt.Sprintf("unmarshal enc proof failed, party: %d", j)
			return
		}

		contextJ := append(party.temp.ssid, big.NewInt(int64(j)).Bytes()...)

		if err := encProof.Verify(ProofParameter, contextJ, party.temp.kCiphertexts[j],
			party.keys.PaillierPKs[j].N, party.keys.RingPedersenPKs[i],
		); err != nil {
			common.Logger.Errorf("verify enc proof failed, party: %d", j)
			result.Err = fmt.Sprintf("verify enc proof failed, party: %d", j)
			return
		}
	}

	// Compute Ri = ki * G
	Ri := crypto.ScalarBaseMult(party.params.EC(), party.temp.k)

	G, err := crypto.NewECPoint(party.params.EC(), party.params.EC().Params().Gx, party.params.EC().Params().Gy)
	if err != nil {
		common.Logger.Errorf("create base point failed")
		result.Err = "create base point failed"
		return
	}

	contextI := append(party.temp.ssid, big.NewInt(int64(i)).Bytes()...)

	// p2p send log proof to Pj
	for j, Pj := range party.params.Parties().IDs() {
		// logProof for the secret k, rho: M(prove, Πlog, (sid,i), (Iε,Ki,Ri,g); (ki,rhoi))
		logProof, err := logproof.NewKnowExponentAndPaillierEncryption(ProofParameter, contextI, party.temp.k,
			party.temp.rho, party.temp.kCiphertexts[i], party.keys.PaillierPKs[i].N, party.keys.RingPedersenPKs[j], Ri, G)
		if err != nil {
			common.Logger.Errorf("create log proof failed")
			result.Err = "create log proof failed"
			return
		}

		err = logProof.Verify(ProofParameter, contextI, party.temp.kCiphertexts[i],
			party.keys.PaillierPKs[i].N, party.keys.RingPedersenPKs[j], Ri, G)
		if err != nil {
			common.Logger.Errorf("verify my log proof failed: %s, party: %d", err, j)
			result.Err = fmt.Sprintf("verify my log proof failed: %s, party: %d", err, j)
			return
		}

		logProofBytes, err := proto.Marshal(logProof)
		if err != nil {
			common.Logger.Errorf("marshal log proof failed: %s, party: %d", err, j)
			result.Err = fmt.Sprintf("marshal log proof failed: %s, party: %d", err, j)
			return
		}

		r2msg := m.NewSignRound2Message(Pj, party.PartyID(), Ri, logProofBytes)
		msgWireBytes, _, err := r2msg.WireBytes()
		if err != nil {
			common.Logger.Errorf("get msg wire bytes error: %s", key)
			result.Err = fmt.Sprintf("get msg wire bytes error: %s", key)
			return
		}
		party.temp.send.signRound2Messages[j] = msgWireBytes
		if j == i {
			party.temp.signRound2Messages[i] = msgWireBytes
			continue
		}
	}

	result.Ok = true
	return result
}

func GetRound2Msg(key string, to int) (result OnsignExecResult) {
	party, ok := SignParties[key]
	if !ok {
		common.Logger.Errorf("party not found: %s", key)
		result.Err = fmt.Sprintf("party not found: %s", key)
		return
	}
	result.Ok = true
	result.MsgWireBytes = party.temp.send.signRound2Messages[to]
	return
}

func OnSignRound2MsgAccept(key string, from int, msgWireBytes string) (result OnsignResult) {
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
	party.temp.signRound2Messages[from] = rMsgBytes

	msg, err := tss.ParseWireMsg(rMsgBytes)
	if err != nil {
		common.Logger.Errorf("msg error, parse wire msg fail, err:%s", err.Error())
		result.Err = fmt.Sprintf("msg error, parse wire msg fail, err:%s", err.Error())
		return
	}
	if _, ok := msg.Content().(*m.SignRound2Message); !ok {
		result.Err = "not SignRound2Message"
		return
	}

	result.Ok = true
	return
}

func OnSignRound2Finish(key string) (result OnsignResult) {
	party, ok := SignParties[key]
	if !ok {
		common.Logger.Errorf("party not found: %s", key)
		result.Err = "not SignRound1Message2"
		return
	}

	for j, msg := range party.temp.signRound2Messages {
		if len(msg) == 0 {
			result.Err = fmt.Sprintf("msg is null: %d", j)
			return
		}
	}
	result.Ok = true
	return
}
