package onsign

//#include <stdio.h>
//#include <stdlib.h>
//#include <string.h>
import "C"

import (
	"encoding/base64"
	"fmt"
	"math/big"

	"tss_sdk/common"
	"tss_sdk/crypto"
	"tss_sdk/crypto/encproof"
	m "tss_sdk/eddsacmp/onsign/message"
	"tss_sdk/tss"

	edwards "github.com/decred/dcrd/dcrec/edwards/v2"
	"google.golang.org/protobuf/proto"
)

type OnsignExecResult struct {
	Ok           bool   `json:"ok"`
	Err          string `json:"error"`
	MsgWireBytes []byte `json:"data"`
}

type OnsignResult struct {
	Ok  bool   `json:"ok"`
	Err string `json:"error"`
}

var ProofParameter = crypto.NewProofConfig(edwards.Edwards().N)

func OnSignRound1Exec(key string) (result OnsignExecResult) {
	party, ok := SignParties[key]
	if !ok {
		common.Logger.Errorf("party not found: %s", key)
		result.Err = fmt.Sprintf("party not found: %s", key)
		return
	}

	party.number = 1
	party.resetOK()

	Pi := party.PartyID()
	i := Pi.Index
	common.Logger.Infof("[sign] party: %d, round_1 start", i)

	party.temp.ssidNonce = new(big.Int).SetUint64(0)
	var err error
	party.temp.ssid, err = party.getSSID()
	if err != nil {
		return
	}

	pkSum := party.keys.PubXj[0]
	for j, pubx := range party.keys.PubXj {
		common.Logger.Infof("%d, pubkey: (%d, %d)", j, pubx.X(), pubx.Y())
		if j == 0 {
			continue
		}
		pkSum, err = pkSum.Add(pubx)
		if err != nil {
			common.Logger.Errorf("calc pubkey failed, party: %d", j)
			result.Err = fmt.Sprintf("calc pubkey failed, party: %d", j)
			return
		}
	}
	party.keys.EdDSAPub = pkSum

	// k in F_q
	party.temp.k = common.GetRandomPositiveInt(party.params.Rand(), party.params.EC().Params().N)

	// Ki = enc(k, ρ)
	kCiphertext, rho, err := party.keys.PaillierPKs[i].EncryptAndReturnRandomness(
		party.params.Rand(),
		party.temp.k,
	)
	if err != nil {
		common.Logger.Errorf("P[%d]: create enc proof failed: %s", i, err)
		result.Err = fmt.Sprintf("P[%d]: create enc proof failed: %s", i, err)
		return
	}
	party.temp.rho = rho
	party.temp.kCiphertexts[i] = kCiphertext

	// broadcast Ki
	r1msg1 := m.NewSignRound1Message1(party.PartyID(), kCiphertext)
	msgWireBytes, _, err := r1msg1.WireBytes()
	if err != nil {
		common.Logger.Errorf("get msg wire bytes error: %s", key)
		result.Err = fmt.Sprintf("get msg wire bytes error: %s", key)
		return
	}
	party.temp.signRound1Message1s[i] = msgWireBytes

	contextI := append(party.temp.ssid, big.NewInt(int64(i)).Bytes()...)

	// p2p send enc proof to Pj
	for j, Pj := range party.params.Parties().IDs() {
		// M(prove, Πenc, (sid,i), (Iε,Ki); (ki,rhoi))
		encProof, err := encproof.NewEncryptRangeMessage(ProofParameter, contextI, kCiphertext,
			party.keys.PaillierPKs[i].N, party.temp.k, party.temp.rho, party.keys.RingPedersenPKs[j],
		)
		if err != nil {
			common.Logger.Errorf("create enc proof failed: %s, party: %d", err, j)
			result.Err = fmt.Sprintf("create enc proof failed: %s, party: %d", err, j)
			return
		}

		encProofBytes, err := proto.Marshal(encProof)
		if err != nil {
			common.Logger.Errorf("marshal enc proof failed: %s, party: %d", err, j)
			return
		}

		r1msg2 := m.NewSignRound1Message2(Pj, party.PartyID(), encProofBytes)
		msg2WireBytes, _, err := r1msg2.WireBytes()
		if err != nil {
			common.Logger.Errorf("get msg wire bytes error: %s", key)
			result.Err = fmt.Sprintf("get msg wire bytes error: %s", key)
			return
		}
		party.temp.send.signRound1Message2s[j] = msg2WireBytes
		if j == i {
			party.temp.signRound1Message2s[i] = msg2WireBytes
		}
	}

	result.Ok = true
	result.MsgWireBytes = msgWireBytes
	return result
}

func GetRound1Msg2(key string, to int) (result OnsignExecResult) {
	party, ok := SignParties[key]
	if !ok {
		common.Logger.Errorf("party not found: %s", key)
		result.Err = fmt.Sprintf("party not found: %s", key)
		return
	}
	result.Ok = true
	result.MsgWireBytes = party.temp.send.signRound1Message2s[to]
	return
}

func OnSignRound1MsgAccept(key string, from int, msgWireBytes string) (result OnsignResult) {
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

	msg, err := tss.ParseWireMsg(rMsgBytes)
	if err != nil {
		common.Logger.Errorf("msg error, parse wire msg fail, err:%s", err.Error())
		result.Err = fmt.Sprintf("msg error, parse wire msg fail, err:%s", err.Error())
		return
	}

	if _, ok := msg.Content().(*m.SignRound1Message1); ok {
		party.temp.signRound1Message1s[from] = rMsgBytes
	} else if _, ok := msg.Content().(*m.SignRound1Message2); ok {
		party.temp.signRound1Message2s[from] = rMsgBytes
	} else {
		result.Err = "not SignRound1Message"
		return
	}
	result.Ok = true
	return
}

func OnSignRound1Finish(key string) (result OnsignResult) {
	party, ok := SignParties[key]
	if !ok {
		common.Logger.Errorf("party not found: %s", key)
		result.Err = fmt.Sprintf("party not found: %s", key)
		return
	}

	for j, msg := range party.temp.signRound1Message2s {
		if len(party.temp.signRound1Message1s[j]) == 0 {
			result.Err = fmt.Sprintf("msg1 is null: %d", j)
			return
		}
		if len(msg) == 0 {
			result.Err = fmt.Sprintf("msg2 is null: %d", j)
			return
		}
	}
	result.Ok = true
	return
}
