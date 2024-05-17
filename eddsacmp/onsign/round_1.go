package onsign

//#include <stdio.h>
//#include <stdlib.h>
//#include <string.h>
import "C"

import (
	"math/big"

	"tss/common"
	"tss/crypto"
	"tss/crypto/encproof"
	m "tss/eddsacmp/onsign/message"
	"tss/tss"

	edwards "github.com/decred/dcrd/dcrec/edwards/v2"
	"google.golang.org/protobuf/proto"
)

var ProofParameter = crypto.NewProofConfig(edwards.Edwards().N)

func OnSignRound1Exec(key string) (msgWireBytes []byte) {
	party, ok := SignParties[key]
	if !ok {
		common.Logger.Errorf("party not found: %s", key)
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
			return
		}
	}
	party.keys.EdDSAPub = pkSum

	// k in F_q
	party.temp.k = common.GetRandomPositiveInt(party.params.Rand(), party.params.EC().Params().N)
	common.Logger.Debugf("P[%d]: calc ki", i)

	// Ki = enc(k, ρ)
	kCiphertext, rho, err := party.keys.PaillierPKs[i].EncryptAndReturnRandomness(
		party.params.Rand(),
		party.temp.k,
	)
	if err != nil {
		common.Logger.Errorf("P[%d]: create enc proof failed: %s", i, err)
		return
	}
	party.temp.rho = rho
	party.temp.kCiphertexts[i] = kCiphertext
	common.Logger.Debugf("P[%d]: calc kCiphertext", i)

	// broadcast Ki
	common.Logger.Debugf("P[%d]: broadcast Ki", i)
	r1msg1 := m.NewSignRound1Message1(party.PartyID(), kCiphertext)
	msgWireBytes, _, err = r1msg1.WireBytes()
	if err != nil {
		common.Logger.Errorf("get msg wire bytes error: %s", key)
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
			return
		}
		common.Logger.Debugf("P[%d]: calc enc proof", i)

		encProofBytes, err := proto.Marshal(encProof)
		if err != nil {
			common.Logger.Errorf("marshal enc proof failed: %s, party: %d", err, j)
			return
		}

		common.Logger.Debugf("P[%d]: p2p send enc proof", i)
		r1msg2 := m.NewSignRound1Message2(Pj, party.PartyID(), encProofBytes)
		msg2WireBytes, _, err := r1msg2.WireBytes()
		if err != nil {
			common.Logger.Errorf("get msg wire bytes error: %s", key)
			return
		}
		party.temp.send.signRound1Message2s[j] = msg2WireBytes
		if j == i {
			party.temp.signRound1Message2s[i] = msg2WireBytes
		}
	}

	return msgWireBytes
}

func GetRound1Msg2(key string, to int) (msgWireBytes []byte) {
	party, ok := SignParties[key]
	if !ok {
		common.Logger.Errorf("party not found: %s", key)
		return nil
	}
	return party.temp.send.signRound1Message2s[to]
}

func OnSignRound1Msg1Accept(key string, from int, msgWireBytes []byte) bool {
	msg, err := tss.ParseWireMsg([]byte(msgWireBytes))
	if err != nil {
		common.Logger.Errorf("msg error, parse wire msg fail, err:%s", err.Error())
		return false
	}
	if _, ok := msg.Content().(*m.SignRound1Message1); !ok {
		return false
	}

	party, ok := SignParties[key]
	if !ok {
		common.Logger.Errorf("party not found: %s", key)
		return false
	}

	party.ok[from] = true
	if from == party.PartyID().Index {
		return true
	}
	party.temp.signRound1Message1s[from] = msgWireBytes
	return true
}

func OnSignRound1Msg2Accept(key string, from int, msgWireBytes []byte) bool {
	msg, err := tss.ParseWireMsg([]byte(msgWireBytes))
	if err != nil {
		common.Logger.Errorf("msg error, parse wire msg fail, err:%s", err.Error())
		return false
	}
	if _, ok := msg.Content().(*m.SignRound1Message2); !ok {
		return false
	}

	party, ok := SignParties[key]
	if !ok {
		common.Logger.Errorf("party not found: %s", key)
		return false
	}

	party.ok[from] = true
	if from == party.PartyID().Index {
		return true
	}
	party.temp.signRound1Message2s[from] = msgWireBytes
	return true
}

func OnSignRound1Finish(key string) bool {
	party, ok := SignParties[key]
	if !ok {
		common.Logger.Errorf("party not found: %s", key)
		return false
	}

	for j, msg := range party.temp.signRound1Message2s {
		if party.ok[j] {
			continue
		}
		if msg == nil || len(msg) == 0 {
			return false
		}
	}
	return true
}
