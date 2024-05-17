package onsign

//#include <stdio.h>
//#include <stdlib.h>
//#include <string.h>
import "C"

import (
	"math/big"

	"google.golang.org/protobuf/proto"

	"tss/common"
	"tss/crypto"
	"tss/crypto/logproof"
	m "tss/eddsacmp/onsign/message"
	"tss/tss"
)

func OnsignRound2Exec(key string) (ok bool) {
	party, ok := SignParties[key]
	if !ok {
		common.Logger.Errorf("party not found: %s", key)
		return
	}

	party.number = 2
	party.resetOK()

	i := party.PartyID().Index
	Ps := party.params.Parties().IDs()
	common.Logger.Infof("[sign] party: %d, party_2 start", i)

	// Verify received enc proof
	for j := range Ps {
		if j == i {
			continue
		}

		pMsg, err := tss.ParseWireMsg(party.temp.signRound1Message1s[j])
		if err != nil {
			common.Logger.Errorf("msg error, parse wire msg fail, err:%s", err.Error())
			return
		}
		r1msg1 := pMsg.Content().(*m.SignRound1Message1)
		party.temp.kCiphertexts[j] = r1msg1.UnmarshalK()
		common.Logger.Debugf("P[%d]: receive P[%d]'s kCiphertext", i, j)

		pMsg, err = tss.ParseWireMsg(party.temp.signRound1Message2s[j])
		if err != nil {
			common.Logger.Errorf("msg error, parse wire msg2 fail, err:%s", err.Error())
			return
		}
		r1msg2 := pMsg.Content().(*m.SignRound1Message2)
		encProof, err := r1msg2.UnmarshalEncProof()
		if err != nil {
			common.Logger.Errorf("unmarshal enc proof failed, party: %d", j)
			return
		}
		common.Logger.Debugf("P[%d]: receive P[%d]'s enc proof", i, j)

		contextJ := append(party.temp.ssid, big.NewInt(int64(j)).Bytes()...)

		if err := encProof.Verify(ProofParameter, contextJ, party.temp.kCiphertexts[j],
			party.keys.PaillierPKs[j].N, party.keys.RingPedersenPKs[i],
		); err != nil {
			common.Logger.Errorf("verify enc proof failed, party: %d", j)
			return
		}
		common.Logger.Debugf("P[%d]: verify P[%d]'s enc proof ok", i, j)
	}

	// Compute Ri = ki * G
	common.Logger.Debugf("P[%d]: calc Ri", i)
	Ri := crypto.ScalarBaseMult(party.params.EC(), party.temp.k)

	G, err := crypto.NewECPoint(party.params.EC(), party.params.EC().Params().Gx, party.params.EC().Params().Gy)
	if err != nil {
		common.Logger.Errorf("create base point failed")
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
			return
		}
		common.Logger.Debugf("P[%d]: calc log proof for P[%d]", i, j)

		err = logProof.Verify(ProofParameter, contextI, party.temp.kCiphertexts[i],
			party.keys.PaillierPKs[i].N, party.keys.RingPedersenPKs[j], Ri, G)
		if err != nil {
			common.Logger.Errorf("verify my log proof failed: %s, party: %d", err, j)
		} else {
			common.Logger.Debugf("verify my log proof ok, for %d", j)
		}

		logProofBytes, err := proto.Marshal(logProof)
		if err != nil {
			common.Logger.Errorf("marshal log proof failed: %s, party: %d", err, j)
			return
		}

		common.Logger.Debugf("P[%d]: send log proof to P[%d]", i, j)
		r2msg := m.NewSignRound2Message(Pj, party.PartyID(), Ri, logProofBytes)
		msgWireBytes, _, err := r2msg.WireBytes()
		if err != nil {
			common.Logger.Errorf("get msg wire bytes error: %s", key)
			return
		}
		party.temp.send.signRound2Messages[j] = msgWireBytes
		if j == i {
			party.temp.signRound2Messages[i] = msgWireBytes
			continue
		}
	}

	return true
}

func OnSignRound2MsgAccept(key string, from int, msgWireBytes []byte) bool {
	msg, err := tss.ParseWireMsg([]byte(msgWireBytes))
	if err != nil {
		common.Logger.Errorf("msg error, parse wire msg fail, err:%s", err.Error())
		return false
	}
	if _, ok := msg.Content().(*m.SignRound2Message); !ok {
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
	party.temp.signRound2Messages[from] = msgWireBytes
	return true
}

func OnSignRound2Finish(key string) bool {
	party, ok := SignParties[key]
	if !ok {
		common.Logger.Errorf("party not found: %s", key)
		return false
	}

	for j, msg := range party.temp.signRound2Messages {
		if party.ok[j] {
			continue
		}
		if msg == nil || len(msg) == 0 {
			return false
		}
	}
	return true
}
