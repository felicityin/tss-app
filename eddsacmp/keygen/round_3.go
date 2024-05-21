package keygen

//#include <stdio.h>
//#include <stdlib.h>
//#include <string.h>
import "C"

import (
	"bytes"
	"fmt"
	"math/big"
	"strconv"

	"tss/common"
	"tss/crypto/alice/utils"
	"tss/crypto/schnorr"
	m "tss/eddsacmp/keygen/message"
	"tss/tss"
)

func KeygenRound3Exec(key string) (result KeygenExecResult) {
	party, ok := Parties[key]
	if !ok {
		result.Err = fmt.Sprintf("party not found: %s", key)
		return
	}

	party.number = 3
	party.resetOK()

	i := party.PartyID().Index
	common.Logger.Infof("party: %d, round_3 start", i)

	for j, bz := range party.temp.kgRound2Messages {
		if j == i {
			continue
		}

		pMsg, err := tss.ParseWireMsg(bz)
		if err != nil {
			common.Logger.Errorf("msg error, parse wire msg fail, err:%s", err.Error())
			result.Err = fmt.Sprintf("msg error, parse wire msg fail, err:%s", err.Error())
			return
		}

		r2Msg := pMsg.Content().(*m.KGRound2Message)

		party.temp.payload[j], err = r2Msg.UnmarshalPayload(party.params.EC())
		if err != nil {
			result.Err = fmt.Sprintf("unmarshal r2msg payload err:%s", err.Error())
			return
		}
		party.save.PubXj[j], err = r2Msg.UnmarshalPubXj(party.params.EC())
		if err != nil {
			result.Err = fmt.Sprintf("unmarshal r2msg pubxj err:%s", err.Error())
			return
		}

		if !bytes.Equal(party.temp.payload[j].Ssid, party.temp.ssid) {
			common.Logger.Errorf("payload.ssid != round.temp.ssid, party: %d", j)
			result.Err = fmt.Sprintf("payload.ssid != round.temp.ssid, party: %d", j)
			return
		}

		v := common.SHA512_256(
			party.temp.ssid,
			[]byte(strconv.Itoa(j)),
			party.temp.payload[j].Srid,
			party.save.PubXj[j].X().Bytes(),
			party.save.PubXj[j].Y().Bytes(),
			party.temp.payload[j].CommitedA.X().Bytes(),
			party.temp.payload[j].CommitedA.Y().Bytes(),
			party.temp.payload[j].U,
		)

		// Verify commited V_i
		if !bytes.Equal(v, party.temp.V[j]) {
			common.Logger.Errorf("hash != V, party: %d", j)
			result.Err = fmt.Sprintf("hash != V, party: %d", j)
			return
		}

		// Set srid as xor of all party's srid_i
		party.temp.srid = utils.Xor(party.temp.srid, party.temp.payload[j].Srid)
	}

	challenge := common.RejectionSample(
		party.params.EC().Params().N,
		common.SHA512_256i_TAGGED(
			append(party.temp.ssid, party.temp.srid...),
			big.NewInt(int64(i)),
			party.save.PubXj[i].X(),
			party.save.PubXj[i].Y(),
			party.temp.commitedA.X(),
			party.temp.commitedA.Y(),
		),
	)

	// Generate schnorr proof
	schProof := schnorr.Prove(party.params.EC().Params().N, party.temp.tau, challenge, party.save.PrivXi)

	// BROADCAST proofs
	bmsg := m.NewKGRound3Message(party.PartyID(), schProof.Proof.Bytes())

	msgWireBytes, _, err := bmsg.WireBytes()
	if err != nil {
		common.Logger.Errorf("get msg wire bytes error: %s", key)
		result.Err = fmt.Sprintf("get msg wire bytes error: %s", key)
		return
	}
	party.temp.kgRound3Messages[i] = msgWireBytes

	result.Ok = true
	result.MsgWireBytes = msgWireBytes
	return result
}

func KeygenRound3Accept(key string, from int, msgWireBytes []byte) (result KeygenResult) {
	msg, err := tss.ParseWireMsg([]byte(msgWireBytes))
	if err != nil {
		common.Logger.Errorf("msg error, parse wire msg fail, err:%s", err.Error())
		result.Err = fmt.Sprintf("msg error, parse wire msg fail, err:%s", err.Error())
		return
	}
	if _, ok := msg.Content().(*m.KGRound3Message); !ok {
		result.Err = fmt.Sprintf("not KGRound3Message, err:%s", err.Error())
		return
	}

	party, ok := Parties[key]
	if !ok {
		common.Logger.Errorf("party not found: %s", key)
		result.Err = fmt.Sprintf("party not found: %s", key)
		return
	}

	result.Ok = true
	party.ok[from] = true
	if from == party.PartyID().Index {
		return
	}
	party.temp.kgRound3Messages[from] = msgWireBytes
	return
}

func KeygenRound3Finish(key string) (result KeygenResult) {
	party, ok := Parties[key]
	if !ok {
		common.Logger.Errorf("party not found: %s", key)
		result.Err = fmt.Sprintf("party not found: %s", key)
		return
	}

	for j, msg := range party.temp.kgRound3Messages {
		if party.ok[j] {
			continue
		}
		if msg == nil || len(msg) == 0 {
			result.Err = fmt.Sprintf("msg is null: %d", j)
			return
		}
	}
	result.Ok = true
	return
}
