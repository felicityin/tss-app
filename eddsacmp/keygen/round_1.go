package keygen

//#include <stdio.h>
//#include <stdlib.h>
//#include <string.h>
import "C"

import (
	"fmt"
	"math/big"
	"strconv"

	"tss/common"
	"tss/crypto"
	m "tss/eddsacmp/keygen/message"
	"tss/tss"
)

type KeygenExecResult struct {
	Ok           bool   `json:"ok"`
	Err          string `json:"error"`
	MsgWireBytes []byte `json:"data"`
}

type KeygenResult struct {
	Ok  bool   `json:"ok"`
	Err string `json:"error"`
}

func KeygenRound1Exec(key string) (result KeygenExecResult) {
	party, ok := Parties[key]
	if !ok {
		common.Logger.Errorf("party not found: %s", key)
		result.Err = fmt.Sprintf("party not found: %s", key)
		return
	}

	party.number = 1
	party.resetOK()

	Pi := party.PartyID()
	i := Pi.Index
	common.Logger.Infof("party: %d, party_1 start", i)

	party.temp.ssidNonce = new(big.Int).SetUint64(0)
	ssid, err := party.getSSID()
	if err != nil {
		result.Err = fmt.Sprintf("get ssid err: %s", err.Error())
		return
	}
	party.temp.ssid = ssid

	if party.save.PrivXi == nil {
		party.save.PrivXi = common.GetRandomPositiveInt(party.params.PartialKeyRand(), party.params.EC().Params().N)
	}
	party.save.PubXj[i] = crypto.ScalarBaseMult(party.params.EC(), party.save.PrivXi)

	party.temp.tau = common.GetRandomPositiveInt(party.params.PartialKeyRand(), party.params.EC().Params().N)
	party.temp.commitedA = crypto.ScalarBaseMult(party.params.EC(), party.temp.tau)

	party.temp.u, _ = common.GetRandomBytes(party.params.Rand(), 32)
	party.temp.srid, _ = common.GetRandomBytes(party.params.Rand(), 32)

	ids := party.params.Parties().IDs().Keys()
	party.save.Ks = ids
	party.save.ShareID = ids[i]

	// Compute V_i
	hash := common.SHA512_256(
		ssid,
		[]byte(strconv.Itoa(i)),
		party.temp.srid,
		party.save.PubXj[i].X().Bytes(),
		party.save.PubXj[i].Y().Bytes(),
		party.temp.commitedA.X().Bytes(),
		party.temp.commitedA.Y().Bytes(),
		party.temp.u,
	)

	msg := m.NewKGRound1Message(party.PartyID(), hash)
	msgWireBytes, _, err := msg.WireBytes()
	if err != nil {
		common.Logger.Errorf("get msg wire bytes error: %s", key)
		result.Err = fmt.Sprintf("get msg wire bytes error: %s", key)
		return
	}
	party.temp.kgRound1Messages[i] = msgWireBytes

	result.Ok = true
	result.MsgWireBytes = msgWireBytes
	return result
}

func KeygenRound1Accept(key string, from int, msgWireBytes []byte) (result KeygenResult) {
	msg, err := tss.ParseWireMsg([]byte(msgWireBytes))
	if err != nil {
		common.Logger.Errorf("msg error, parse wire msg fail, err:%s", err.Error())
		result.Err = fmt.Sprintf("msg error, parse wire msg fail, err:%s", err.Error())
		return
	}
	if _, ok := msg.Content().(*m.KGRound1Message); !ok {
		result.Err = fmt.Sprintf("not KGRound1Message, err:%s", err.Error())
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
	party.temp.kgRound1Messages[from] = msgWireBytes
	return
}

func KeygenRound1Finish(key string) (result KeygenResult) {
	party, ok := Parties[key]
	if !ok {
		common.Logger.Errorf("party not found: %s", key)
		result.Err = fmt.Sprintf("party not found: %s", key)
		return
	}

	for j, msg := range party.temp.kgRound1Messages {
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
