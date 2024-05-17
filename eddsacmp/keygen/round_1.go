package keygen

//#include <stdio.h>
//#include <stdlib.h>
//#include <string.h>
import "C"

import (
	"math/big"
	"strconv"

	"tss/common"
	"tss/crypto"
	m "tss/eddsacmp/keygen/message"
	"tss/tss"
)

func KeygenRound1Exec(key string) (msgWireBytes []byte) {
	party, ok := Parties[key]
	if !ok {
		common.Logger.Errorf("party not found: %s", key)
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
	msgWireBytes, _, err = msg.WireBytes()
	if err != nil {
		common.Logger.Errorf("get msg wire bytes error: %s", key)
		return
	}
	party.temp.kgRound1Messages[i] = msgWireBytes
	return msgWireBytes
}

func KeygenRound1Accept(key string, from int, msgWireBytes []byte) bool {
	msg, err := tss.ParseWireMsg([]byte(msgWireBytes))
	if err != nil {
		common.Logger.Errorf("msg error, parse wire msg fail, err:%s", err.Error())
		return false
	}
	if _, ok := msg.Content().(*m.KGRound1Message); !ok {
		return false
	}

	party, ok := Parties[key]
	if !ok {
		common.Logger.Errorf("party not found: %s", key)
		return false
	}

	party.ok[from] = true
	if from == party.PartyID().Index {
		return true
	}
	party.temp.kgRound1Messages[from] = msgWireBytes
	return true
}

func KeygenRound1Finish(key string) bool {
	party, ok := Parties[key]
	if !ok {
		common.Logger.Errorf("party not found: %s", key)
		return false
	}

	for j, msg := range party.temp.kgRound1Messages {
		if party.ok[j] {
			continue
		}
		if msg == nil || len(msg) == 0 {
			return false
		}
	}
	return true
}
