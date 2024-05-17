package keygen

//#include <stdio.h>
//#include <stdlib.h>
//#include <string.h>
import "C"

import (
	"tss/common"
	m "tss/eddsacmp/keygen/message"
	"tss/tss"
)

func KeygenRound2Exec(key string) (msgWireBytes []byte) {
	party, ok := Parties[key]
	if !ok {
		common.Logger.Errorf("party not found: %s", key)
		return
	}

	party.number = 2
	party.resetOK()

	i := party.PartyID().Index

	for j, bz := range party.temp.kgRound1Messages {
		pMsg, err := tss.ParseWireMsg(bz)
		if err != nil {
			common.Logger.Errorf("msg error, parse wire msg fail, err:%s", err.Error())
			return
		}
		r1Msg := pMsg.Content().(*m.KGRound1Message)
		party.temp.V[j] = r1Msg.Commitment
	}

	msg := m.NewKGRound2Message(
		party.PartyID(),
		party.temp.ssid,
		party.temp.srid,
		party.save.PubXj[i],
		party.temp.commitedA,
		party.temp.u,
	)
	var err error
	msgWireBytes, _, err = msg.WireBytes()
	if err != nil {
		common.Logger.Errorf("get msg wire bytes error: %s", key)
		return
	}
	party.temp.kgRound2Messages[i] = msgWireBytes
	return msgWireBytes

}

func KeygenRound2Accept(key string, from int, msgWireBytes []byte) bool {
	msg, err := tss.ParseWireMsg([]byte(msgWireBytes))
	if err != nil {
		common.Logger.Errorf("msg error, parse wire msg fail, err:%s", err.Error())
		return false
	}
	if _, ok := msg.Content().(*m.KGRound2Message); !ok {
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
	party.temp.kgRound2Messages[from] = msgWireBytes
	return true
}

func KeygenRound2Finish(key string) bool {
	party, ok := Parties[key]
	if !ok {
		common.Logger.Errorf("party not found: %s", key)
		return false
	}

	for j, msg := range party.temp.kgRound3Messages {
		if party.ok[j] {
			continue
		}
		if msg == nil || len(msg) == 0 {
			return false
		}
	}
	return true
}
