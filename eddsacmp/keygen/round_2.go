package keygen

//#include <stdio.h>
//#include <stdlib.h>
//#include <string.h>
import "C"

import (
	"fmt"
	"tss/common"
	m "tss/eddsacmp/keygen/message"
	"tss/tss"
)

func KeygenRound2Exec(key string) (result KeygenExecResult) {
	party, ok := Parties[key]
	if !ok {
		common.Logger.Errorf("party not found: %s", key)
		result.Err = fmt.Sprintf("party not found: %s", key)
		return
	}

	party.number = 2
	party.resetOK()

	i := party.PartyID().Index

	for j, bz := range party.temp.kgRound1Messages {
		pMsg, err := tss.ParseWireMsg(bz)
		if err != nil {
			common.Logger.Errorf("msg error, parse wire msg fail, err:%s", err.Error())
			result.Err = fmt.Sprintf("msg error, parse wire msg fail, err:%s", err.Error())
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
	msgWireBytes, _, err := msg.WireBytes()
	if err != nil {
		common.Logger.Errorf("get msg wire bytes error: %s", key)
		result.Err = fmt.Sprintf("get msg wire bytes error: %s", key)
		return
	}
	party.temp.kgRound2Messages[i] = msgWireBytes

	result.Ok = true
	result.MsgWireBytes = msgWireBytes
	return result

}

func KeygenRound2Accept(key string, from int, msgWireBytes []byte) (result KeygenResult) {
	msg, err := tss.ParseWireMsg([]byte(msgWireBytes))
	if err != nil {
		common.Logger.Errorf("msg error, parse wire msg fail, err:%s", err.Error())
		result.Err = fmt.Sprintf("msg error, parse wire msg fail, err:%s", err.Error())
		return
	}
	if _, ok := msg.Content().(*m.KGRound2Message); !ok {
		result.Err = fmt.Sprintf("not KGRound2Message, err:%s", err.Error())
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
	party.temp.kgRound2Messages[from] = msgWireBytes
	return
}

func KeygenRound2Finish(key string) (result KeygenResult) {
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
