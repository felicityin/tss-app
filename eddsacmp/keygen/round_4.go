package keygen

//#include <stdio.h>
//#include <stdlib.h>
//#include <string.h>
import "C"

import (
	"encoding/json"
	"fmt"
	"math/big"

	"tss/common"
	"tss/crypto/schnorr"
	m "tss/eddsacmp/keygen/message"
	"tss/tss"
)

func KeygenRound4Exec(key string) (result KeygenExecResult) {
	party, ok := Parties[key]
	if !ok {
		common.Logger.Errorf("party not found: %s", key)
		result.Err = fmt.Sprintf("party not found: %s", key)
		return
	}

	party.number = 4
	party.resetOK()

	i := party.PartyID().Index
	common.Logger.Infof("party: %d, round_4 start", i)

	for j, bz := range party.temp.kgRound3Messages {
		if j == i {
			continue
		}

		pMsg, err := tss.ParseWireMsg(bz)
		if err != nil {
			common.Logger.Errorf("msg error, parse wire msg fail, err:%s", err.Error())
			result.Err = fmt.Sprintf("msg error, parse wire msg fail, err:%s", err.Error())
			return
		}

		challenge := common.RejectionSample(
			party.params.EC().Params().N,
			common.SHA512_256i_TAGGED(
				append(party.temp.ssid, party.temp.srid...),
				big.NewInt(int64(j)),
				party.save.PubXj[j].X(),
				party.save.PubXj[j].Y(),
				party.temp.payload[j].CommitedA.X(),
				party.temp.payload[j].CommitedA.Y(),
			),
		)

		schProof := schnorr.Proof{Proof: pMsg.Content().(*m.KGRound3Message).UnmarshalSchProof()}

		if !schProof.Verify(party.temp.payload[j].CommitedA, party.save.PubXj[j], challenge) {
			common.Logger.Errorf("schnorr proof verify failed, party: %d", j)
			result.Err = fmt.Sprintf("schnorr proof verify failed, party: %d", j)
			return
		}
	}

	// Compute and SAVE the EdDSA public key
	eddsaPubKey := party.save.PubXj[0]
	var err error
	for j, pubx := range party.save.PubXj {
		common.Logger.Infof("%d, pubkey: (%d, %d)", j, pubx.X(), pubx.Y())
		if j == 0 {
			continue
		}
		eddsaPubKey, err = eddsaPubKey.Add(pubx)
		if err != nil {
			common.Logger.Errorf("calc pubkey failed, party: %d", j)
			result.Err = fmt.Sprintf("calc pubkey failed, party: %d", j)
			return
		}
	}
	party.save.EdDSAPub = eddsaPubKey

	saveBytes, err := json.Marshal(party.save)
	if err != nil {
		common.Logger.Errorf("round_4 save err: %s", err.Error())
		result.Err = fmt.Sprintf("round_4 save err: %s", err.Error())
		return
	}
	common.Logger.Infof("party: %d, round_4 save", i)

	result.Ok = true
	result.MsgWireBytes = saveBytes
	return result
}
