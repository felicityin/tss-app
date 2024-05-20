package onsign

//#include <stdio.h>
//#include <stdlib.h>
//#include <string.h>
import "C"

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"tss/common"
	"tss/crypto"
	pailliera "tss/crypto/alice/paillier"
	"tss/crypto/paillier"
	"tss/eddsacmp/keygen"
	"tss/tss"
)

// Implements Party
// Implements Stringer
// var _ tss.Party = (*LocalParty)(nil)
// var _ fmt.Stringer = (*LocalParty)(nil)

type (
	LocalParty struct {
		*tss.BaseParty
		params *tss.Parameters

		keys   keygen.LocalPartySaveData
		temp   localTempData
		data   *common.SignatureData
		number int
		ok     []bool
	}

	localMessageStore struct {
		signRound1Message1s,
		signRound1Message2s,
		signRound2Messages,
		signRound3Messages [][]byte // msg.WireBytes()
	}

	sendMessageStore struct {
		signRound1Message2s,
		signRound2Messages [][]byte // msg.WireBytes()
	}

	localTempData struct {
		localMessageStore
		send sendMessageStore

		// temp data (thrown away after sign) / round 1
		k            *big.Int
		rho          *big.Int
		kCiphertexts []*big.Int
		m            *big.Int
		fullBytesLen int

		// round 2
		si *[32]byte

		// round 3
		r *big.Int

		ssid      []byte
		ssidNonce *big.Int
	}
)

var SignParties = map[string]*LocalParty{}

func NewLocalParty(
	key string,
	partyIndex int,
	partyCount int,
	pIDs []string,
	msg string, // hex string
	keyData []byte, // keygen.LocalPartySaveData
	refreshData []byte, // refresh.LocalPartySaveData
) bool {
	uIds := make(tss.UnSortedPartyIDs, 0, partyCount)
	for i := 0; i < partyCount; i++ {
		pId, _ := new(big.Int).SetString(pIDs[i], 10)
		uIds = append(uIds, tss.NewPartyID(fmt.Sprintf("%d", i), fmt.Sprintf("m_%d", i), pId))
	}
	ids := tss.SortPartyIDs(uIds)
	p2pCtx := tss.NewPeerContext(ids)
	params := tss.NewParameters(tss.Edwards(), p2pCtx, ids[partyIndex], partyCount, partyCount)

	keys := &keygen.LocalPartySaveData{}
	if err := json.Unmarshal(keyData, keys); err != nil {
		common.Logger.Errorf("unmarshal keygen save data err: %s", err.Error())
		return false
	}

	rfSave := &RefreshLocalPartySaveData{}
	if err := json.Unmarshal(refreshData, rfSave); err != nil {
		common.Logger.Errorf("unmarshal refresh save data err: %s", err.Error())
		return false
	}

	keys.LocalRefreshSaveData = NewRefreshSaveData(partyCount)
	j := 1376
	for i := 0; i < partyCount; i++ {
		keys.LocalRefreshSaveData.PaillierPKs[i] = &paillier.PublicKey{
			N: new(big.Int).SetBytes(rfSave.Payload[j+33 : j+289]),
		}
		keys.LocalRefreshSaveData.RingPedersenPKs[i] = &pailliera.PedPubKey{
			N: new(big.Int).SetBytes(rfSave.Payload[j+289 : j+417]),
			S: new(big.Int).SetBytes(rfSave.Payload[j+417 : j+545]),
			T: new(big.Int).SetBytes(rfSave.Payload[j+545 : j+673]),
		}
		j += 673
	}

	p := &LocalParty{
		BaseParty: new(tss.BaseParty),
		params:    params,
		keys:      keygen.BuildLocalSaveDataSubset(*keys, params.Parties().IDs()),
		temp:      localTempData{},
		data:      &common.SignatureData{},
		ok:        make([]bool, partyCount),
	}
	// msgs init
	p.temp.signRound1Message1s = make([][]byte, partyCount)
	p.temp.signRound1Message2s = make([][]byte, partyCount)
	p.temp.signRound2Messages = make([][]byte, partyCount)
	p.temp.signRound3Messages = make([][]byte, partyCount)
	p.temp.send.signRound1Message2s = make([][]byte, partyCount)
	p.temp.send.signRound2Messages = make([][]byte, partyCount)

	// temp data init
	m, err := hex.DecodeString(msg)
	if err != nil {
		common.Logger.Errorf("hex decode msg err: %s", err.Error())
		return false
	}
	p.temp.m = new(big.Int).SetBytes(m)
	p.temp.kCiphertexts = make([]*big.Int, partyCount)

	SignParties[key] = p
	return true
}

func RemoveSignParty(key string) {
	delete(SignParties, key)
}

func NewRefreshSaveData(partyCount int) (saveData keygen.LocalRefreshSaveData) {
	saveData.PaillierPKs = make([]*paillier.PublicKey, partyCount)
	saveData.RingPedersenPKs = make([]*pailliera.PedPubKey, partyCount)
	return
}

func (p *LocalParty) resetOK() {
	for j := range p.ok {
		p.ok[j] = false
	}
}

func (p *LocalParty) PartyID() *tss.PartyID {
	return p.params.PartyID()
}

func (p *LocalParty) String() string {
	return fmt.Sprintf("id: %s, %s", p.PartyID(), p.BaseParty.String())
}

// get ssid from local params
func (round *LocalParty) getSSID() ([]byte, error) {
	ssidList := []*big.Int{round.params.EC().Params().P, round.params.EC().Params().N, round.params.EC().Params().Gx, round.params.EC().Params().Gy} // ec curve
	ssidList = append(ssidList, round.params.Parties().IDs().Keys()...)                                                                              // parties
	BigXjList, err := crypto.FlattenECPoints(round.keys.PubXj)
	if err != nil {
		return nil, round.WrapError(errors.New("read BigXj failed"), round.PartyID())
	}
	ssidList = append(ssidList, BigXjList...)                    // BigXj
	ssidList = append(ssidList, big.NewInt(int64(round.number))) // round number
	ssidList = append(ssidList, round.temp.ssidNonce)
	for _, pk := range round.keys.RingPedersenPKs {
		if pk == nil {
			return nil, errors.New("found nil pedersen pk")
		}
		ssidList = append(ssidList, pk.N)
		ssidList = append(ssidList, pk.S)
		ssidList = append(ssidList, pk.T)
	}
	ssid := common.SHA512_256i(ssidList...).Bytes()

	return ssid, nil
}
