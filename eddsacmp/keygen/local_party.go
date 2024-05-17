package keygen

//#include <stdio.h>
//#include <stdlib.h>
//#include <string.h>
import "C"

import (
	"encoding/hex"
	"fmt"
	"math/big"

	"tss/common"
	"tss/crypto"
	m "tss/eddsacmp/keygen/message"
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

		temp   LocalTempData
		save   LocalPartySaveData
		number int
		ok     []bool
	}

	localMessageStore struct {
		kgRound1Messages [][]byte // msg.WireBytes()
		kgRound2Messages [][]byte
		kgRound3Messages [][]byte
	}

	LocalTempData struct {
		localMessageStore

		// temp data (thrown away after keygen)

		// ZKP Schnorr
		tau       *big.Int
		commitedA *crypto.ECPoint

		// Echo broadcast and random oracle data seed
		srid []byte
		u    []byte

		payload []*m.CmpKeyGenerationPayload

		ssid      []byte
		ssidNonce *big.Int

		srids [][]byte
		V     [][]byte
	}
)

var Parties = map[string]*LocalParty{}

// Exported, used in `tss` client
func NewLocalParty(
	key string,
	partyIndex int,
	partyCount int,
	pIDs []string,
	rootPrivKey string,
) bool {
	uIds := make(tss.UnSortedPartyIDs, 0, partyCount)
	for i := 0; i < partyCount; i++ {
		pId, _ := new(big.Int).SetString(pIDs[i], 10)
		uIds = append(uIds, tss.NewPartyID(fmt.Sprintf("%d", i), fmt.Sprintf("m_%d", i), pId))
	}
	ids := tss.SortPartyIDs(uIds)

	p2pCtx := tss.NewPeerContext(ids)
	params := tss.NewParameters(tss.Edwards(), p2pCtx, ids[partyIndex], partyCount, partyCount)
	data := NewLocalPartySaveData(partyCount)

	privkey, err := hex.DecodeString(rootPrivKey)
	if err != nil {
		return false
	}
	data.PrivXi = new(big.Int).SetBytes(privkey)

	p := &LocalParty{
		BaseParty: new(tss.BaseParty),
		params:    params,
		temp:      LocalTempData{},
		save:      data,
		ok:        make([]bool, partyCount),
	}

	// msgs init
	p.temp.kgRound1Messages = make([][]byte, partyCount)
	p.temp.kgRound2Messages = make([][]byte, partyCount)
	p.temp.kgRound3Messages = make([][]byte, partyCount)

	// temp data init
	p.temp.payload = make([]*m.CmpKeyGenerationPayload, partyCount)
	p.temp.srids = make([][]byte, partyCount)
	p.temp.V = make([][]byte, partyCount)

	Parties[key] = p
	return true
}

func RemoveParty(key string) {
	delete(Parties, key)
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
func (p *LocalParty) getSSID() ([]byte, error) {
	ssidList := []*big.Int{p.params.EC().Params().P, p.params.EC().Params().N, p.params.EC().Params().Gx, p.params.EC().Params().Gy} // ec curve
	ssidList = append(ssidList, p.params.Parties().IDs().Keys()...)
	ssidList = append(ssidList, big.NewInt(int64(p.number))) // round number
	ssidList = append(ssidList, p.temp.ssidNonce)
	ssid := common.SHA512_256i(ssidList...).Bytes()

	return ssid, nil
}
