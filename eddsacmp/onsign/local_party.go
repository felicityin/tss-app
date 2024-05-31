package onsign

//#include <stdio.h>
//#include <stdlib.h>
//#include <string.h>
import "C"

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"

	"tss_sdk/common"
	pailliera "tss_sdk/crypto/alice/paillier"
	"tss_sdk/crypto/ckd"
	"tss_sdk/crypto/paillier"
	"tss_sdk/eddsacmp/keygen"
	"tss_sdk/tss"

	"github.com/ipfs/go-log"
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
	keyData string, // keygen.LocalPartySaveData, base64 string
	refreshPayload string, // refresh.Payload, hex string
	walletPath string,
) (result OnsignResult) {
	if err := log.SetLogLevel("tss-lib", "info"); err != nil {
		common.Logger.Errorf("set log level, err: %s", err.Error())
		result.Err = fmt.Sprintf("set log level, err: %s", err.Error())
		return
	}
	tss.SetCurve(tss.Edwards())

	uIds := make(tss.UnSortedPartyIDs, 0, partyCount)
	for i := 0; i < partyCount; i++ {
		pId, _ := new(big.Int).SetString(pIDs[i], 10)
		common.Logger.Infof("id: %d", pId)
		uIds = append(uIds, tss.NewPartyID(fmt.Sprintf("%d", i), fmt.Sprintf("m_%d", i), pId))
	}
	ids := tss.SortPartyIDs(uIds)
	p2pCtx := tss.NewPeerContext(ids)
	params := tss.NewParameters(tss.Edwards(), p2pCtx, ids[partyIndex], partyCount, partyCount)

	keyDataBytes, err := base64.StdEncoding.DecodeString(keyData)
	if err != nil {
		common.Logger.Errorf("base64 decode keygen data fail, err:%s", err.Error())
		result.Err = fmt.Sprintf("base64 decode keygen data fail, err:%s", err.Error())
		return
	}
	keys := &keygen.LocalPartySaveData{}
	if err := json.Unmarshal(keyDataBytes, keys); err != nil {
		common.Logger.Errorf("unmarshal keygen save data err: %s", err.Error())
		result.Err = fmt.Sprintf("unmarshal keygen save data err: %s", err.Error())
		return
	}

	common.Logger.Infof("wallet path: %s", walletPath)
	common.Logger.Infof("chaincode count: %d", len(keys.ChainCodes))
	common.Logger.Infof("keys.PubXj count: %d", len(keys.PubXj))
	parts := strings.Split(walletPath, "/")
	if len(parts) != 5 {
		common.Logger.Errorf("wallet path err: %s", walletPath)
		result.Err = fmt.Sprintf("wallet path err: %s", walletPath)
		return
	}

	// 推导子私钥分片
	chainCode := keys.ChainCodes[partyIndex].Bytes()
	deducePubKey := keys.EdDSAPub // 签名权限下发前后不变
	childPrivKey, _, err := ckd.DeriveEddsaChildPrivKey(
		keys.PrivXi, keys.PubXj[partyIndex], deducePubKey, chainCode, walletPath)
	if err != nil {
		common.Logger.Errorf("deriveChildPrivateKey err: %s", err.Error())
		result.Err = fmt.Sprintf("deriveChildPrivateKey err: %s", err.Error())
		return
	}
	keys.PrivXi = new(big.Int).SetBytes(childPrivKey[:]) // 替换

	// 推导所有子公钥分片
	partyLen := len(keys.PubXj)
	for i := 0; i < partyLen; i++ {
		childPubkey, err1 := ckd.DeriveEddsaChildPubKey(
			keys.PubXj[i], deducePubKey, keys.ChainCodes[i].Bytes(), walletPath,
		)
		if err1 != nil {
			common.Logger.Errorf("deriveChildPubKey err: %s", err.Error())
			result.Err = fmt.Sprintf("deriveChildPubKey err: %s", err.Error())
			return
		}
		keys.PubXj[i] = childPubkey // 替换
	}

	rfPayload, err := hex.DecodeString(refreshPayload)
	if err != nil {
		common.Logger.Errorf("hex decode refresh data fail, err:%s", err.Error())
		result.Err = fmt.Sprintf("hex decode refresh data fail, err:%s", err.Error())
		return
	}

	keys.LocalRefreshSaveData = NewRefreshSaveData(partyCount)
	j := 1376
	for i := 0; i < partyCount; i++ {
		keys.LocalRefreshSaveData.PaillierPKs[i] = &paillier.PublicKey{
			N: new(big.Int).SetBytes(rfPayload[j+33 : j+289]),
		}
		keys.LocalRefreshSaveData.RingPedersenPKs[i] = &pailliera.PedPubKey{
			N: new(big.Int).SetBytes(rfPayload[j+289 : j+417]),
			S: new(big.Int).SetBytes(rfPayload[j+417 : j+545]),
			T: new(big.Int).SetBytes(rfPayload[j+545 : j+673]),
		}
		j += 673
	}

	keyParty, err := keygen.BuildLocalSaveDataSubset(*keys, params.Parties().IDs())
	if err != nil {
		result.Err = err.Error()
		return
	}

	p := &LocalParty{
		BaseParty: new(tss.BaseParty),
		params:    params,
		keys:      keyParty,
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
		result.Err = fmt.Sprintf("hex decode msg err: %s", err.Error())
		return
	}
	p.temp.m = new(big.Int).SetBytes(m)
	p.temp.kCiphertexts = make([]*big.Int, partyCount)

	SignParties[key] = p
	result.Ok = true
	return
}

func RemoveSignParty(key string) bool {
	if _, ok := SignParties[key]; !ok {
		return false
	}
	delete(SignParties, key)
	return true
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
	// ssidList := []*big.Int{round.params.EC().Params().P, round.params.EC().Params().N, round.params.EC().Params().Gx, round.params.EC().Params().Gy} // ec curve
	// ssidList = append(ssidList, round.params.Parties().IDs().Keys()...)                                                                              // parties
	// BigXjList, err := crypto.FlattenECPoints(round.keys.PubXj)
	// if err != nil {
	// 	return nil, round.WrapError(errors.New("read BigXj failed"), round.PartyID())
	// }
	// ssidList = append(ssidList, BigXjList...)                    // BigXj
	// ssidList = append(ssidList, big.NewInt(int64(round.number))) // round number
	// ssidList = append(ssidList, round.temp.ssidNonce)
	// for _, pk := range round.keys.RingPedersenPKs {
	// 	if pk == nil {
	// 		return nil, errors.New("found nil pedersen pk")
	// 	}
	// 	ssidList = append(ssidList, pk.N)
	// 	ssidList = append(ssidList, pk.S)
	// 	ssidList = append(ssidList, pk.T)
	// }
	// ssid := common.SHA512_256i(ssidList...).Bytes()

	return []byte("eddsacmp-onsign"), nil
}
