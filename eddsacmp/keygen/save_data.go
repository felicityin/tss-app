package keygen

import (
	"encoding/hex"
	"math/big"

	"tss/crypto"
	pailliera "tss/crypto/alice/paillier"
	"tss/crypto/paillier"
	"tss/tss"
)

type (
	LocalKeygenSecrets struct {
		PrivXi, ShareID *big.Int // xi, kj
		ChainCodes      []*big.Int
	}

	LocalKeygenSavaData struct {
		LocalKeygenSecrets

		// original indexes (ki in signing preparation phase)
		Ks []*big.Int

		// public keys (Xj = uj*G for each Pj)
		PubXj []*crypto.ECPoint // Xj

		// used for assertions and derive child
		EdDSAPub *crypto.ECPoint // y
	}

	LocalRefreshSaveData struct {
		PaillierPKs     []*paillier.PublicKey
		RingPedersenPKs []*pailliera.PedPubKey
	}

	// Everything in LocalPartySaveData is saved locally to user's HD when done
	LocalPartySaveData struct {
		LocalKeygenSavaData
		LocalRefreshSaveData
	}
)

func NewLocalPartySaveData(partyCount int) (saveData LocalPartySaveData) {
	saveData.Ks = make([]*big.Int, partyCount)
	saveData.PubXj = make([]*crypto.ECPoint, partyCount)
	saveData.PaillierPKs = make([]*paillier.PublicKey, partyCount)
	saveData.RingPedersenPKs = make([]*pailliera.PedPubKey, partyCount)
	return
}

func NewRefreshSaveData(partyCount int) (saveData LocalRefreshSaveData) {
	saveData.PaillierPKs = make([]*paillier.PublicKey, partyCount)
	saveData.RingPedersenPKs = make([]*pailliera.PedPubKey, partyCount)
	return
}

// BuildLocalSaveDataSubset re-creates the LocalPartySaveData to contain data for only the list of signing parties.
func BuildLocalSaveDataSubset(sourceData LocalPartySaveData, sortedIDs tss.SortedPartyIDs) LocalPartySaveData {
	keysToIndices := make(map[string]int, len(sourceData.Ks))
	for j, kj := range sourceData.Ks {
		keysToIndices[hex.EncodeToString(kj.Bytes())] = j
	}
	newData := NewLocalPartySaveData(sortedIDs.Len())
	newData.LocalKeygenSavaData = sourceData.LocalKeygenSavaData
	newData.EdDSAPub = sourceData.EdDSAPub
	for j, id := range sortedIDs {
		savedIdx, ok := keysToIndices[hex.EncodeToString(id.Key)]
		if !ok {
			panic("BuildLocalSaveDataSubset: unable to find a signer party in the local save data")
		}
		newData.Ks[j] = sourceData.Ks[savedIdx]
		newData.PubXj[j] = sourceData.PubXj[savedIdx]
		newData.PaillierPKs[j] = sourceData.PaillierPKs[savedIdx]
		newData.RingPedersenPKs[j] = sourceData.RingPedersenPKs[savedIdx]
	}
	return newData
}
