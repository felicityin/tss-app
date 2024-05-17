package crypto

import (
	"encoding/hex"
	"math/big"
	"testing"

	s256k1 "github.com/btcsuite/btcd/btcec"
	edwards "github.com/decred/dcrd/dcrec/edwards/v2"
	"github.com/stretchr/testify/assert"
)

func TestAjustValue(t *testing.T) {
	oldPrivkey1, _ := hex.DecodeString("ae1e5bf5f3d6bf58b5c222088671fcbe78b437e28fae944c793897b26091f241")
	oldPrivkey2, _ := hex.DecodeString("ae1e5bf5f3d6bf58b5c222088671fcbe78b437e28fae944c793897b26091f242")
	oldPrivkey3, _ := hex.DecodeString("ae1e5bf5f3d6bf58b5c222088671fcbe78b437e28fae944c793897b26091f243")

	oldPrivkeyInt1 := new(big.Int).SetBytes(oldPrivkey1)
	oldPrivkeyInt2 := new(big.Int).SetBytes(oldPrivkey2)
	oldPrivkeyInt3 := new(big.Int).SetBytes(oldPrivkey3)

	newPrivkey1, _ := hex.DecodeString("be1e5bf5f3d6bf58b5c222088671fcbe78b437e28fae944c793897b26091f244")
	newPrivkeyInt1 := new(big.Int).Mod(new(big.Int).SetBytes(newPrivkey1), s256k1.S256().Params().N)

	adjustValueSum := new(big.Int).Sub(oldPrivkeyInt1, newPrivkeyInt1)
	adjustValueSum = adjustValueSum.Mod(adjustValueSum, s256k1.S256().Params().N)

	adjustSlice2, _ := hex.DecodeString("ce1e5bf5f3d6bf58b5c222088671fcbe78b437e28fae944c793897b26091f245")
	adjustSliceInt2 := new(big.Int).Mod(new(big.Int).SetBytes(adjustSlice2), s256k1.S256().Params().N)

	adjustSliceInt3 := new(big.Int).Sub(adjustValueSum, adjustSliceInt2)
	adjustSliceInt3 = adjustSliceInt3.Mod(adjustSliceInt3, s256k1.S256().Params().N)

	newPrivkeyInt2 := new(big.Int).Add(oldPrivkeyInt2, adjustSliceInt2)
	newPrivkeyInt2 = newPrivkeyInt2.Mod(newPrivkeyInt2, s256k1.S256().Params().N)

	newPrivkeyInt3 := new(big.Int).Add(oldPrivkeyInt3, adjustSliceInt3)
	newPrivkeyInt3 = newPrivkeyInt3.Mod(newPrivkeyInt3, s256k1.S256().Params().N)

	oldPrivKey := oldPrivkeyInt1
	oldPrivKey = oldPrivKey.Add(oldPrivKey, oldPrivkeyInt2)
	oldPrivKey = oldPrivKey.Mod(oldPrivKey, s256k1.S256().Params().N)
	oldPrivKey = oldPrivKey.Add(oldPrivKey, oldPrivkeyInt3)
	oldPrivKey = oldPrivKey.Mod(oldPrivKey, s256k1.S256().Params().N)

	newPrivKey := newPrivkeyInt1
	newPrivKey = newPrivKey.Add(newPrivKey, newPrivkeyInt2)
	newPrivKey = newPrivKey.Mod(newPrivKey, s256k1.S256().Params().N)
	newPrivKey = newPrivKey.Add(newPrivKey, newPrivkeyInt3)
	newPrivKey = newPrivKey.Mod(newPrivKey, s256k1.S256().Params().N)

	assert.Equal(t, oldPrivKey, newPrivKey)
}

func TestEddsaAjustValue(t *testing.T) {
	oldPrivkey1, _ := hex.DecodeString("ae1e5bf5f3d6bf58b5c222088671fcbe78b437e28fae944c793897b26091f241")
	oldPrivkey2, _ := hex.DecodeString("ae1e5bf5f3d6bf58b5c222088671fcbe78b437e28fae944c793897b26091f242")
	oldPrivkey3, _ := hex.DecodeString("ae1e5bf5f3d6bf58b5c222088671fcbe78b437e28fae944c793897b26091f243")

	oldPrivkeyInt1 := new(big.Int).SetBytes(oldPrivkey1)
	oldPrivkeyInt2 := new(big.Int).SetBytes(oldPrivkey2)
	oldPrivkeyInt3 := new(big.Int).SetBytes(oldPrivkey3)

	newPrivkey1, _ := hex.DecodeString("be1e5bf5f3d6bf58b5c222088671fcbe78b437e28fae944c793897b26091f244")
	newPrivkeyInt1 := new(big.Int).Mod(new(big.Int).SetBytes(newPrivkey1), s256k1.S256().Params().N)

	adjustValueSum := new(big.Int).Sub(oldPrivkeyInt1, newPrivkeyInt1)
	adjustValueSum = adjustValueSum.Mod(adjustValueSum, edwards.Edwards().Params().N)

	adjustSlice2, _ := hex.DecodeString("ce1e5bf5f3d6bf58b5c222088671fcbe78b437e28fae944c793897b26091f245")
	adjustSliceInt2 := new(big.Int).Mod(new(big.Int).SetBytes(adjustSlice2), edwards.Edwards().Params().N)

	adjustSliceInt3 := new(big.Int).Sub(adjustValueSum, adjustSliceInt2)
	adjustSliceInt3 = adjustSliceInt3.Mod(adjustSliceInt3, edwards.Edwards().Params().N)

	newPrivkeyInt2 := new(big.Int).Add(oldPrivkeyInt2, adjustSliceInt2)
	newPrivkeyInt2 = newPrivkeyInt2.Mod(newPrivkeyInt2, edwards.Edwards().Params().N)

	newPrivkeyInt3 := new(big.Int).Add(oldPrivkeyInt3, adjustSliceInt3)
	newPrivkeyInt3 = newPrivkeyInt3.Mod(newPrivkeyInt3, edwards.Edwards().Params().N)

	oldPrivKey := oldPrivkeyInt1
	oldPrivKey = oldPrivKey.Add(oldPrivKey, oldPrivkeyInt2)
	oldPrivKey = oldPrivKey.Mod(oldPrivKey, edwards.Edwards().Params().N)
	oldPrivKey = oldPrivKey.Add(oldPrivKey, oldPrivkeyInt3)
	oldPrivKey = oldPrivKey.Mod(oldPrivKey, edwards.Edwards().Params().N)

	newPrivKey := newPrivkeyInt1
	newPrivKey = newPrivKey.Add(newPrivKey, newPrivkeyInt2)
	newPrivKey = newPrivKey.Mod(newPrivKey, edwards.Edwards().Params().N)
	newPrivKey = newPrivKey.Add(newPrivKey, newPrivkeyInt3)
	newPrivKey = newPrivKey.Mod(newPrivKey, edwards.Edwards().Params().N)

	assert.Equal(t, oldPrivKey, newPrivKey)
}
