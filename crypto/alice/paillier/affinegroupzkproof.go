package paillier

import (
	"math/big"
	"tss/crypto/alice/utils"

	"github.com/golang/protobuf/proto"
)

func GetE(groupOrder *big.Int, msgs ...proto.Message) (*big.Int, []byte, error) {
	for j := 0; j < maxRetry; j++ {
		salt, err := utils.GenRandomBytes(128)
		if err != nil {
			return nil, nil, err
		}
		seedMsg, err := utils.HashProtos(salt, msgs...)
		if err != nil {
			return nil, nil, err
		}

		// Assume that the length of yi is 32 byte
		// e should belongs in [-q, q]
		e := utils.RandomAbsoluteRangeIntBySeed(salt, seedMsg, groupOrder)
		absoluteE := new(big.Int).Abs(e)
		if absoluteE.Cmp(groupOrder) <= 0 {
			return e, salt, nil
		}
	}
	return nil, nil, ErrExceedMaxRetry
}
