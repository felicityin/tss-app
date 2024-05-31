// Reference github.com/getamis/alice/crypto/homo/paillier/ringpedersenparameter.go

package paillier

import (
	"math/big"

	zkPaillier "tss_sdk/crypto/alice/zkproof/paillier"

	"tss_sdk/crypto/alice/utils"
)

type (
	PedPubKey struct {
		N *big.Int
		S *big.Int
		T *big.Int
	}

	PedPrivKey struct {
		PedPubKey
		LambdaN *big.Int
		Euler   *big.Int
	}
)

type PederssenParameter struct {
	p      *big.Int
	q      *big.Int
	eulern *big.Int
	lambda *big.Int

	PedersenOpenParameter *zkPaillier.PederssenOpenParameter
}

func (ped *PederssenParameter) Getlambda() *big.Int {
	return ped.lambda
}

func (ped *PederssenParameter) GetP() *big.Int {
	return ped.p
}

func (ped *PederssenParameter) GetQ() *big.Int {
	return ped.q
}

func (ped *PederssenParameter) GetEulerValue() *big.Int {
	return ped.eulern
}

// By paillier
func (paillier *Paillier) NewPedersenParameterByPaillier() (*PederssenParameter, error) {
	eulern, err := utils.EulerFunction([]*big.Int{paillier.privateKey.p, paillier.privateKey.q})
	n := paillier.publicKey.n
	if err != nil {
		return nil, err
	}
	lambda, err := utils.RandomInt(eulern)
	if err != nil {
		return nil, err
	}
	tau, err := utils.RandomInt(n)
	if err != nil {
		return nil, err
	}
	t := new(big.Int).Exp(tau, big2, n)
	s := new(big.Int).Exp(t, lambda, n)
	return &PederssenParameter{
		p:                     paillier.privateKey.p,
		q:                     paillier.privateKey.q,
		eulern:                eulern,
		lambda:                lambda,
		PedersenOpenParameter: zkPaillier.NewPedersenOpenParameter(n, s, t),
	}, nil
}

func NewPedersenOpenParameter(n, s, t *big.Int) (*zkPaillier.PederssenOpenParameter, error) {
	if !utils.IsRelativePrime(s, n) {
		return nil, ErrInvalidInput
	}
	if !utils.IsRelativePrime(t, n) {
		return nil, ErrInvalidInput
	}
	if n.BitLen() < safePubKeySize {
		return nil, ErrSmallPublicKeySize
	}
	return zkPaillier.NewPedersenOpenParameter(n, s, t), nil
}
