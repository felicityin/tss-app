package message

import (
	"crypto/elliptic"
	"math/big"

	"google.golang.org/protobuf/proto"

	"tss_sdk/common"
	"tss_sdk/crypto"
	pailliera "tss_sdk/crypto/alice/paillier"
	paillierzkproof "tss_sdk/crypto/alice/zkproof/paillier"
	"tss_sdk/crypto/modproof"
	"tss_sdk/crypto/paillier"
	"tss_sdk/tss"
)

// ----- //

func NewKGRound1Message(from *tss.PartyID, hash []byte) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	content := &KGRound1Message{
		Commitment: hash,
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *KGRound1Message) ValidateBasic() bool {
	return m != nil && common.NonEmptyBytes(m.GetCommitment())
}

// ----- //

func NewKGRound2Message(
	from *tss.PartyID,
	ssid []byte,
	srid []byte,
	pubX *crypto.ECPoint,
	commitmentA *crypto.ECPoint,
	u []byte,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	content := &KGRound2Message{
		Ssid:        ssid,
		Srid:        srid,
		PublicXX:    pubX.X().Bytes(),
		PublicXY:    pubX.Y().Bytes(),
		CommitmentX: commitmentA.X().Bytes(),
		CommitmentY: commitmentA.Y().Bytes(),
		U:           u,
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *KGRound2Message) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.GetPublicXX()) &&
		common.NonEmptyBytes(m.GetPublicXY()) &&
		common.NonEmptyBytes(m.GetCommitmentX()) &&
		common.NonEmptyBytes(m.GetCommitmentY()) &&
		common.NonEmptyBytes(m.GetSrid()) &&
		common.NonEmptyBytes(m.GetSsid()) &&
		common.NonEmptyBytes(m.GetU())
}

func (m *KGRound2Message) UnmarshalPaillierPK() *paillier.PublicKey {
	return &paillier.PublicKey{N: new(big.Int).SetBytes(m.GetPaillierN())}
}

func (m *KGRound2Message) UnmarshalPedersenPK() *pailliera.PedPubKey {
	return &pailliera.PedPubKey{
		S: new(big.Int).SetBytes(m.GetPedersenS()),
		T: new(big.Int).SetBytes(m.GetPedersenT()),
	}
}

func (m *KGRound2Message) UnmarshalPubXj(ec elliptic.Curve) (*crypto.ECPoint, error) {
	publicX, err := crypto.NewECPoint(
		ec,
		new(big.Int).SetBytes(m.GetPublicXX()),
		new(big.Int).SetBytes(m.GetPublicXY()),
	)
	if err != nil {
		return nil, err
	}
	return publicX, nil
}

type CmpKeyGenerationPayload struct {
	// Schnorr ZKP
	CommitedA *crypto.ECPoint

	// Echo broadcast and random oracle data seed
	Ssid []byte
	Srid []byte
	U    []byte
}

func (m *KGRound2Message) UnmarshalPayload(ec elliptic.Curve) (*CmpKeyGenerationPayload, error) {
	commitedA, err := crypto.NewECPoint(
		ec,
		new(big.Int).SetBytes(m.GetCommitmentX()),
		new(big.Int).SetBytes(m.GetCommitmentY()),
	)
	if err != nil {
		return nil, err
	}

	return &CmpKeyGenerationPayload{
		CommitedA: commitedA,
		Ssid:      m.GetSsid(),
		Srid:      m.GetSrid(),
		U:         m.GetU(),
	}, nil
}

// ----- //

func NewKGRound3Message(
	from *tss.PartyID,
	schProof []byte,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	content := &KGRound3Message{
		SchProof: schProof,
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *KGRound3Message) ValidateBasic() bool {
	return m != nil && common.NonEmptyBytes(m.GetSchProof())
}

func (m *KGRound3Message) UnmarshalSchProof() *big.Int {
	return new(big.Int).SetBytes(m.GetSchProof())
}

func (m *KGRound3Message) UnmarshalModProof() (*modproof.ProofMod, error) {
	return modproof.NewProofFromBytes(m.GetModProof())
}

func (m *KGRound3Message) UnmarshalPrmProof() (*paillierzkproof.RingPederssenParameterMessage, error) {
	prmProof := &paillierzkproof.RingPederssenParameterMessage{}
	if err := proto.Unmarshal(m.GetPrmProof(), prmProof); err != nil {
		return nil, err
	}
	return prmProof, nil
}
