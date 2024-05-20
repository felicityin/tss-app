package onsign

import (
	"math/big"
)

type (
	LocalSecrets struct {
		// secret fields (not shared, but stored locally)
		ShareID *big.Int //
	}

	LocalRefreshParams struct {
		Payload []uint8 //64  + 32 + 5*32*8 +（33 + 32*8 + 32*4*3）* partyCount
	}

	// Everything in RefreshLocalPartySaveData is saved locally to user's HD when done
	RefreshLocalPartySaveData struct {
		//LocalPreParams
		LocalSecrets

		LocalRefreshParams

		// original indexes (ki in signing preparation phase)
		Ks []*big.Int

		// used for test assertions (may be discarded)
		SumN []uint8
	}
)
