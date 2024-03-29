package mimc

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"
)

func TestPreimage(t *testing.T) {
	assert := test.NewAssert(t)

	var mimcCircuit Circuit

	assert.ProverFailed(&mimcCircuit, &Circuit{
		Hash:     42,
		PreImage: 42,
	})

	assert.ProverSucceeded(&mimcCircuit, &Circuit{
		PreImage: "16130099170765464552823636852555369511329944820189892919423002775646948828469",
		Hash:     "12886436712380113721405259596386800092738845035233065858332878701083870690753",
	}, test.WithCurves(ecc.BN254))

	assert.ProverSucceeded(&mimcCircuit, &Circuit{
		PreImage: "20528568611862521940634556288214005375381336839062841310757054581435473848735",
		Hash:     "2098347828211243903322576363299668518464195203336068935409712310067544070766",
	}, test.WithCurves(ecc.BN254))

}
