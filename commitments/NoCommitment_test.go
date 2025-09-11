package commits

import (
	"gnark_example/commitments/groth16"
	"gnark_example/utils"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/stretchr/testify/assert"
)

// go test ./commitments -v -run TestNoCommitment_BN254
func TestNoCommitment_BN254(t *testing.T) {
	utils.CheckDirs([]string{"proofs", "keys"})

	g16 := groth16.G16_no_commit{}

	g16.Compile(ecc.BN254.ScalarField())
	g16.Setup()
	g16.Prove(ecc.BN254.ScalarField())
	g16.Verify()
	err := g16.Export()
	assert.NoError(t, err)
}
func TestNoCommitment_BLS12381(t *testing.T) {
	utils.CheckDirs([]string{"proofs", "keys"})

	g16 := groth16.G16_no_commit{}

	g16.Compile(ecc.BLS12_381.ScalarField())
	g16.Setup()
	g16.Prove(ecc.BLS12_381.ScalarField())
	g16.Verify()
	err := g16.Export()
	assert.NoError(t, err)
}
