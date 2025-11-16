package merkle_proof

import (
	"gnark_example/utils"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/stretchr/testify/assert"
)

// go test ./merkle_proof -v -run TestMerkleProofBN254
func TestMerkleProofBN254(t *testing.T) {
	utils.CheckDirs([]string{"proofs", "keys"})
	g16 := G16{}

	g16.Compile(ecc.BN254.ScalarField())
	g16.Setup()
	g16.Prove(ecc.BN254.ScalarField())
	g16.Verify()
	err := g16.Export()
	assert.NoError(t, err)
}

// go test ./merkle_proof -v -run TestMerkleProofBLS12_381
func TestMerkleProofBLS12_381(t *testing.T) {
	utils.CheckDirs([]string{"proofs", "keys"})

	g16 := G16{}

	g16.Compile(ecc.BLS12_381.ScalarField())
	g16.Setup()
	g16.Prove(ecc.BLS12_381.ScalarField())
	g16.Verify()
	err := g16.Export()
	assert.NoError(t, err)
}
