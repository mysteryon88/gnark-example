package cubic

import (
	"gnark/utils"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
)

// go test ./cubic -v -run TestCubicBLS12_381
func TestCubicBLS12_381(t *testing.T) {
	utils.CheckDirs([]string{"proofs", "keys"})

	g16 := G16{}

	g16.Compile(ecc.BLS12_381.ScalarField())
	g16.Setup()
	g16.Prove(ecc.BLS12_381.ScalarField())
	g16.Verify()
	g16.Export(ecc.BLS12_381.ScalarField())
}

// go test ./cubic -v -run TestCubicBN254
func TestCubicBN254(t *testing.T) {
	utils.CheckDirs([]string{"proofs", "keys"})
	g16 := G16{}

	g16.Compile(ecc.BN254.ScalarField())
	g16.Setup()
	g16.Prove(ecc.BN254.ScalarField())
	g16.Verify()
	g16.Export(ecc.BN254.ScalarField())
}
