package cubic

import (
	"fmt"
	"gnark/utils/hashes"
	"math/big"
	"os"

	fr_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	groth16_bls12381 "github.com/consensys/gnark/backend/groth16/bls12-381"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

var hash string

func (g16 *G16) Export() error {

	var ProofPath, VKeyPath string

	switch g16.proof.(type) {
	case *groth16_bls12381.Proof:
		ProofPath, VKeyPath = ProofPathG16_BLS12381, VKeyPathG16_BLS12381

	case *groth16_bn254.Proof:
		ProofPath, VKeyPath = ProofPathG16_BN254, VKeyPathG16_BN254
	default:
		panic("not implemented")
	}

	// Export the proof
	{

		proof_out, err := os.Create(ProofPath)
		if err != nil {
			return err
		}

		defer proof_out.Close()

		err = g16.proof.ExportProof([]string{hash}, proof_out)
		if err != nil {
			return err
		}
	}

	// Export the verification key
	{
		out, err := os.Create(VKeyPath)
		if err != nil {
			return err
		}
		defer out.Close()
		err = g16.vk.ExportVerifyingKey(out)
		if err != nil {
			return err
		}
	}
	return nil
}

func (g16 *G16) Compile(ScalarField *big.Int) error {
	var err error
	g16.r1cs, err = frontend.Compile(ScalarField, r1cs.NewBuilder, &g16.circuit)
	if err != nil {
		return err
	}
	return nil
}

func (g16 *G16) Setup() error {
	var err error
	g16.pk, g16.vk, err = groth16.Setup(g16.r1cs)
	if err != nil {
		return err
	}
	return nil
}

func (g16 *G16) Prove(ScalarField *big.Int) error {
	var err error

	perImage := "500304"

	switch {
	case ScalarField.Cmp(fr_bn254.Modulus()) == 0:
		hash = hashes.MimcHash_BN254(perImage)

	case ScalarField.Cmp(fr_bls12381.Modulus()) == 0:
		hash = hashes.MimcHash_BLS12_381(perImage)

	default:
		return fmt.Errorf("unsupported scalar field modulus: %s", ScalarField.String())
	}

	// enter inputs
	g16.circuit.PreImage = perImage
	g16.circuit.Hash = hash

	g16.getWitness(ScalarField)

	g16.proof, err = groth16.Prove(g16.r1cs, g16.pk, g16.witnessFull)
	if err != nil {
		return err
	}

	return nil
}

func (g16 *G16) Verify() error {
	err := groth16.Verify(g16.proof, g16.vk, g16.witnessPublic)
	if err != nil {
		return err
	}
	return nil
}

func (g16 *G16) getWitness(ScalarField *big.Int) error {

	var err error

	g16.witnessFull, err = frontend.NewWitness(&g16.circuit, ScalarField)
	if err != nil {
		return err
	}

	g16.witnessPublic, err = frontend.NewWitness(&g16.circuit, ScalarField, frontend.PublicOnly())
	if err != nil {
		return err
	}

	return nil
}
