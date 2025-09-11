package groth16

import (
	"math/big"
	"os"

	"github.com/consensys/gnark/backend/groth16"
	groth16_bls12381 "github.com/consensys/gnark/backend/groth16/bls12-381"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	gnarktosnarkjs "github.com/mysteryon88/gnark-to-snarkjs"
)

func (g16 *G16_commit) Export() error {
	var ProofPath, VKeyPath string

	switch g16.proof.(type) {
	case *groth16_bls12381.Proof:
		ProofPath, VKeyPath = ProofPathG16_commit_BLS12381, VKeyPathG16_commit_BLS12381
	case *groth16_bn254.Proof:
		ProofPath, VKeyPath = ProofPathG16_commit_BN254, VKeyPathG16_commit_BN254
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

		err = gnarktosnarkjs.ExportProof(g16.proof, []string{"2", "3", "6"}, proof_out)
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
		err = gnarktosnarkjs.ExportVerifyingKey(g16.vk, out)
		if err != nil {
			return err
		}
	}
	return nil
}

func (g16 *G16_commit) Compile(ScalarField *big.Int) error {
	var err error
	g16.r1cs, err = frontend.Compile(ScalarField, r1cs.NewBuilder, &g16.circuit)
	if err != nil {
		return err
	}
	return nil
}

func (g16 *G16_commit) Setup() error {
	var err error
	g16.pk, g16.vk, err = groth16.Setup(g16.r1cs)
	if err != nil {
		return err
	}
	return nil
}

func (g16 *G16_commit) Prove(ScalarField *big.Int) error {
	var err error

	g16.circuit.A = 2
	g16.circuit.B = 3
	g16.circuit.Out = 6

	g16.getWitness(ScalarField)

	g16.proof, err = groth16.Prove(g16.r1cs, g16.pk, g16.witnessFull)
	if err != nil {
		return err
	}

	return nil
}

func (g16 *G16_commit) Verify() error {
	err := groth16.Verify(g16.proof, g16.vk, g16.witnessPublic)
	if err != nil {
		return err
	}
	return nil
}

func (g16 *G16_commit) getWitness(ScalarField *big.Int) error {
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
