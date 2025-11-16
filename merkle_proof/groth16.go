package merkle_proof

import (
	"fmt"
	"math/big"
	"os"

	"github.com/consensys/gnark-crypto/accumulator/merkletree"
	fr_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/backend/groth16"
	groth16_bls12381 "github.com/consensys/gnark/backend/groth16/bls12-381"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	gnarktosnarkjs "github.com/mysteryon88/gnark-to-snarkjs"
)

func (g16 *G16) Prove(ScalarField *big.Int) error {

	var tree *merkletree.Tree

	switch {
	case ScalarField.Cmp(fr_bn254.Modulus()) == 0:
		tree = merkletree.New(hash.MIMC_BN254.New())

	case ScalarField.Cmp(fr_bls12381.Modulus()) == 0:
		tree = merkletree.New(hash.MIMC_BLS12_381.New())
	}

	leafIndex := uint64(34)
	err := tree.SetIndex(leafIndex)
	if err != nil {
		return err
	}

	// generate 1000 leaves
	for i := 1; i <= 1000; i++ {
		leafValue := big.NewInt(int64(i))
		leafData := make([]byte, 32)
		leafBytes := leafValue.Bytes()
		copy(leafData[32-len(leafBytes):], leafBytes)

		tree.Push(leafData)
	}

	merkleRoot, proofSet, proofIndex, numLeaves := tree.Prove()

	fmt.Println("proof index: ", proofIndex)
	fmt.Println("num leaves: ", numLeaves)
	fmt.Println("proof set length: ", len(proofSet))

	rootHashBigInt := new(big.Int).SetBytes(merkleRoot)
	g16.circuit.RootHash = rootHashBigInt
	g16.rootHash = rootHashBigInt // Store for export

	for i := 0; i < len(proofSet); i++ {
		proofBigInt := new(big.Int).SetBytes(proofSet[i])
		g16.circuit.Path[i] = proofBigInt
	}

	g16.circuit.Index = proofIndex

	err = g16.getWitness(ScalarField)
	if err != nil {
		return fmt.Errorf("failed to create witness: %w", err)
	}

	g16.proof, err = groth16.Prove(g16.r1cs, g16.pk, g16.witnessFull)
	if err != nil {
		return fmt.Errorf("failed to generate proof: %w", err)
	}

	if g16.proof == nil {
		return fmt.Errorf("proof is nil after generation")
	}

	return nil
}

func (g16 *G16) Export() error {
	if g16.proof == nil {
		return fmt.Errorf("proof is nil, cannot export")
	}

	var ProofPath, VKeyPath string

	switch g16.proof.(type) {
	case *groth16_bls12381.Proof:
		ProofPath, VKeyPath = ProofPathG16_BLS12381, VKeyPathG16_BLS12381

	case *groth16_bn254.Proof:
		ProofPath, VKeyPath = ProofPathG16_BN254, VKeyPathG16_BN254
	default:
		return fmt.Errorf("unsupported proof type: %T", g16.proof)
	}

	// Export the proof
	{

		proof_out, err := os.Create(ProofPath)
		if err != nil {
			return err
		}

		defer proof_out.Close()

		err = gnarktosnarkjs.ExportProof(g16.proof, []string{g16.rootHash.String()}, proof_out)
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

func (g16 *G16) Verify() error {
	if g16.proof == nil {
		return fmt.Errorf("proof is nil, cannot verify")
	}
	if g16.vk == nil {
		return fmt.Errorf("verification key is nil, cannot verify")
	}
	if g16.witnessPublic == nil {
		return fmt.Errorf("public witness is nil, cannot verify")
	}

	err := groth16.Verify(g16.proof, g16.vk, g16.witnessPublic)
	if err != nil {
		return fmt.Errorf("verification failed: %w", err)
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
