package groth16

import (
	"gnark_example/commitments/circuits"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
)

const (
	// G16_no_commit
	ProofPathG16_no_commit_BN254    = "proofs/proof_no_commit_bn254.json"
	VKeyPathG16_no_commit_BN254     = "keys/verification_key_no_commit_bn254.json"
	ProofPathG16_no_commit_BLS12381 = "proofs/proof_no_commit_bls12381.json"
	VKeyPathG16_no_commit_BLS12381  = "keys/verification_key_no_commit_bls12381.json"

	// G16_commit
	ProofPathG16_commit_BN254    = "proofs/proof_commit_bn254.json"
	VKeyPathG16_commit_BN254     = "keys/verification_key_commit_bn254.json"
	ProofPathG16_commit_BLS12381 = "proofs/proof_commit_bls12381.json"
	VKeyPathG16_commit_BLS12381  = "keys/verification_key_commit_bls12381.json"

	// G16_two_commit
	ProofPathG16_two_commit_BN254    = "proofs/proof_two_commit_bn254.json"
	VKeyPathG16_two_commit_BN254     = "keys/verification_key_two_commit_bn254.json"
	ProofPathG16_two_commit_BLS12381 = "proofs/proof_two_commit_bls12381.json"
	VKeyPathG16_two_commit_BLS12381  = "keys/verification_key_two_commit_bls12381.json"
)

type G16_no_commit struct {
	circuit circuits.NoCommitCircuit

	r1cs constraint.ConstraintSystem

	pk groth16.ProvingKey
	vk groth16.VerifyingKey

	witnessFull   witness.Witness
	witnessPublic witness.Witness
	proof         groth16.Proof
}

type G16_commit struct {
	circuit circuits.CommitCircuit

	r1cs constraint.ConstraintSystem

	pk groth16.ProvingKey
	vk groth16.VerifyingKey

	witnessFull   witness.Witness
	witnessPublic witness.Witness
	proof         groth16.Proof
}

type G16_two_commit struct {
	circuit circuits.TwoCommitCircuit

	r1cs constraint.ConstraintSystem

	pk groth16.ProvingKey
	vk groth16.VerifyingKey

	witnessFull   witness.Witness
	witnessPublic witness.Witness
	proof         groth16.Proof
}
