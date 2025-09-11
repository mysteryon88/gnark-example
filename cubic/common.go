package cubic

import (
	"gnark_example/circuits/cubic"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
)

// your circuit type
type CircuitInterface struct {
	cubic.Circuit
}

const (
	ProofPathG16_BN254 = "proofs/proof_bn254.json"
	VKeyPathG16_BN254  = "keys/verification_key_bn254.json"

	ProofPathG16_BLS12381 = "proofs/proof_bls12381.json"
	VKeyPathG16_BLS12381  = "keys/verification_key_bls12381.json"
)

type G16 struct {
	circuit CircuitInterface

	r1cs constraint.ConstraintSystem

	pk groth16.ProvingKey
	vk groth16.VerifyingKey

	witnessFull   witness.Witness
	witnessPublic witness.Witness
	proof         groth16.Proof
}
