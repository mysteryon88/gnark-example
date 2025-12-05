package eddsa

import (
	"gnark_example/circuits/eddsa"

	twistededwards "github.com/consensys/gnark-crypto/ecc/bls12-381/twistededwards/eddsa"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
)

// your circuit type
type CircuitInterface struct {
	eddsa.EddsaCircuit
}

const (
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

	publicKeyStruct twistededwards.PublicKey // Store original PublicKey structure for export
	publicKey       []byte                   // Store PublicKey as []byte for export
	signature       []byte                   // Store Signature as []byte for export
	message         []byte                   // Store Message as []byte for export
}
