package systems

import (
	"gnark/circuits/mimc"

	"github.com/consensys/gnark-crypto/kzg"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
)

// your circuit type
type CircuitInterface struct {
	mimc.Circuit
}

const (
	WitnessFilePathG16       = "witness/witness_g16.wtns"
	WitnessPublicFilePathG16 = "witness/witnessPub_g16.wtns"
	VerificationKeyPathG16   = "keys/g16.vk"
	ProvingKeyPathG16        = "keys/g16.pk"
	ContractFilePathG16      = "contracts/contract_g16.sol"
	R1CSFilePathG16          = "constraints/g16.r1sc"

	WitnessFilePathPLONK       = "witness/witness_plonk.wtns"
	WitnessPublicFilePathPLONK = "witness/witnessPub_plonk.wtns"
	VerificationKeyPathPLONK   = "keys/plonk.vk"
	ProvingKeyPathPLONK        = "keys/plonk.pk"
	ContractFilePathPLONK      = "contracts/contract_plonk.sol"
	SCSFilePathPLONK           = "constraints/plonk.scs"
	SRSFilePathPLONK           = "constraints/plonk.srs"
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

type PLONK struct {
	circuit CircuitInterface

	ccs         constraint.ConstraintSystem
	srs         kzg.SRS
	srsLagrange kzg.SRS

	pk plonk.ProvingKey
	vk plonk.VerifyingKey

	witnessFull   witness.Witness
	witnessPublic witness.Witness
	proof         plonk.Proof
}
