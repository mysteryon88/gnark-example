package merkle_proof

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/accumulator/merkle"
	"github.com/consensys/gnark/std/hash/mimc"
)

type MerkleCircuit struct {
	RootHash frontend.Variable `gnark:",public"`
	Path     [11]frontend.Variable
	Index    frontend.Variable
}

func (circuit *MerkleCircuit) Define(api frontend.API) error {
	hFunc, _ := mimc.NewMiMC(api)

	proof := merkle.MerkleProof{
		RootHash: circuit.RootHash,
		Path:     circuit.Path[:], // Path contains 11 elements (with the leaf)
	}

	proof.VerifyProof(api, &hFunc, circuit.Index)

	return nil
}
