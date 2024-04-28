// https://pkg.go.dev/github.com/consensys/gnark@v0.10.0/std/recursion/plonk

package plonk

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/recursion/plonk"
)

// OuterCircuit is the generic outer circuit which can verify PLONK proofs
// using field emulation or 2-chains of curves.
type OuterCircuit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	Proof        plonk.Proof[FR, G1El, G2El]
	VerifyingKey plonk.VerifyingKey[FR, G1El, G2El] `gnark:"-"` // constant verification key
	InnerWitness plonk.Witness[FR]                  `gnark:",public"`
}

func (c *OuterCircuit[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {
	verifier, err := plonk.NewVerifier[FR, G1El, G2El, GtEl](api)
	if err != nil {
		return fmt.Errorf("new verifier: %w", err)
	}
	err = verifier.AssertProof(c.VerifyingKey, c.Proof, c.InnerWitness)
	return err
}
