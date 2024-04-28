// https://pkg.go.dev/github.com/consensys/gnark@v0.10.0/std/recursion/plonk

package plonk

import (
	"math/big"

	"gnark/circuits/recursive"

	native_plonk "github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/recursion/plonk"
	"github.com/consensys/gnark/test/unsafekzg"
)

// computeInnerProof computes the proof for the inner circuit we want to verify
// recursively. In this example the PLONK keys are generated on the fly, but
// in practice should be genrated once and using MPC.
func computeInnerProof(field, outer *big.Int) (constraint.ConstraintSystem, native_plonk.VerifyingKey, witness.Witness, native_plonk.Proof) {
	innerCcs, err := frontend.Compile(field, scs.NewBuilder, &recursive.InnerCircuitNative{})
	if err != nil {
		panic(err)
	}
	// NB! UNSAFE! Use MPC.
	srs, srsLagrange, err := unsafekzg.NewSRS(innerCcs)
	if err != nil {
		panic(err)
	}

	innerPK, innerVK, err := native_plonk.Setup(innerCcs, srs, srsLagrange)
	if err != nil {
		panic(err)
	}

	// inner proof
	innerAssignment := &recursive.InnerCircuitNative{
		P: 3,
		Q: 5,
		N: 15,
	}
	innerWitness, err := frontend.NewWitness(innerAssignment, field)
	if err != nil {
		panic(err)
	}
	innerProof, err := native_plonk.Prove(innerCcs, innerPK, innerWitness, plonk.GetNativeProverOptions(outer, field))
	if err != nil {
		panic(err)
	}
	innerPubWitness, err := innerWitness.Public()
	if err != nil {
		panic(err)
	}
	err = native_plonk.Verify(innerProof, innerVK, innerPubWitness, plonk.GetNativeVerifierOptions(outer, field))
	if err != nil {
		panic(err)
	}
	return innerCcs, innerVK, innerPubWitness, innerProof
}
