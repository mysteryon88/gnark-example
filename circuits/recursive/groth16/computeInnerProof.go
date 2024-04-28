// https://pkg.go.dev/github.com/consensys/gnark@v0.10.0/std/recursion/groth16

package groth16

import (
	"math/big"

	"gnark/circuits/recursive"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
)

// computeInnerProof computes the proof for the inner circuit we want to verify
// recursively. In this example the Groth16 keys are generated on the fly, but
// in practice should be genrated once and using MPC.
func computeInnerProof(field, outer *big.Int) (constraint.ConstraintSystem, groth16.VerifyingKey, witness.Witness, groth16.Proof) {
	innerCcs, err := frontend.Compile(field, r1cs.NewBuilder, &recursive.InnerCircuitNative{})
	if err != nil {
		panic(err)
	}
	// NB! UNSAFE! Use MPC.
	innerPK, innerVK, err := groth16.Setup(innerCcs)
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
	innerProof, err := groth16.Prove(innerCcs, innerPK, innerWitness, stdgroth16.GetNativeProverOptions(outer, field))
	if err != nil {
		panic(err)
	}
	innerPubWitness, err := innerWitness.Public()
	if err != nil {
		panic(err)
	}
	err = groth16.Verify(innerProof, innerVK, innerPubWitness, stdgroth16.GetNativeVerifierOptions(outer, field))
	if err != nil {
		panic(err)
	}
	return innerCcs, innerVK, innerPubWitness, innerProof
}
