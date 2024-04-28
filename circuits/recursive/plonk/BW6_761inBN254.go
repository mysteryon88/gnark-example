// https://pkg.go.dev/github.com/consensys/gnark@v0.10.0/std/recursion/plonk

package plonk

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	native_plonk "github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bw6761"
	"github.com/consensys/gnark/std/recursion/plonk"
	"github.com/consensys/gnark/test/unsafekzg"
)

// Example of verifying recursively BW6-761 PLONK proof in BN254 PLONK circuit using field emulation

func BW6_761inBN254() {
	// compute the proof which we want to verify recursively
	innerCcs, innerVK, innerWitness, innerProof := computeInnerProof(ecc.BW6_761.ScalarField(), ecc.BN254.ScalarField())

	// initialize the witness elements
	circuitVk, err := plonk.ValueOfVerifyingKey[sw_bw6761.ScalarField, sw_bw6761.G1Affine, sw_bw6761.G2Affine](innerVK)
	if err != nil {
		panic(err)
	}
	circuitWitness, err := plonk.ValueOfWitness[sw_bw6761.ScalarField](innerWitness)
	if err != nil {
		panic(err)
	}
	circuitProof, err := plonk.ValueOfProof[sw_bw6761.ScalarField, sw_bw6761.G1Affine, sw_bw6761.G2Affine](innerProof)
	if err != nil {
		panic(err)
	}

	outerCircuit := &OuterCircuit[sw_bw6761.ScalarField, sw_bw6761.G1Affine, sw_bw6761.G2Affine, sw_bw6761.GTEl]{
		InnerWitness: plonk.PlaceholderWitness[sw_bw6761.ScalarField](innerCcs),
		Proof:        plonk.PlaceholderProof[sw_bw6761.ScalarField, sw_bw6761.G1Affine, sw_bw6761.G2Affine](innerCcs),
		VerifyingKey: circuitVk,
	}
	outerAssignment := &OuterCircuit[sw_bw6761.ScalarField, sw_bw6761.G1Affine, sw_bw6761.G2Affine, sw_bw6761.GTEl]{
		InnerWitness: circuitWitness,
		Proof:        circuitProof,
	}
	// compile the outer circuit
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, outerCircuit)
	if err != nil {
		panic("compile failed: " + err.Error())
	}

	// NB! UNSAFE! Use MPC.
	srs, srsLagrange, err := unsafekzg.NewSRS(ccs)
	if err != nil {
		panic(err)
	}

	// create PLONK setup. NB! UNSAFE
	pk, vk, err := native_plonk.Setup(ccs, srs, srsLagrange) // UNSAFE! Use MPC
	if err != nil {
		panic("setup failed: " + err.Error())
	}

	// create prover witness from the assignment
	secretWitness, err := frontend.NewWitness(outerAssignment, ecc.BN254.ScalarField())
	if err != nil {
		panic("secret witness failed: " + err.Error())
	}

	// create public witness from the assignment
	publicWitness, err := secretWitness.Public()
	if err != nil {
		panic("public witness failed: " + err.Error())
	}

	// construct the PLONK proof of verifying PLONK proof in-circuit
	outerProof, err := native_plonk.Prove(ccs, pk, secretWitness)
	if err != nil {
		panic("proving failed: " + err.Error())
	}

	// verify the PLONK proof
	err = native_plonk.Verify(outerProof, vk, publicWitness)
	if err != nil {
		panic("circuit verification failed: " + err.Error())
	}
	fmt.Println("done")
}
