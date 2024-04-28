// https://pkg.go.dev/github.com/consensys/gnark@v0.10.0/std/recursion/groth16

package recursive

import (
	"github.com/consensys/gnark/frontend"
)

// InnerCircuitNative is the definition of the inner circuit we want to
// recursively verify inside an outer circuit. The circuit proves the knowledge
// of a factorisation of a semiprime.
type InnerCircuitNative struct {
	P, Q frontend.Variable
	N    frontend.Variable `gnark:",public"`
}

func (c *InnerCircuitNative) Define(api frontend.API) error {
	// prove that P*Q == N
	res := api.Mul(c.P, c.Q)
	api.AssertIsEqual(res, c.N)
	// we must also enforce that P != 1 and Q != 1
	api.AssertIsDifferent(c.P, 1)
	api.AssertIsDifferent(c.Q, 1)
	return nil
}
