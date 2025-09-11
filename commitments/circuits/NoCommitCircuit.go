package circuits

import "github.com/consensys/gnark/frontend"

type NoCommitCircuit struct {
	A, B, Out frontend.Variable `gnark:",public"`
}

func (c *NoCommitCircuit) Define(api frontend.API) error {
	res := api.Mul(c.A, c.B)
	api.AssertIsEqual(res, c.Out)
	return nil
}
