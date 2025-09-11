package circuits

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
)

type TwoCommitCircuit struct {
	A, B, Out frontend.Variable `gnark:",public"`
}

func (c *TwoCommitCircuit) Define(api frontend.API) error {
	res := api.Mul(c.A, c.B)
	api.AssertIsEqual(res, c.Out)
	cmter, ok := api.(frontend.Committer)
	if !ok {
		return fmt.Errorf("api does not support commitment")
	}
	cmt1, err := cmter.Commit(res)
	if err != nil {
		return err
	}
	cmt2, err := cmter.Commit(cmt1)
	if err != nil {
		return err
	}
	api.AssertIsDifferent(cmt1, cmt2)
	return nil
}
