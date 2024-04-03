// Copyright 2020 ConsenSys AG

package exponentiate

import (
	"testing"

	"github.com/consensys/gnark/test"
)

func TestExponentiateGroth16(t *testing.T) {

	assert := test.NewAssert(t)

	var expCircuit Circuit

	assert.ProverFailed(&expCircuit, &Circuit{
		X: 2,
		E: 12,
		Y: 4095,
	})

	assert.ProverSucceeded(&expCircuit, &Circuit{
		X: 2,
		E: 12,
		Y: 4096,
	})

}
