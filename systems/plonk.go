package systems

import (
	"gnark/circuits/mimc"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test"
)

func GeneratePlonk() error {
	var circuit mimc.Circuit

	scs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &circuit)
	if err != nil {
		return err
	}

	srs, err := test.NewKZGSRS(scs)
	if err != nil {
		return err
	}

	pk, vk, err := plonk.Setup(scs, srs)
	if err != nil {
		return err
	}
	{
		f, err := os.Create("keys/mimc.plonk.vk")
		if err != nil {
			return err
		}
		_, err = vk.WriteTo(f)
		if err != nil {
			return err
		}
	}
	{
		f, err := os.Create("keys/mimc.plonk.pk")
		if err != nil {
			return err
		}
		_, err = pk.WriteTo(f)
		if err != nil {
			return err
		}
	}

	{
		f, err := os.Create("contracts/contract_plonk.sol")
		if err != nil {
			return err
		}
		err = vk.ExportSolidity(f)
		if err != nil {
			return err
		}
	}
	return nil
}
