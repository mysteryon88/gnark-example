package systems

import (
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test"
)

func (plonk *PLONK) Compile() error {
	var err error
	plonk.scs, err = frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &plonk.circuit)
	if err != nil {
		return err
	}

	plonk.srs, err = test.NewKZGSRS(plonk.scs)
	if err != nil {
		return err
	}

	plonk.SaveSCS()

	return nil
}

func (pl *PLONK) Setup() error {
	var err error
	pl.pk, pl.vk, err = plonk.Setup(pl.scs, pl.srs)
	if err != nil {
		return err
	}
	{
		file, err := os.Create(VerificationKeyPathPLONK)
		if err != nil {
			return err
		}
		_, err = pl.vk.WriteTo(file)
		if err != nil {
			return err
		}
		defer file.Close()
	}
	{
		file, err := os.Create(ProvingKeyPathPLONK)
		if err != nil {
			return err
		}
		_, err = pl.pk.WriteTo(file)
		if err != nil {
			return err
		}
		defer file.Close()
	}
	pl.ExportSolidity()

	return nil
}

func (plonk *PLONK) ExportSolidity() error {
	file, err := os.Create(ContractFilePathPLONK)
	if err != nil {
		return err
	}
	defer file.Close()

	err = plonk.vk.ExportSolidity(file)
	if err != nil {
		return err
	}
	return nil
}

func (plonk *PLONK) SaveSCS() error {
	file, err := os.Create(SCSFilePathPLONK)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = plonk.scs.WriteTo(file)
	if err != nil {
		return err
	}
	return nil
}

func (plonk *PLONK) SaveSRS() error {
	file, err := os.Create(SRSFilePathPLONK)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = plonk.srs.WriteTo(file)
	if err != nil {
		return err
	}
	return nil
}
