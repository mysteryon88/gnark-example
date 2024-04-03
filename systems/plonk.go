package systems

import (
	"crypto/rand"
	"fmt"
	"gnark/utils"
	"gnark/utils/hashes"
	"math/big"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test"
)

func (pl *PLONK) Prove() error {
	var err error

	// Create a limit: 2^254
	limit := new(big.Int).Exp(big.NewInt(2), big.NewInt(254), nil)
	// Generate a random number in the range [0, 2^254)
	randNum, _ := rand.Int(rand.Reader, limit)
	perImage := randNum.String()
	hash := hashes.MimcHash_BN254(perImage)

	// enter inputs
	pl.circuit.PreImage = perImage
	pl.circuit.Hash = hash

	pl.getWitness()

	pl.proof, err = plonk.Prove(pl.ccs, pl.pk, pl.witnessFull)
	if err != nil {
		return err
	}

	// public inputs
	// utils.GetCalldataG16(pl.proof, []string{hash})
	return nil
}

func (pl *PLONK) getWitness() error {

	var err error

	pl.witnessFull, err = frontend.NewWitness(&pl.circuit, ecc.BN254.ScalarField())
	if err != nil {
		return err
	}

	err = utils.SaveWitness(pl.witnessFull, WitnessFilePathPLONK)
	if err != nil {
		return err
	}

	pl.witnessPublic, err = frontend.NewWitness(&pl.circuit, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return err
	}

	err = utils.SaveWitness(pl.witnessPublic, WitnessPublicFilePathPLONK)
	if err != nil {
		return err
	}

	return nil
}

func (pl *PLONK) Verify() error {
	err := plonk.Verify(pl.proof, pl.vk, pl.witnessPublic)
	if err != nil {
		return fmt.Errorf("Verify error: %w", err)
	}
	return nil
}

func (pl *PLONK) Compile() error {
	var err error
	pl.ccs, err = frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &pl.circuit)
	if err != nil {
		return err
	}

	pl.srs, err = test.NewKZGSRS(pl.ccs)
	if err != nil {
		return err
	}

	pl.SaveSCS()

	return nil
}

func (pl *PLONK) Setup() error {
	var err error
	pl.pk, pl.vk, err = plonk.Setup(pl.ccs, pl.srs)
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

func (pl *PLONK) ExportSolidity() error {
	file, err := os.Create(ContractFilePathPLONK)
	if err != nil {
		return err
	}
	defer file.Close()

	err = pl.vk.ExportSolidity(file)
	if err != nil {
		return err
	}
	return nil
}

func (pl *PLONK) SaveSCS() error {
	file, err := os.Create(SCSFilePathPLONK)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = pl.ccs.WriteTo(file)
	if err != nil {
		return err
	}
	return nil
}

func (pl *PLONK) SaveSRS() error {
	file, err := os.Create(SRSFilePathPLONK)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = pl.srs.WriteTo(file)
	if err != nil {
		return err
	}
	return nil
}

// Wrong data: the proof fails
// func (pl *PLONK) BadVerify() error {
// 	var err error
// 	var publicWitness CircuitInterface
// 	publicWitness.Hash = "123456789"
// 	witnessPublic, err := frontend.NewWitness(&publicWitness, ecc.BN254.ScalarField(), frontend.PublicOnly())
// 	if err != nil {
// 		return err
// 	}

// 	pk, vk, err := plonk.Setup(pl.ccs, pl.srs)
// 	if err != nil {
// 		return err
// 	}

// 	proof, err := plonk.Prove(pl.ccs, pk, pl.witnessFull)
// 	if err != nil {
// 		return err
// 	}

// 	err = plonk.Verify(proof, vk, witnessPublic)
// 	if err != nil {
// 		return fmt.Errorf("BadVerify error: %w", err)
// 	}

// 	return nil
// }
