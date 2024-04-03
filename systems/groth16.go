package systems

import (
	"crypto/rand"
	"gnark/circuits/hashes"
	"gnark/utils"
	"math/big"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func (g16 *G16) Prove() error {
	var err error

	// Create a limit: 2^254
	limit := new(big.Int).Exp(big.NewInt(2), big.NewInt(254), nil)
	// Generate a random number in the range [0, 2^254)
	randNum, _ := rand.Int(rand.Reader, limit)
	perImage := randNum.String()
	hash := hashes.MimcHash_BN254(perImage)

	// enter inputs
	g16.circuit.PreImage = perImage
	g16.circuit.Hash = hash

	g16.getWitness()

	g16.proof, err = groth16.Prove(g16.r1cs, g16.pk, g16.witnessFull)
	if err != nil {
		return err
	}

	// public inputs
	utils.GetCalldataG16(g16.proof, []string{hash})
	return nil
}

func (g16 *G16) getWitness() error {

	var err error

	g16.witnessFull, err = frontend.NewWitness(&g16.circuit, ecc.BN254.ScalarField())
	if err != nil {
		return err
	}

	err = utils.SaveWitness(g16.witnessFull, WitnessFilePathG16)
	if err != nil {
		return err
	}

	g16.witnessPublic, err = frontend.NewWitness(&g16.circuit, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return err
	}

	err = utils.SaveWitness(g16.witnessPublic, WitnessPublicFilePathG16)
	if err != nil {
		return err
	}

	return nil
}

func (g16 *G16) Verify() error {
	err := groth16.Verify(g16.proof, g16.vk, g16.witnessPublic)
	if err != nil {
		return err
	}
	return nil
}

func (g16 *G16) Compile() error {
	var err error
	g16.r1cs, err = frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &g16.circuit)
	if err != nil {
		return err
	}

	err = g16.SaveR1CS()
	if err != nil {
		return err
	}

	return nil
}

func (g16 *G16) Setup() error {
	var err error
	g16.pk, g16.vk, err = groth16.Setup(g16.r1cs)
	if err != nil {
		return err
	}
	{
		file, err := os.Create(VerificationKeyPathG16)
		if err != nil {
			return err
		}
		defer file.Close()
		_, err = g16.vk.WriteRawTo(file)
		if err != nil {
			return err
		}
	}
	{
		file, err := os.Create(ProvingKeyPathG16)
		if err != nil {
			return err
		}
		defer file.Close()
		_, err = g16.pk.WriteRawTo(file)
		if err != nil {
			return err
		}
	}

	err = g16.ExportSolidity()
	if err != nil {
		return err
	}

	return nil
}

func (g16 *G16) ExportSolidity() error {
	file, err := os.Create(ContractFilePathG16)
	if err != nil {
		return err
	}
	defer file.Close()

	err = g16.vk.ExportSolidity(file)
	if err != nil {
		return err
	}
	return nil
}

func (g16 *G16) SaveR1CS() error {
	file, err := os.Create(R1CSFilePathG16)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = g16.r1cs.WriteTo(file)

	if err != nil {
		return err
	}
	return nil
}

func (g16 *G16) LoadProvingKey(filename string) error {

	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = g16.pk.ReadFrom(file)
	if err != nil {
		return err
	}
	return nil
}

func (g16 *G16) LoadVerifyingKey(filename string) error {

	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = g16.vk.ReadFrom(file)
	if err != nil {
		return err
	}
	return nil
}

func (g16 *G16) LoadProof(filename string) error {

	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = g16.proof.ReadFrom(file)
	if err != nil {
		return err
	}
	return nil
}

func (g16 *G16) LoadWitness(filename string) error {

	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = g16.witnessFull.ReadFrom(file)
	if err != nil {
		return err
	}
	return nil
}

func (g16 *G16) LoadWitnessPublic(filename string) error {

	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = g16.witnessPublic.ReadFrom(file)
	if err != nil {
		return err
	}
	return nil
}

func (g16 *G16) LoadR1CS(filename string) error {

	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = g16.r1cs.ReadFrom(file)
	if err != nil {
		return err
	}
	return nil
}
