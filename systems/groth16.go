package systems

import (
	"crypto/rand"
	"gnark/circuits/hashes"
	"gnark/circuits/mimc"
	"gnark/utils"
	"math/big"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// your circuit type
type CircuitInterface struct {
	mimc.Circuit
}

type G16 struct {
	circuit CircuitInterface

	r1cs constraint.ConstraintSystem
	pk   groth16.ProvingKey
	vk   groth16.VerifyingKey

	witnessFull   witness.Witness
	witnessPublic witness.Witness
	proof         groth16.Proof
	R1sc          constraint.ConstraintSystem
}

func (g16 *G16) Prove() error {
	var err error

	// Create a limit: 2^254
	limit := new(big.Int).Exp(big.NewInt(2), big.NewInt(254), nil)
	// Generate a random number in the range [0, 2^254)
	randNum, _ := rand.Int(rand.Reader, limit)
	perImage := randNum.String()
	hash := hashes.MimcHashBN254(perImage)

	// enter inputs
	g16.circuit.PreImage = perImage
	g16.circuit.Hash = hashes.MimcHashBN254(perImage)

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

	saveWitness(g16.witnessFull, "witness/witness_g16.wtns")

	g16.witnessPublic, err = frontend.NewWitness(&g16.circuit, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return err
	}

	saveWitness(g16.witnessPublic, "witness/witnessPub_g16.wtns")

	return nil
}

func (g16 *G16) Verify() error {
	err := groth16.Verify(g16.proof, g16.vk, g16.witnessPublic)
	if err != nil {
		return err
	}
	return nil
}

func (g16 *G16) Setup() error {
	var err error
	g16.r1cs, err = frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &g16.circuit)
	if err != nil {
		return err
	}

	g16.R1sc = g16.r1cs
	g16.pk, g16.vk, err = g16.setupG16()
	if err != nil {
		return err
	}
	return nil
}

func (g16 *G16) setupG16() (groth16.ProvingKey, groth16.VerifyingKey, error) {
	pk, vk, err := groth16.Setup(g16.r1cs)
	if err != nil {
		return nil, nil, err
	}
	{
		f, err := os.Create("keys/mimc.g16.vk")
		if err != nil {
			return nil, nil, err
		}
		_, err = vk.WriteRawTo(f)
		if err != nil {
			return nil, nil, err
		}
	}
	{
		f, err := os.Create("keys/mimc.g16.pk")
		if err != nil {
			return nil, nil, err
		}
		_, err = pk.WriteRawTo(f)
		if err != nil {
			return nil, nil, err
		}
	}

	{
		f, err := os.Create("contracts/contract_g16.sol")
		if err != nil {
			return nil, nil, err
		}
		err = vk.ExportSolidity(f)
		if err != nil {
			return nil, nil, err
		}
	}

	return pk, vk, nil
}

func saveWitness(witness witness.Witness, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = witness.WriteTo(file)

	if err != nil {
		return err
	}
	return nil
}
