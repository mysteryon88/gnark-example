package utils

import (
	"os"

	"github.com/consensys/gnark/backend/witness"
)

func SaveWitness(witness witness.Witness, filename string) error {
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
