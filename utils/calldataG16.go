package utils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"os"

	"github.com/consensys/gnark/backend/groth16"
)

type ContractInputG16 struct {
	A     [2]string
	B     [2][2]string
	C     [2]string
	Input []string
}

func GetCalldataG16(proof groth16.Proof, input []string) (ContractInputG16, error) {

	const fpSize = 4 * 8
	var buf bytes.Buffer
	proof.WriteRawTo(&buf)
	proofBytes := buf.Bytes()

	var (
		a [2]*big.Int
		b [2][2]*big.Int
		c [2]*big.Int
	)

	a[0] = new(big.Int).SetBytes(proofBytes[fpSize*0 : fpSize*1])
	a[1] = new(big.Int).SetBytes(proofBytes[fpSize*1 : fpSize*2])
	b[0][0] = new(big.Int).SetBytes(proofBytes[fpSize*2 : fpSize*3])
	b[0][1] = new(big.Int).SetBytes(proofBytes[fpSize*3 : fpSize*4])
	b[1][0] = new(big.Int).SetBytes(proofBytes[fpSize*4 : fpSize*5])
	b[1][1] = new(big.Int).SetBytes(proofBytes[fpSize*5 : fpSize*6])
	c[0] = new(big.Int).SetBytes(proofBytes[fpSize*6 : fpSize*7])
	c[1] = new(big.Int).SetBytes(proofBytes[fpSize*7 : fpSize*8])

	inputJSON := ContractInputG16{
		A:     [2]string{a[0].String(), a[1].String()},
		B:     [2][2]string{{b[0][0].String(), b[0][1].String()}, {b[1][0].String(), b[1][1].String()}},
		C:     [2]string{c[0].String(), c[1].String()},
		Input: input,
	}

	err := jsonFile(inputJSON)
	if err != nil {
		return ContractInputG16{}, err
	}

	err = byteFile(proof)
	if err != nil {
		return ContractInputG16{}, err
	}

	arrayFile(a, b, c)

	return inputJSON, nil
}

func jsonFile(inputJSON ContractInputG16) error {
	jsonData, err := json.MarshalIndent(inputJSON, "", "    ")
	if err != nil {
		return err
	}

	err = os.WriteFile("proof/proof_g16.json", jsonData, 0644)
	if err != nil {
		return err
	}

	return nil
}

func byteFile(proof groth16.Proof) error {
	file, err := os.Create("proof/proof_g16.proof")
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = proof.WriteRawTo(file)
	if err != nil {
		return err
	}
	return nil
}

func arrayFile(a [2]*big.Int, b [2][2]*big.Int, c [2]*big.Int) {
	file, err := os.Create("proof/proofArr_g16.json")
	if err != nil {
		panic(err)
	}
	defer file.Close()

	fmt.Fprintf(file, "[")

	totalElements := 2 + 2*2 + 2
	currentElement := 1

	// array a
	for _, val := range a {
		fmt.Fprintf(file, "\"%s\"", val)
		if currentElement < totalElements {
			fmt.Fprintf(file, ", ")
			currentElement++
		}
	}

	// matrix b
	for _, arr := range b {
		for _, val := range arr {
			fmt.Fprintf(file, "\"%s\"", val)
			if currentElement < totalElements {
				fmt.Fprintf(file, ", ")
				currentElement++
			}
		}
	}

	// array c
	for _, val := range c {
		fmt.Fprintf(file, "\"%s\"", val)
		if currentElement < totalElements {
			fmt.Fprintf(file, ", ")
			currentElement++
		}
	}

	fmt.Fprintf(file, "]")
}
