package main

import (
	"fmt"
	"gnark/systems"
	"gnark/utils"
)

func main() {
	// you need these directories
	utils.CheckDirs([]string{"proof", "contracts", "keys", "witness", "constraints"})

	//Groth16()
	Plonk()
}

func Groth16() {
	g16 := systems.G16{}
	g16.Compile()
	g16.Setup()
	g16.Prove()
	g16.Verify()
}

func Plonk() {
	plonk := systems.PLONK{}
	err := plonk.Compile()
	if err != nil {
		fmt.Println("Compile error:", err)
	}

	err = plonk.Setup()
	if err != nil {
		fmt.Println("Setup error:", err)
	}

	err = plonk.Prove()
	if err != nil {
		fmt.Println("Prove error:", err)
	}

	err = plonk.Verify()
	if err != nil {
		fmt.Println(err)
	}
}
