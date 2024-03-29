package main

import (
	"gnark/systems"
	"gnark/utils"
)

func main() {
	// you need these directories
	utils.CheckDirs([]string{"proof", "contracts", "keys", "witness", "constraints"})

	Groth16()
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
	plonk.Compile()
	plonk.Setup()
}
