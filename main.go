package main

import (
	"gnark/systems"
	"gnark/utils"
)

func main() {
	// you need these directories
	utils.CheckDirs([]string{"proof", "contracts", "keys", "witness"})

	g16 := systems.G16{}

	g16.Setup()
	g16.Prove()
	g16.Verify()

	// err := systems.GeneratePlonk()
	// if err != nil {
	// 	log.Fatal("plonk error:", err)
	// }
}
