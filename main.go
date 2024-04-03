package main

import (
	"fmt"
	"time"

	"gnark/circuits/recursive/g16_v0_9_1"
	"gnark/systems"
)

func main() {
	// you need these directories
	//utils.CheckDirs([]string{"proof", "contracts", "keys", "witness", "constraints"})

	//Groth16()
	//Plonk()

	recursiveGroth16PerformanceTest()
}

func recursiveGroth16PerformanceTest() {
	start := time.Now()
	g16_v0_9_1.BLS12_337inBW6_761()
	duration := time.Since(start)
	fmt.Printf("Execution time: %v ms\n", duration.Milliseconds())

	start = time.Now()
	g16_v0_9_1.BN254inBN254()
	duration = time.Since(start)
	fmt.Printf("Execution time: %v ms\n", duration.Milliseconds())
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
