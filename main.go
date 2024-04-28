package main

import (
	"fmt"
	"time"

	"gnark/circuits/recursive/groth16"
	"gnark/circuits/recursive/plonk"
	"gnark/systems"
)

func main() {
	// you need these directories
	//utils.CheckDirs([]string{"proof", "contracts", "keys", "witness", "constraints"})

	//Groth16()
	//Plonk()

	//RecursiveGroth16PerformanceTest()
	RecursivePLONKPerformanceTest()
}

func RecursiveGroth16PerformanceTest() {
	start := time.Now()
	groth16.BLS12_337inBW6_761()
	duration := time.Since(start)
	fmt.Printf("Execution time: %v ms\n", duration.Milliseconds())

	start = time.Now()
	groth16.BN254inBN254()
	duration = time.Since(start)
	fmt.Printf("Execution time: %v ms\n", duration.Milliseconds())
}

func RecursivePLONKPerformanceTest() {
	start := time.Now()
	plonk.BLS12_337inBW6_761()
	duration := time.Since(start)
	fmt.Printf("Execution time: %v ms\n", duration.Milliseconds())

	start = time.Now()
	plonk.BW6_761inBN254()
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
