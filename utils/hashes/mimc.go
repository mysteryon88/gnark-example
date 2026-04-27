package hashes

import (
	"fmt"

	frbls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	frbls24317 "github.com/consensys/gnark-crypto/ecc/bls24-317/fr"
	frbn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/hash"
	_ "github.com/consensys/gnark-crypto/ecc/bls12-381/fr/mimc"
	_ "github.com/consensys/gnark-crypto/ecc/bls24-317/fr/mimc"
	_ "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
)

func MimcHash_BN254(input string) string {
	var x frbn254.Element
	mimcHash := hash.MIMC_BN254.New()
	// to fild
	x.SetString(input)
	b := x.Bytes()
	_, err := mimcHash.Write(b[:])
	if err != nil {
		fmt.Println(err)
		return ""
	}
	hashB := mimcHash.Sum(nil)
	x.SetBytes(hashB)
	hash := x.String()

	// fmt.Println("MimcHash = ", hash)
	return hash
}

func MimcHash_BLS12_381(input string) string {
	var x frbls12381.Element
	mimcHash := hash.MIMC_BLS12_381.New()
	// to fild
	x.SetString(input)
	b := x.Bytes()
	_, err := mimcHash.Write(b[:])
	if err != nil {
		fmt.Println(err)
		return ""
	}
	hashB := mimcHash.Sum(nil)
	x.SetBytes(hashB)
	hash := x.String()

	// fmt.Println("MimcHash = ", hash)
	return hash
}

func MimcHash_BLS24_317(input string) string {
	var x frbls24317.Element
	mimcHash := hash.MIMC_BLS24_317.New()
	// to fild
	x.SetString(input)
	b := x.Bytes()
	_, err := mimcHash.Write(b[:])
	if err != nil {
		fmt.Println(err)
		return ""
	}
	hashB := mimcHash.Sum(nil)
	x.SetBytes(hashB)
	hash := x.String()

	// fmt.Println("MimcHash = ", hash)
	return hash
}
