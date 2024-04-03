package hashes

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/hash"
)

func MimcHash_BN254(input string) string {
	var x fr.Element
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

func MimcHash_BLS24_317(input string) string {
	var x fr.Element
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
