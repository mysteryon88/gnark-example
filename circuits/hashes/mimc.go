package hashes

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/hash"
)

func MimcHashBN254(input string) string {
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
