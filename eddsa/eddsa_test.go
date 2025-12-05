package eddsa

import (
	"fmt"
	"gnark_example/utils"
	"testing"

	"crypto/rand"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/mimc"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/twistededwards/eddsa"
	"github.com/stretchr/testify/assert"
)

// go test ./eddsa -v -run TestEdDSA
func TestEdDSA(t *testing.T) {
	hFunc := mimc.NewMiMC()
	privateKey, _ := eddsa.GenerateKey(rand.Reader)
	publicKey := privateKey.PublicKey

	var _msg fr.Element
	_msg.MustSetRandom()
	msg := _msg.Marshal()

	// sign the message
	signature, _ := privateKey.Sign(msg, hFunc)

	// verifies signature
	isValid, _ := publicKey.Verify(signature, msg, hFunc)
	if !isValid {
		fmt.Println("1. invalid signature")
	} else {
		fmt.Println("1. valid signature")
	}

	utils.CheckDirs([]string{"proofs", "keys"})

	g16 := G16{}

	g16.Compile(ecc.BLS12_381.ScalarField())
	g16.Setup()
	g16.Prove(ecc.BLS12_381.ScalarField(), publicKey, signature, msg)
	g16.Verify()
	err := g16.Export()
	assert.NoError(t, err)
}
