package hashes

import (
	"testing"

	frbls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	frbn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/hash"
	_ "github.com/consensys/gnark-crypto/ecc/bls12-381/fr/mimc"
	_ "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
)

func TestMimcHashBN254MatchesReference(t *testing.T) {
	const input = "500304"

	var x frbn254.Element
	x.SetString(input)

	h := hash.MIMC_BN254.New()
	b := x.Bytes()
	if _, err := h.Write(b[:]); err != nil {
		t.Fatalf("write hash input: %v", err)
	}

	sum := h.Sum(nil)
	x.SetBytes(sum)

	got := MimcHash_BN254(input)
	want := x.String()
	if got != want {
		t.Fatalf("bn254 hash mismatch: got %s, want %s", got, want)
	}
}

func TestMimcHashBLS12381MatchesReference(t *testing.T) {
	const input = "1"

	var x frbls12381.Element
	x.SetString(input)

	h := hash.MIMC_BLS12_381.New()
	b := x.Bytes()
	if _, err := h.Write(b[:]); err != nil {
		t.Fatalf("write hash input: %v", err)
	}

	sum := h.Sum(nil)
	x.SetBytes(sum)

	got := MimcHash_BLS12_381(input)
	want := x.String()
	if got != want {
		t.Fatalf("bls12-381 hash mismatch: got %s, want %s", got, want)
	}
}
