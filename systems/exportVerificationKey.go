package systems

import (
	"encoding/json"
	"log"
	"math/big"
	"os"

	curve "github.com/consensys/gnark-crypto/ecc/bls12-381"
	groth16_bls12381 "github.com/consensys/gnark/backend/groth16/bls12-381"
)

type VKExportAlt struct {
	Protocol    string       `json:"protocol"`
	Curve       string       `json:"curve"`
	NPublic     int          `json:"nPublic"`
	VKAlpha1    []string     `json:"vk_alpha_1"`
	VKBeta2     [][]string   `json:"vk_beta_2"`
	VKGamma2    [][]string   `json:"vk_gamma_2"`
	VKDelta2    [][]string   `json:"vk_delta_2"`
	VKAlphaBeta [][][]string `json:"vk_alphabeta_12,omitempty"`
	IC          [][]string   `json:"IC"`
}

func g1CoordsDec(p curve.G1Affine) []string {
	return []string{
		p.X.BigInt(new(big.Int)).String(),
		p.Y.BigInt(new(big.Int)).String(),
		"1",
	}
}

func g2CoordsDec(p curve.G2Affine) [][]string {
	return [][]string{
		{p.X.A0.BigInt(new(big.Int)).String(), p.X.A1.BigInt(new(big.Int)).String()},
		{p.Y.A0.BigInt(new(big.Int)).String(), p.Y.A1.BigInt(new(big.Int)).String()},
		{"1", "0"},
	}
}

func gtToDec(z curve.GT) [][][]string {
	return [][][]string{
		{
			{z.C0.B0.A0.BigInt(new(big.Int)).String(), z.C0.B0.A1.BigInt(new(big.Int)).String()},
			{z.C0.B1.A0.BigInt(new(big.Int)).String(), z.C0.B1.A1.BigInt(new(big.Int)).String()},
			{z.C0.B2.A0.BigInt(new(big.Int)).String(), z.C0.B2.A1.BigInt(new(big.Int)).String()},
		},
		{
			{z.C1.B0.A0.BigInt(new(big.Int)).String(), z.C1.B0.A1.BigInt(new(big.Int)).String()},
			{z.C1.B1.A0.BigInt(new(big.Int)).String(), z.C1.B1.A1.BigInt(new(big.Int)).String()},
			{z.C1.B2.A0.BigInt(new(big.Int)).String(), z.C1.B2.A1.BigInt(new(big.Int)).String()},
		},
	}
}

func exportVerificationKey_groth16_bls12381() {
	file, err := os.Open(VerificationKeyPathG16)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	var vk groth16_bls12381.VerifyingKey
	if _, err = vk.ReadFrom(file); err != nil {
		log.Fatal(err)
	}

	out := VKExportAlt{
		Protocol: "groth16",
		Curve:    "bls12381",
		NPublic:  vk.NbPublicWitness(),
		VKAlpha1: g1CoordsDec(vk.G1.Alpha),
		VKBeta2:  g2CoordsDec(vk.G2.Beta),
		VKGamma2: g2CoordsDec(vk.G2.Gamma),
		VKDelta2: g2CoordsDec(vk.G2.Delta),
	}

	// vk_alphabeta_12 = e(alpha, beta)
	if ab, err := curve.Pair(
		[]curve.G1Affine{vk.G1.Alpha},
		[]curve.G2Affine{vk.G2.Beta},
	); err == nil {
		out.VKAlphaBeta = gtToDec(ab)
	} else {
		log.Fatal(err)
	}

	// IC
	for _, ic := range vk.G1.K {
		out.IC = append(out.IC, g1CoordsDec(ic))
	}

	if err := os.MkdirAll("keys", 0o755); err != nil {
		log.Fatal(err)
	}
	outFile, err := os.Create(VKeyPathG16)
	if err != nil {
		log.Fatal(err)
	}
	defer outFile.Close()

	enc := json.NewEncoder(outFile)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		log.Fatal(err)
	}
}
