package utils

import (
	"bytes"
	"encoding/json"
	"math/big"
	"os"

	"github.com/consensys/gnark/backend/groth16"
)

type SnarkJSProof struct {
	PiA           []string   `json:"pi_a"`
	PiB           [][]string `json:"pi_b"`
	PiC           []string   `json:"pi_c"`
	Protocol      string     `json:"protocol"`
	Curve         string     `json:"curve"`
	PublicSignals []string   `json:"publicSignals"`
}

func ExportProofBLS12381(proof groth16.Proof, publicInputs []string) (SnarkJSProof, error) {
	// BLS12-381: one Fp = 48 bytes (RAW), G1 = 96, G2 = 192
	const fpSize = 48

	// serialize proof in RAW
	var buf bytes.Buffer
	if _, err := proof.WriteRawTo(&buf); err != nil {
		return SnarkJSProof{}, err
	}
	proofBytes := buf.Bytes()

	offset := 0

	readBig := func(n int) *big.Int {
		s := proofBytes[offset : offset+n]
		offset += n
		return new(big.Int).SetBytes(s) // big-endian
	}

	// A
	Ax := readBig(fpSize)
	Ay := readBig(fpSize)

	// B (Fp2: X=(x1,x0), Y=(y1,y0) — as in pi_b snarkjs)
	Bx1 := readBig(fpSize)
	Bx0 := readBig(fpSize)
	By1 := readBig(fpSize)
	By0 := readBig(fpSize)

	// C
	Cx := readBig(fpSize)
	Cy := readBig(fpSize)

	p := SnarkJSProof{
		Protocol:      "groth16",
		Curve:         "bls12381",
		PiA:           []string{Ax.String(), Ay.String(), "1"},
		PiB:           [][]string{{Bx0.String(), Bx1.String()}, {By0.String(), By1.String()}, {"1", "0"}},
		PiC:           []string{Cx.String(), Cy.String(), "1"},
		PublicSignals: publicInputs,
	}
	if err := writeJSON("proof/proof.json", p); err != nil {
		return SnarkJSProof{}, err
	}

	return p, nil
}

func writeJSON(path string, v any) error {
	if err := os.MkdirAll(dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(v, "", "    ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

func dir(p string) string {
	if i := len(p) - 1; i >= 0 {
		for j := i; j >= 0; j-- {
			if p[j] == '/' || p[j] == '\\' {
				return p[:j]
			}
		}
	}
	return "."
}
