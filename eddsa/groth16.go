package eddsa

import (
	"fmt"
	"math/big"
	"os"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/twistededwards/eddsa"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	gnarktosnarkjs "github.com/mysteryon88/gnark-to-snarkjs"

	"github.com/consensys/gnark-crypto/ecc/twistededwards"
)

func (g16 *G16) Prove(ScalarField *big.Int, publicKey eddsa.PublicKey, signature []byte, msg []byte) error {

	var err error

	// assign message value
	g16.circuit.Message = msg

	// store original public key structure and bytes
	g16.publicKeyStruct = publicKey
	g16.publicKey = publicKey.Bytes()
	g16.signature = signature
	g16.message = msg

	// assign public key values
	g16.circuit.PublicKey.Assign(twistededwards.BLS12_381, g16.publicKey[:32])

	// assign signature values
	g16.circuit.Signature.Assign(twistededwards.BLS12_381, signature)

	err = g16.getWitness(ScalarField)
	if err != nil {
		return fmt.Errorf("failed to create witness: %w", err)
	}

	g16.proof, err = groth16.Prove(g16.r1cs, g16.pk, g16.witnessFull)
	if err != nil {
		return fmt.Errorf("failed to generate proof: %w", err)
	}

	if g16.proof == nil {
		return fmt.Errorf("proof is nil after generation")
	}

	return nil
}

func (g16 *G16) Export() error {
	if g16.proof == nil {
		return fmt.Errorf("proof is nil, cannot export")
	}

	var ProofPath, VKeyPath string

	ProofPath, VKeyPath = ProofPathG16_BLS12381, VKeyPathG16_BLS12381

	// Export the proof
	{

		proof_out, err := os.Create(ProofPath)
		if err != nil {
			return err
		}

		defer proof_out.Close()

		// Extract public signals by converting bytes to big.Int
		// The verification key indicates there should be 6 public signals
		// The circuit has: PublicKey (point with X, Y), Signature (structure with R.X, R.Y, S), Message
		// Total: PublicKey.X, PublicKey.Y, Signature.R.X, Signature.R.Y, Signature.S, Message = 6 signals
		var publicSignals []string

		// Extract public signals from original data structures
		// Use the stored publicKeyStruct to get X and Y coordinates
		publicKeyX := new(big.Int)
		publicKeyY := new(big.Int)
		g16.publicKeyStruct.A.X.BigInt(publicKeyX)
		g16.publicKeyStruct.A.Y.BigInt(publicKeyY)
		publicSignals = append(publicSignals, publicKeyX.String(), publicKeyY.String())

		// Extract Signature coordinates (R.X, R.Y, S)
		// For EdDSA signature, we need to parse the signature bytes
		// Standard EdDSA signature format: R (compressed 32 bytes) + S (32 bytes) = 64 bytes
		if len(g16.signature) >= 64 {
			// Parse signature to get R point and S scalar
			var sig eddsa.Signature
			_, err := sig.SetBytes(g16.signature)
			if err != nil {
				return fmt.Errorf("failed to parse signature: %w", err)
			}

			// Extract R coordinates (R is a point on the curve)
			sigRX := new(big.Int)
			sigRY := new(big.Int)
			sig.R.X.BigInt(sigRX)
			sig.R.Y.BigInt(sigRY)

			// Extract S scalar (S is [32]byte)
			sigS := new(big.Int).SetBytes(sig.S[:])

			publicSignals = append(publicSignals, sigRX.String(), sigRY.String(), sigS.String())
		} else {
			// Fallback
			padded := make([]byte, 32)
			copy(padded[32-len(g16.signature):], g16.signature)
			sigRX := new(big.Int).SetBytes(padded)
			sigRY := new(big.Int).SetBytes(padded)
			sigS := big.NewInt(0)
			publicSignals = append(publicSignals, sigRX.String(), sigRY.String(), sigS.String())
		}

		// Extract Message
		messageInt := new(big.Int).SetBytes(g16.message)
		publicSignals = append(publicSignals, messageInt.String())

		// Total 6 public signals: PublicKey.X, PublicKey.Y, Signature.R.X, Signature.R.Y, Signature.S, Message

		err = gnarktosnarkjs.ExportProof(g16.proof, publicSignals, proof_out)
		if err != nil {
			return err
		}
	}

	// Export the verification key
	{
		out, err := os.Create(VKeyPath)
		if err != nil {
			return err
		}
		defer out.Close()
		err = gnarktosnarkjs.ExportVerifyingKey(g16.vk, out)
		if err != nil {
			return err
		}
	}
	return nil
}

func (g16 *G16) Compile(ScalarField *big.Int) error {
	var err error
	g16.r1cs, err = frontend.Compile(ScalarField, r1cs.NewBuilder, &g16.circuit)
	if err != nil {
		return err
	}
	return nil
}

func (g16 *G16) Setup() error {
	var err error
	g16.pk, g16.vk, err = groth16.Setup(g16.r1cs)
	if err != nil {
		return err
	}
	return nil
}

func (g16 *G16) Verify() error {
	if g16.proof == nil {
		return fmt.Errorf("proof is nil, cannot verify")
	}
	if g16.vk == nil {
		return fmt.Errorf("verification key is nil, cannot verify")
	}
	if g16.witnessPublic == nil {
		return fmt.Errorf("public witness is nil, cannot verify")
	}

	err := groth16.Verify(g16.proof, g16.vk, g16.witnessPublic)
	if err != nil {
		return fmt.Errorf("verification failed: %w", err)
	}
	return nil
}

func (g16 *G16) getWitness(ScalarField *big.Int) error {

	var err error

	g16.witnessFull, err = frontend.NewWitness(&g16.circuit, ScalarField)
	if err != nil {
		return err
	}

	g16.witnessPublic, err = frontend.NewWitness(&g16.circuit, ScalarField, frontend.PublicOnly())
	if err != nil {
		return err
	}

	return nil
}
