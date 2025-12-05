import { readFileSync } from "node:fs";
import { join } from "node:path";
import { groth16 } from "snarkjs";

function loadJson(p: string): any {
  const full = join(__dirname, p);
  return JSON.parse(readFileSync(full, "utf8"));
}

// npm test ./eddsa/verify-snarkjs.test.ts
describe("(EdDSA) snarkjs verify (Groth16) BLS12-381", () => {
  it("verifies proof_bls12381.json with verification_key.json", async () => {
    const vkey = loadJson("keys/verification_key_bls12381.json");
    const proof = loadJson("proofs/proof_bls12381.json");

    // Public signals: PublicKey (X, Y), Signature (R.X, R.Y, S), Message
    // The circuit verifies that the signature is valid for the given message and public key
    const ok = await groth16.verify(vkey, proof.publicSignals, proof);
    expect(ok).toBe(true);
  });

  it("rejects proof_bls12381.json with wrong publicSignals (wrong public key)", async () => {
    const vkey = loadJson("keys/verification_key_bls12381.json");
    const proof = loadJson("proofs/proof_bls12381.json");

    // Change the public key - verification should fail
    const wrongPublicSignals = [...proof.publicSignals];
    if (wrongPublicSignals.length > 0) {
      wrongPublicSignals[0] =
        "1234567890123456789012345678901234567890123456789012345678901234"; // wrong public key X
    }

    const ok = await groth16.verify(vkey, wrongPublicSignals, proof);
    expect(ok).toBe(false);
  });

  it("rejects proof_bls12381.json with wrong publicSignals (wrong message)", async () => {
    const vkey = loadJson("keys/verification_key_bls12381.json");
    const proof = loadJson("proofs/proof_bls12381.json");

    // Change the message - verification should fail
    const wrongPublicSignals = [...proof.publicSignals];
    // Message is typically the last public signal
    if (wrongPublicSignals.length > 0) {
      wrongPublicSignals[wrongPublicSignals.length - 1] =
        "9999999999999999999999999999999999999999999999999999999999999999";
    }

    const ok = await groth16.verify(vkey, wrongPublicSignals, proof);
    expect(ok).toBe(false);
  });

  it("rejects proof_bls12381.json with empty publicSignals", async () => {
    const vkey = loadJson("keys/verification_key_bls12381.json");
    const proof = loadJson("proofs/proof_bls12381.json");

    // Empty array of public signals
    const wrongPublicSignals: string[] = [];

    const ok = await groth16.verify(vkey, wrongPublicSignals, proof);
    expect(ok).toBe(false);
  });

  it("rejects proof_bls12381.json with too many publicSignals", async () => {
    const vkey = loadJson("keys/verification_key_bls12381.json");
    const proof = loadJson("proofs/proof_bls12381.json");

    // Too many public signals - snarkjs throws an error
    const wrongPublicSignals = [...proof.publicSignals, "999999"];

    await expect(
      groth16.verify(vkey, wrongPublicSignals, proof)
    ).rejects.toThrow();
  });
});
