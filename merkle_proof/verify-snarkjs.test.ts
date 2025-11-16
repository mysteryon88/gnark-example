import { readFileSync } from "node:fs";
import { join } from "node:path";
import { groth16 } from "snarkjs";

function loadJson(p: string): any {
  const full = join(__dirname, p);
  return JSON.parse(readFileSync(full, "utf8"));
}

// npm test ./merkle_proof/verify-snarkjs.test.ts
describe("(MerkleProof) snarkjs verify (Groth16) BLS12-381", () => {
  it("verifies proof_bls12381.json with verification_key.json", async () => {
    const vkey = loadJson("keys/verification_key_bls12381.json");
    const proof = loadJson("proofs/proof_bls12381.json");

    // Public signal: RootHash (Merkle tree root)
    // The circuit verifies that the 35th leaf (index 34) is present in the tree with this root
    const ok = await groth16.verify(vkey, proof.publicSignals, proof);
    expect(ok).toBe(true);
  });

  it("rejects proof_bls12381.json with wrong publicSignals (wrong root)", async () => {
    const vkey = loadJson("keys/verification_key_bls12381.json");
    const proof = loadJson("proofs/proof_bls12381.json");

    // Change the tree root - verification should fail
    const wrongPublicSignals = [...proof.publicSignals];
    wrongPublicSignals[0] =
      "1234567890123456789012345678901234567890123456789012345678901234"; // wrong root

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

describe("(MerkleProof) snarkjs verify (Groth16) BN254", () => {
  it("verifies proof_bn254.json with verification_key.json", async () => {
    const vkey = loadJson("keys/verification_key_bn254.json");
    const proof = loadJson("proofs/proof_bn254.json");

    // Public signal: RootHash (Merkle tree root)
    // The circuit verifies that the 35th leaf (index 34) is present in the tree with this root
    const ok = await groth16.verify(vkey, proof.publicSignals, proof);
    expect(ok).toBe(true);
  });

  it("rejects proof_bn254.json with wrong publicSignals (wrong root)", async () => {
    const vkey = loadJson("keys/verification_key_bn254.json");
    const proof = loadJson("proofs/proof_bn254.json");

    // Change the tree root - verification should fail
    const wrongPublicSignals = [...proof.publicSignals];
    wrongPublicSignals[0] = "42"; // wrong root

    const ok = await groth16.verify(vkey, wrongPublicSignals, proof);
    expect(ok).toBe(false);
  });

  it("rejects proof_bn254.json with empty publicSignals", async () => {
    const vkey = loadJson("keys/verification_key_bn254.json");
    const proof = loadJson("proofs/proof_bn254.json");

    // Empty array of public signals
    const wrongPublicSignals: string[] = [];

    const ok = await groth16.verify(vkey, wrongPublicSignals, proof);
    expect(ok).toBe(false);
  });

  it("rejects proof_bn254.json with too many publicSignals", async () => {
    const vkey = loadJson("keys/verification_key_bn254.json");
    const proof = loadJson("proofs/proof_bn254.json");

    // Too many public signals - snarkjs throws an error
    const wrongPublicSignals = [...proof.publicSignals, "999999"];

    await expect(
      groth16.verify(vkey, wrongPublicSignals, proof)
    ).rejects.toThrow();
  });

  it("rejects proof_bn254.json with zero root", async () => {
    const vkey = loadJson("keys/verification_key_bn254.json");
    const proof = loadJson("proofs/proof_bn254.json");

    // Root is zero - verification should fail
    const wrongPublicSignals = ["0"];

    const ok = await groth16.verify(vkey, wrongPublicSignals, proof);
    expect(ok).toBe(false);
  });
});
