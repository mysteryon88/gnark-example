// test/verify-groth16.test.ts
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { groth16 } from "snarkjs";

function loadJson(p: string): any {
  const full = join(__dirname, p);
  return JSON.parse(readFileSync(full, "utf8"));
}

// npm test
describe("snarkjs verify (Groth16) BLS12-381", () => {
  it("verifies proof.json with verification_key.json", async () => {
    const vkey = loadJson("keys/verification_key_bls12381.json");
    const proof = loadJson("proofs/proof_bls12381.json");
    const publicSignals: string[] = ["35"];

    // sanity checks
    expect(Array.isArray(publicSignals)).toBe(true);
    expect(publicSignals.length).toBeGreaterThan(0);

    const ok = await groth16.verify(vkey, publicSignals, proof);
    expect(ok).toBe(true);
  });

  it("rejects proof.json with wrong publicSignals", async () => {
    const vkey = loadJson("keys/verification_key_bls12381.json");
    const proof = loadJson("proofs/proof_bls12381.json");

    const wrongPublicSignals: string[] = ["99"];

    expect(Array.isArray(wrongPublicSignals)).toBe(true);
    expect(wrongPublicSignals.length).toBeGreaterThan(0);

    const ok = await groth16.verify(vkey, wrongPublicSignals, proof);
    expect(ok).toBe(false); // здесь должно быть false
  });
});

describe("snarkjs verify (Groth16) BN254", () => {
  it("verifies proof.json with verification_key.json", async () => {
    const vkey = loadJson("keys/verification_key_bn254.json");
    const proof = loadJson("proofs/proof_bn254.json");
    const publicSignals: string[] = ["35"];

    // sanity checks
    expect(Array.isArray(publicSignals)).toBe(true);
    expect(publicSignals.length).toBeGreaterThan(0);

    const ok = await groth16.verify(vkey, publicSignals, proof);
    expect(ok).toBe(true);
  });

  it("rejects proof.json with wrong publicSignals", async () => {
    const vkey = loadJson("keys/verification_key_bn254.json");
    const proof = loadJson("proofs/proof_bn254.json");

    const wrongPublicSignals: string[] = ["99"];

    expect(Array.isArray(wrongPublicSignals)).toBe(true);
    expect(wrongPublicSignals.length).toBeGreaterThan(0);

    const ok = await groth16.verify(vkey, wrongPublicSignals, proof);
    expect(ok).toBe(false); // здесь должно быть false
  });
});
