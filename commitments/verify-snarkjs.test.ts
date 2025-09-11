import { readFileSync } from "node:fs";
import { join } from "node:path";
import { groth16 } from "snarkjs";

function loadJson(p: string): any {
  const full = join(__dirname, p);
  return JSON.parse(readFileSync(full, "utf8"));
}

const curves = [
  { type: "bn254", name: "BN254" },
  { type: "bls12381", name: "BLS12-381" },
];

// npm test
curves.forEach(({ type: curveType, name: curveName }) => {
  describe(`(NoCommit) snarkjs verify (Groth16) ${curveName}`, () => {
    test("verifies proof.json with verification_key.json", async () => {
      const vkey = loadJson(
        `keys/verification_key_no_commit_${curveType}.json`
      );

      const proof = loadJson(`proofs/proof_no_commit_${curveType}.json`);

      const ok = await groth16.verify(vkey, proof.publicSignals, proof);
      expect(ok).toBe(true);
    });

    test("rejects proof.json with wrong publicSignals", async () => {
      const vkey = loadJson(
        `keys/verification_key_no_commit_${curveType}.json`
      );

      const proof = loadJson(`proofs/proof_no_commit_${curveType}.json`);

      const wrongPublicSignals: string[] = ["99"];
      const ok = await groth16.verify(vkey, wrongPublicSignals, proof);
      expect(ok).toBe(false);
    });
  });
});
