const { execFileSync } = require("node:child_process");

const steps = [
  [
    "go",
    [
      "test",
      "./cubic",
      "-run",
      "^TestCubic(BN254|BLS12_381)$",
      "-count=1",
    ],
  ],
  [
    "go",
    [
      "test",
      "./mimc",
      "-run",
      "^TestMimc(BN254|BLS12_381)$",
      "-count=1",
    ],
  ],
  ["go", ["test", "./eddsa", "-run", "^TestEdDSA$", "-count=1"]],
  [
    "go",
    [
      "test",
      "./merkle_proof",
      "-run",
      "^TestMerkleProof(BN254|BLS12_381)$",
      "-count=1",
    ],
  ],
  [
    "go",
    [
      "test",
      "./commitments",
      "-run",
      "^TestNoCommitment_(BN254|BLS12381)$",
      "-count=1",
    ],
  ],
];

for (const [command, args] of steps) {
  console.log(`> ${command} ${args.join(" ")}`);
  execFileSync(command, args, { stdio: "inherit" });
}
