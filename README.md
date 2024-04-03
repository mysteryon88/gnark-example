# A template for using gnark

zkSNARK in golang for Ethereum (groth16 and plonk)

The research started with gnark v0.9.1

- The `circuits` directory is where you place your circuits
- In the `systems` directory, you can create proofs and verify them
  - You need to replace the `interface` and add `inputs`
