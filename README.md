# A template for using gnark

zkSNARK in golang for Ethereum (groth16 and plonk)

The research started with gnark v0.9.1

- The `circuits` directory is where you place your circuits
- In the `systems` directory, you can create proofs and verify them
  - You need to replace the `interface` and add `inputs`

# elliptic curves

- gnark supports six elliptic curves:
  - BN254
  - BLS12-381
  - BLS12-377
  - BW6-761
  - BLS24-315
  - BW6-633

> [!NOTE]
>
> - BN254 is used in Ethereum 1.x.
> - BLS12-381 in Ethereum 2.0, ZCash Sapling, Algorand, Dfinity, Chia, and Filecoin.
> - BLS12-377/BW6-761 in Celo, Aleo and EY.
>
> For applications that target Ethereum 1.x mainnet, BN254 is the only supported curve.
>
> [Read More](https://docs.gnark.consensys.io/Concepts/schemes_curves)
