# The use of recursive proofs

- groth16
- plonk

## v0.10.0

Package plonk implements in-circuit PLONK verifier.

NB! The circuit allows verifying proofs of PLONK circuits of size up to 2\*\*30 constraints.

# Performance Tests

## Groth16

- In gnark v0.10.0
  - Recursive verification of the `BN254` Groth16 proof in `BN254` Groth16
    - ≈ 179065 ms = 179.065 s = 2.98441667 min
  - Recursive verification of the `BLS12-377` Groth16 proof in `BW6-761` Groth16
    - ≈ 6674 ms = 6.674 s
- In gnark v0.9.1
  - Recursive verification of the `BN254` Groth16 proof in `BN254` Groth16
    - ≈ 282093 ms = 282.093 s = 4.70155 min
  - Recursive verification of the `BLS12-377` Groth16 proof in `BW6-761` Groth16
    - ≈ 6194 ms = 6.194 s

## PLONK

- In gnark v0.10.0
  - Recursive verification of the `BW6-761` Groth16 proof in `BN254` Groth16
    - ≈ 1087338 ms = 1087.338 s = 18.1223 min
  - Recursive verification of the `BLS12-377` Groth16 proof in `BW6-761` Groth16
    - ≈ 79777 ms = 79.777 s = 1.3296167 min
