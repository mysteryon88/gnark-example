# The use of recursive proofs

- groth16
- plonk

## v0.10.0

Package plonk implements in-circuit PLONK verifier.

NB! The circuit allows verifying proofs of PLONK circuits of size up to 2\*\*30 constraints.

# Performance Tests

## Groth16

- In gnark v0.14.0
  - Recursive verification of the `BN254` Groth16 proof in `BN254` Groth16
    - ≈ 104366 ms = 104.366 s = 1.739 min
  - Recursive verification of the `BLS12-377` Groth16 proof in `BW6-761` Groth16
    - ≈ 6696 ms = 6.696 s

- In gnark v0.13.0
  - Recursive verification of the `BN254` Groth16 proof in `BN254` Groth16
    - ≈ 85962 ms = 85.962 s = 1.4327 min
  - Recursive verification of the `BLS12-377` Groth16 proof in `BW6-761` Groth16
    - ≈ 6159 ms = 6.159 s

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

- In gnark v0.14.0
  - Recursive verification of the `BW6-761` Groth16 proof in `BN254` Groth16
    - ≈ 417706 ms = 417.706 s = 6.96176667 min
  - Recursive verification of the `BLS12-377` Groth16 proof in `BW6-761` Groth16
    - ≈ 47841 ms = 47.841 s

- In gnark v0.13.0
  - Recursive verification of the `BW6-761` Groth16 proof in `BN254` Groth16
    - ≈ 520033 ms = 520.033 s = 8.66721667 min
  - Recursive verification of the `BLS12-377` Groth16 proof in `BW6-761` Groth16
    - ≈ 41619 ms = 41.619 s

- In gnark v0.10.0
  - Recursive verification of the `BW6-761` Groth16 proof in `BN254` Groth16
    - ≈ 1087338 ms = 1087.338 s = 18.1223 min
  - Recursive verification of the `BLS12-377` Groth16 proof in `BW6-761` Groth16
    - ≈ 79777 ms = 79.777 s = 1.3296167 min
