# Hawaii

This project in Python focuses on fundamental cryptographic operations and blockchain components. It includes classes for elliptic curve cryptography (ECC), digital signatures (ECDSA), and Bitcoin address generation using the SHA-256 algorithm. Key features include:

## Elliptic Curve Cryptography (ECC)

- **FieldElement:** Represents elements in a finite field for ECC operations.
- **Point:** Defines points on an elliptic curve and supports operations like addition and scalar multiplication.
- **Sha256Field and Sha256Point:** Specialized for ECC operations using the SHA-256 curve.

## Elliptic Curve Digital Signature Algorithm (ECDSA)

- **Signature:** Encapsulates components of an ECDSA signature.
- **PrivateKey:** Generates private keys and their corresponding public keys. Supports message signing using ECDSA.

## Utility Functions

- **double_sha256:** Performs double SHA-256 hashing for cryptographic purposes.
- **encode_base58 and encode_base58_checksum:** Converts byte sequences to Base58 format (used for Bitcoin addresses).
- **hash160:** Computes RIPEMD-160 hash of SHA-256 hashed input for address generation.
- **address:** Generates Bitcoin-style addresses from public key hashes.

## Example Usage

- Demonstrates private key generation, message signing, public key derivation, and Bitcoin address generation.
- Illustrates integration of cryptographic primitives into blockchain functionalities.
  
This project provides foundational tools for understanding ECC, ECDSA, and blockchain operations, adaptable for blockchain development, cryptocurrencies, and secure messaging systems.
