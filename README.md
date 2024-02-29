# cryptography
Assignments for the Modern Cryptography Course at Tsinghua University

This repository contains my implementations for the assignments of the Modern Cryptography course at Tsinghua University. The focus is on demonstrating practical applications of cryptographic algorithms including symmetric and asymmetric encryption methods, as well as hashing functions.

## Assignment 2: Symmetric Cryptography

### Objective
Implement the block cipher AES128-CBC and the hash algorithm SHA3-256.

### Requirements
- **AES-CBC**: Implement encryption and decryption algorithms. Use a randomly chosen IV and encrypt/decrypt data of 1M or longer.
- **SHA3-256**: Compress data of 1M or longer.
- Ensure correctness of the implementations.
- Achieve an algorithm efficiency greater than 100Mbps.

## Assignment 3: Asymmetric Cryptography and Digital Signatures

### Part 1: RSA Implementation
- Implement RSA with a key size of 2048 bits.
- Include primality testing and encryption/decryption processes (library calls allowed).

### Part 2: Elliptic Curve Cryptography (ECC)
- On the elliptic curve \(y^2 = x^3 + x + 6\) over \(\mathbb{Z}_{11}\):
  1. Compute all points on \(E\).
  2. Prove that \(\alpha = (2,7)\) is a primitive element.
  3. Using \(\alpha = (2,7)\) as the base point, implement ElGamal encryption and decryption for the plaintext point \(x = (5,2)\) with a randomly chosen \(k = 3\).

### Part 3: Digital Signature Algorithm
- Given Alice's ElGamal signature scheme parameters: \(p = 31847\), \(\alpha = 5\), and \(\beta = 25703\), along with signatures for messages \(x = 8990\) and \(x = 31415\), compute the values of \(k\) and \(a\).