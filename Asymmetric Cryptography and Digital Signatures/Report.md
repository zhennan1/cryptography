## Modern Cryptography Assignment 3

### 1. (Public Key Cryptography Algorithm Implementation) Implement 2048-bit RSA.

Requirements: Must include primality testing, encryption and decryption (library calls allowed)

### (1) Implementation Steps

Import required headers and libraries, including RSA, AutoSeededRandomPool, Hex, Base64, Files modules from the Crypto++ library.

Define a helper function IsPrimeFunction to determine whether a large integer is prime.

Implement GenerateRSAKey function for generating RSA public and private keys. First, generate a random number generator rng using AutoSeededRandomPool. Then use InvertibleRSAFunction to generate RSA parameters, and find two prime numbers p and q in a loop to ensure parameter security. Next, create RSA private and public keys and save them to files.

Implement RSAEncryptString function for encrypting a string with a public key. First, load the public key, and use RSAES_OAEP_SHA_Encryptor for encryption, converting plaintext to ciphertext.

Implement RSADecryptString function for decrypting ciphertext with a private key. First, load the private key, and use RSAES_OAEP_SHA_Decryptor for decryption, converting ciphertext back to plaintext.

In the main function, redirect input and output to files using the freopen function. Set the key length to 2048 bits and name the public and private key files. Generate RSA public and private keys using the GenerateRSAKey function. Read the string to be encrypted from standard input. Encrypt using the public key and output the result to a file. Decrypt using the private key and output the result to a file.

### (2) Functions

IsPrimeFunction: Determines whether a large integer is prime.

GenerateRSAKey: Generates RSA public and private keys.

RSAEncryptString: Encrypts a string using the public key.

RSADecryptString: Decrypts ciphertext using the private key.

### (3) Parameter Selection

Key Length: Set to 2048 bits in the code, a common secure key length providing high security.

Public and Private Key Filenames: Set as "rsa-public.key" and "rsa-private.key" in the code, can be modified as needed.

Input and Output Filenames: Use freopen function to redirect input and output to files in the code. Input filename is "plain.txt", output filenames are "cipher.txt" and "decrypted.txt", can be modified as needed.

### (4) Running Examples and Verification

Input "Hello, world!" in plain.txt for testing, the obtained rsa-private.key, rsa.public.key, and decrypted.txt are all correct, and cipher.txt being unreadable is expected.

### 2. (Public Key Cryptography Algorithm Calculation) Let E be an elliptical curve over Z11 with equation y^2=x^3+x+6

1) Calculate all points on E.

2) Prove that α=(2,7) is a primitive element.

3) Let α=(2,7) be the base point, complete encryption and decryption of plaintext x=(5,2) (a point on the elliptical curve) using ElGamal algorithm on the elliptical curve with randomly chosen k=3.

Solution: (1) Exhaust (x,y) as follows
| x or y | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 |
|--------|---|---|---|---|---|---|---|---|---|---|----|
| x^3+x+6 (mod 11) | 6 | 8 | 5 | 3 | 8 | 4 | 8 | 4 | 9 | 7 | 4 |
| y^2 (mod 11) | 0 | 1 | 4 | 9 | 5 | 3 | 3 | 5 | 9 | 4 | 1 |

For these 121 (x,y), if x^3+x+6=y^2 (mod11), then the point is on E, otherwise it is not.

So, the points on E are: (2,4),(2,7),(3,5),(3,6),(5,2),(5,9),(7,2),(7,9),(8,3),(8,8),(10,2),(10,9) totaling 12 points.

(2) Calculate the inverses of 1-10 (mod11):

| x | Inverse |
|---|---------|
| 1 | 1       |
| 2 | 6       |
| 3 | 4       |
| 4 | 3       |
| 5 | 9       |
| 6 | 2       |
| 7 | 8       |
| 8 | 7       |
| 9 | 5       |
| 10| 10      |

For elliptical curve y^2=x^3+x+6 (mod 11) point addition operation:

α (2,7)

2α (2,7)+(2,7)=(5,2)

This is because slope k = (3 * x₁² + a) / (2 * y₁) = 13 / 14 = 52 = 8; x₃ = k² - x₁ - x₂ = 60 = 5; y₃ = k * (x₁ - x₃) - y₁ = -31 = 2. (mod 11) The same below.

3α to 13α calculations show α=(2,7) generates all 12 points on E and the identity element, proving it's a primitive element.

(3) ElGamal encryption/decryption process on elliptical curves detailed.

### 3. (Digital Signature Algorithm) Suppose Alice uses the ElGamal signature scheme, with p=31847, α=5, and β=25703. Given message x=8990 with signature (23972,31396) and x=31415 with signature (23972,20481), calculate the values of k and a.

Solution detailed for calculating k and a under the given conditions.

Solution: If an attacker has legitimate signatures (r1, s1) and (r2, s2) for two messages m1, m2 under the same random number k, the following equations can be constructed:

m1 = r1a + s1k;
m2 = r2a + s2k.

The attacker can solve these equations to find x and k.

Here, r1 = r2, so first, we calculate k:

k = (8990-31415) / (31396-23972) = -22425 / 7426 = 1165 (mod 31846)

To determine a, we solve the congruence:

23972a = 23704 (mod 31846).

gcd(23972,31846) = 2, 2|23704, so the congruence simplifies to

11986a = 11852 (mod 15923).

This congruence has a solution:

a = 11852 / 11986 (mod 15923) = 7459 (mod 15923).

Therefore, a = 7459 or 7459+(p-1)/2 = 23382.

α^7459 = 25703 = β (mod p)

a^23382 = 6144 ≠ β (mod p)

Thus, a = 7459.