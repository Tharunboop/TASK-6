 Cryptography Fundamentals: Hands-on OpenSSL Experiments

 Table of Contents
1. Core Concepts
2. Symmetric vs Asymmetric Encryption
3. Practical Experiments
4. Real-world Applications
5. Interview Preparation
6. References

 Core Concepts

 What is Encryption?
Encryption transforms plaintext data into unreadable ciphertext using an algorithm (cipher) and a key. Only those with the correct key can decrypt it back to plaintext.


Plaintext → [Encryption Algorithm + Key] → Ciphertext → [Decryption Algorithm + Key] → Plaintext


What is a Hash?
A hash is a one-way mathematical function that takes input of any size and produces a fixed-size output (hash/digest). Key properties:
- Deterministic: Same input = same hash
- Collision-resistant: Hard to find two inputs with same hash
- Avalanche effect: Small input change = drastically different hash
- Irreversible: Can't reverse to original data

bash
echo -n "hello" | openssl dgst -sha256
# Output: 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824


What is a Digital Signature?
Digital signatures provide authenticity, integrity, and non-repudiation:
1. Hash the message
2. Encrypt hash with private key (signature)
3. Recipient decrypts with public key and verifies hash matches


Message → Hash → [Private Key Encrypt] → Signature
Verification: [Public Key Decrypt Signature] == Hash(Message)?


 Symmetric vs Asymmetric Encryption

| Feature | Symmetric | Asymmetric |
|---------|-----------|------------|
| Key Usage | Same key for encrypt/decrypt | Public key encrypt, private key decrypt |
| Speed | Very fast ⚡ | Slower 🐌 |
| Key Distribution | Problematic 🔒 | Public keys can be shared openly |
| Use Case | File encryption, disk encryption | Key exchange, digital signatures |
| Examples | AES, ChaCha20 | RSA, ECC |

Hybrid System (real-world standard):

1. Asymmetric: Exchange symmetric session key
2. Symmetric: Encrypt actual data with session key


 Practical Experiments

 1. Symmetric Encryption (AES-256-CBC)

bash
Create test file
echo "Secret message for Task 6!" > secret.txt

 Generate random key (32 bytes = 256 bits)
openssl rand -hex 32 > aes.key

 Encrypt (interactive password alternative)
openssl enc -aes-256-cbc -salt -in secret.txt -out secret.enc -kfile aes.key

 Decrypt
openssl enc -d -aes-256-cbc -in secret.enc -out secret.dec -kfile aes.key

 Verify
cat secret.dec  # Should match original


Key Points:
- -salt adds randomness (prevents rainbow tables)
- CBC mode requires IV (auto-generated with salt)
- Never reuse IV with same key!

 2. Generate RSA Key Pair

bash
 Generate 4096-bit RSA private key
openssl genrsa -out private.pem 4096

 Extract public key
openssl rsa -in private.pem -pubout -out public.pem

 Verify key details
openssl rsa -in private.pem -text -noout | head -20


Output shows:

Private-Key: (4096 bit)
modulus:
    00:c8:4f:2d:... (huge number)
publicExponent: 65537 (0x10001)  ← Standard


 3. Asymmetric Encryption/Decryption

bash
 Encrypt with public key (only private key holder can decrypt)
echo "Top secret asymmetric message" | openssl rsautl -encrypt -pubin -inkey public.pem -out encrypted.rsa

 Decrypt with private key
openssl rsautl -decrypt -inkey private.pem -in encrypted.rsa

⚠️ RSA Limitation: Max ~245 bytes per encryption (4096-bit key)

 4. Digital Signatures

bash
 Sign file
openssl dgst -sha256 -sign private.pem -out secret.sig secret.txt

 Verify signature
openssl dgst -sha256 -verify public.pem -signature secret.sig secret.txt
Output: Verified OK ✅


What happens:

1. Hash(secret.txt) → H
2. RSA_Encrypt(H, private_key) → signature
3. Verify: RSA_Decrypt(signature, public_key) == H?

 5. File Hashing & Integrity

bash
 Hash file
openssl dgst -sha256 secret.txt
 Output: SHA256(secret.txt)= a1b2c3...
 Verify later
openssl dgst -sha256 -r secret.txt | grep a1b2c3  Should match


Pro Tip: Use sha256sum for production (faster than OpenSSL)

 6. Compare Encryption Algorithms

bash
 Time different AES modes
echo "test" > test.txt

for mode in aes-128-cbc aes-256-gcm chacha20-poly1305; do
    echo "Testing $mode:"
    time openssl enc -${mode} -kfile aes.key -in test.txt -out /tmp/test.enc
done

Results (typical):

AES-128-CBC:     ~500 MB/s
AES-256-GCM:     ~400 MB/s (authenticated)
ChaCha20:        ~600 MB/s (mobile optimized)


Real-world Applications

 HTTPS (TLS 1.3)

1. Client Hello → Server Hello (key exchange)
2. ECDHE → Shared symmetric key
3. AES-256-GCM encrypts HTTP traffic
4. RSA/ECDSA signatures verify server identity


 VPN (WireGuard/OpenVPN)

1. Curve25519 key exchange
2. ChaCha20-Poly1305 encryption + authentication
3. Perfect Forward Secrecy


 Disk Encryption (LUKS)

AES-XTS-256 + PBKDF2 key derivation


 Interview Preparation

 🔥 Must-Know Answers

Q: Symmetric vs Asymmetric?
> Symmetric uses one shared key (AES), fast but key distribution problem. Asymmetric uses public/private key pairs (RSA), solves key distribution but slower. Real-world uses hybrid: RSA for key exchange, AES for bulk data.

Q: What is a Hash?
> One-way function producing fixed-size digest. Properties: deterministic, collision-resistant, avalanche effect. SHA-256 → 32 bytes. Used for integrity (file verification), passwords (with salt), blockchain.

Q: Digital Signature?
> Proves authenticity/integrity/non-repudiation. Hash message → encrypt hash with private key → signature. Verify by decrypting with public key and comparing to fresh hash.

Q: Why Cryptography Important?
> Confidentiality (hide data), Integrity (detect tampering), Authenticity (verify identity), Non-repudiation (prove actions). Protects against eavesdropping, MITM, data leaks.

 Pro Tips for Interviews

1. Mention "hybrid cryptography" = shows real-world understanding
2. Know AES-256-GCM > CBC (authenticated encryption)
3. "Perfect Forward Secrecy" (PFS/ECDHE) = bonus points
4. SHA-256 standard, avoid MD5/SHA-1
5. 4096-bit RSA or switch to ECC (smaller keys, same security)


 Complete Demo Script

Save as crypto_demo.sh and run:

bash
#!/bin/bash
set -e

echo  Cryptography Demo 

 1. Symmetric AES
echo "Top secret" > secret.txt
openssl rand -hex 32 > aes.key
openssl enc -aes-256-gcm -in secret.txt -out secret.enc -kfile aes.key
openssl enc -d -aes-256-gcm -in secret.enc -out secret.dec -kfile aes.key
echo "AES ✅: $(cat secret.dec)"

2. RSA Keys
openssl genrsa -out priv.pem 2048
openssl rsa -in priv.pem -pubout -out pub.pem

 3. Sign & Verify
openssl dgst -sha256 -sign priv.pem -out sig.bin secret.txt
openssl dgst -sha256 -verify pub.pem -signature sig.bin secret.txt
echo "Signature ✅: Verified OK"

4. Hashes
echo "SHA256: $(openssl dgst -sha256 secret.txt | cut -d' ' -f2)"
echo "Demo complete! 🎉"


bash
chmod +x crypto_demo.sh && ./crypto_demo.sh



