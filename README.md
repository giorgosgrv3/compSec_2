# Assignment 2 - ECDH & RSA  
Gravalos Georgios Angelos, 2021030001  
Kerimi Rafaela Aikaterini, 2021030007

(We have optimized this README for Markdown)

### To compile the files:
```bash
make all
```
This will compile both task 1 and task 2. Otherwise, you can freely compile just one of the two.

## Task 1 - ECDH (`ecdh_assign2.c`)
We have used libsodium to perform Elliptic Curve Diffie-Hellman key exchange on Curve25519, using `crypto_scalarmult()` -> it performs the ECDH math.  
Alice and Bob's private keys can optionally be provided through the CLI, or be generated randomly.  
A shared secret is then derived, and fed into `crypto_kdf_derive_from_key()` to generate MAC and encryption keys.

**Usage:**
```bash
./ecdh_assign2 -o <output_file> [-a <alice_priv>] [-b <bob_priv>] [-c <context>]
```

**Options:**
```
-o : the output file destination, where we log results and generated values
-a : alice's private key IN HEX (optional, will be generated randomly if not provided)
-b : bob's private key IN HEX (optional, will be generated randomly if not provided)
-c : 8-byte context for KDF (it is "ECDH_KDF" by default)
-h : print this very help menu in console
```

**Some usage examples can be:**
```bash
./ecdh_assign2 -o ecdh_output.txt
./ecdh_assign2 -o ecdh_output.txt -a 5f2a... -b a19c... -c "uh...huh"
```

**The output file includes:**
- alice and bob's public keys (not their private ones)  
- their shared secrets and whether they match or not  
- their mac and encryption keys and whether they match or not  

## Task 2 - RSA and Digital signatures (`rsa_assign2.c`)
We used the GMP library to implement RSA key generation, encryption, decryption, signing, verification, as well as time & memory performance analysis for each key length.

**Usage:**
```
rsa_assign2 -g <bits>                         # Generate keys (1024|2048|4096)
rsa_assign2 -i <plaintext.txt> -o <ciphertext.txt> -k <public_bits.key> -e  # Encrypt file
rsa_assign2 -i <ciphertext.txt> -o <decrypted.txt> -k <private_bits.key> -d # Decrypt file
rsa_assign2 -i <in> -o <sig> -k <private_bits.key> -s # Sign file
rsa_assign2 -i <in> -k <public_bits.key> -v <sig>     # Verify signature
rsa_assign2 -a <perf.txt>                     # Run performance test
rsa_assign2 -h                                # Show help
```

the files `private_<bits>.key` and `public_<bits>.key` are the private (n,d) and public (n,e) files.  
They consist of TWO lines. The first line is always n, the second line is always either e or d depending on whether it's the public or private key.  
Two helper functions inside the code are responsible for doing the key reading-to / writing-from the files.  
The plaintext must satisfy the constraint M < n . Encrypting plaintext or decrypting ciphertext which is >n is not supported, since it has not been requested in the assignment.

**Examples of usage:**
```bash
# Key generation
./rsa_assign2 -g 2048

# Encryption / Decryption
./rsa_assign2 -i plain.txt -o cipher.txt -k public_2048.key -e
./rsa_assign2 -i cipher.txt -o decrypted.txt -k private_2048.key -d

# Signing / Verification
./rsa_assign2 -i message.txt -o sign.txt -k private_2048.key -s
./rsa_assign2 -i message.txt -k public_2048.key -v sign.txt

# Performance evaluation
./rsa_assign2 -a performance.txt
```
