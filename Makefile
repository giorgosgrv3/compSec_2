# ===============================
#  Assignment 2 Makefile
# ===============================

CC      = gcc
CFLAGS  = -Wall -O2

# Both executables
TARGETS = ecdh_assign2 rsa_assign2

# Default target
all: $(TARGETS)

# ---- ECDH (uses libsodium) ----
ecdh_assign2: ecdh_assign2.c
	$(CC) $(CFLAGS) -o $@ $< -lsodium

# ---- RSA (uses GMP + libsodium for hashing later) ----
rsa_assign2: rsa_assign2.c
	$(CC) $(CFLAGS) -o $@ $< -lgmp -lsodium -lcrypto

# ---- Clean build outputs ----
clean:
	rm -f $(TARGETS) *.o *.out *.key *.bin *.sig
	rm -f $(filter-out input.txt, $(wildcard *.txt))
