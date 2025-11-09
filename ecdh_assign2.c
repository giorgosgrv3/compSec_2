#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>


int main(int argc, char *argv[]) {
    char *output_file = NULL;
    char *alice_key = NULL;
    char *bob_key = NULL;
    char *context = "ECDH_KDF";  //default context, can also provide it through CLI when runnign the executable

//initializes sodium internal state ---- !! must do here before we do anythign else
    if (sodium_init() < 0) {
    fprintf(stderr, "libsodium initialization has failed .. \n");
    return 1;
}

//set up the usage menu -> gather round arguments one by one
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            output_file = argv[++i];
        } else if (strcmp(argv[i], "-a") == 0 && i + 1 < argc) {
            alice_key = argv[++i];
        } else if (strcmp(argv[i], "-b") == 0 && i + 1 < argc) {
            bob_key = argv[++i];
        } else if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
            context = argv[++i];
        } else if (strcmp(argv[i], "-h") == 0) {
            printf("Usage:\n");
            printf("./ecdh_assign2 -o <output file name> -a <privKeyA> -b <privKeyB> -c context\n");
            return 0;
        }
    }

    if (!output_file) {
        fprintf(stderr, "Error: You must provide -o <output file>\n");
        return 1;
    }

FILE *f = fopen(output_file, "w");
char hex[65]; 


unsigned char alice_priv[crypto_scalarmult_SCALARBYTES]; // crypto_scalarmult_SCALARBYTES is 32 bytes --> 256 bit-keys
unsigned char bob_priv[crypto_scalarmult_SCALARBYTES];

unsigned char alice_public[crypto_scalarmult_BYTES];
unsigned char bob_public[crypto_scalarmult_BYTES];

if (alice_key) { //if alice's PRIVATE key exists, then convert it to binary
    if (alice_key[0] == '0' && (alice_key[1] == 'x' || alice_key[1] == 'X')) 
        { alice_key += 2; } //get rid of the "0x" at the start of the given key, if it exists there
    sodium_hex2bin(alice_priv, sizeof alice_priv,
                   alice_key, strlen(alice_key),
                   NULL, NULL, NULL);
} else { //or if it doesn't then generate it randomly
    randombytes_buf(alice_priv, sizeof alice_priv);
}
//now generate the public one, A=aG
crypto_scalarmult_base(alice_public, alice_priv);


if (bob_key) { //same for bob's PRIVATE key
    if (bob_key[0] == '0' && (bob_key[1] == 'x' || bob_key[1] == 'X')) 
        { bob_key += 2; }
    sodium_hex2bin(bob_priv, sizeof bob_priv,
                   bob_key, strlen(bob_key),
                   NULL, NULL, NULL);
} else {
    randombytes_buf(bob_priv, sizeof bob_priv);
}
//now generate the public one, B = bG
crypto_scalarmult_base(bob_public, bob_priv);

//TO OUTPUT FILE
sodium_bin2hex(hex, sizeof hex, alice_public, sizeof alice_public);
fprintf(f, "Alice's public Key:\n%s\n\n", hex);
sodium_bin2hex(hex, sizeof hex, bob_public, sizeof bob_public);
fprintf(f, "Bob's public Key:\n%s\n\n", hex);


//now we generate the shared secret
unsigned char shared_A[crypto_scalarmult_BYTES];
unsigned char shared_B[crypto_scalarmult_BYTES];

//alice generates her shared secret using her priv key and bob's public
// bob generates his public key using his priv key and alice's public
// sharedA & sharedB should be identical S = aB = Ab
crypto_scalarmult(shared_A, alice_priv, bob_public);
crypto_scalarmult(shared_B, bob_priv, alice_public);

// TO OUTPUT FILE
sodium_bin2hex(hex, sizeof hex, shared_A, sizeof shared_A);
fprintf(f, "Alice's shared secret:\n%s\n\n", hex);
sodium_bin2hex(hex, sizeof hex, shared_B, sizeof shared_B);
fprintf(f, "Bob's shared secret:\n%s\n\n", hex);


//normalize context string to exactly 8 bytes
unsigned char ctx8[crypto_kdf_CONTEXTBYTES] = {0};
strncpy((char *)ctx8, context, crypto_kdf_CONTEXTBYTES);

unsigned char encA[32], macA[32], encB[32], macB[32];

//crypto_kdf_derive_from_key(subkey, subkey_len, subkey_id, context, master_key)
        // subkey & subkey_len : output buffer and its size
        // subkey_id : 64bit integer label we choose to get different keys from the same master key. 0 for encr key, 1 for mac key.
crypto_kdf_derive_from_key(encA, 32, 0, (char*)ctx8, shared_A);
crypto_kdf_derive_from_key(macA, 32, 1, (char*)ctx8, shared_A);

crypto_kdf_derive_from_key(encB, 32, 0, (char*)ctx8, shared_B);
crypto_kdf_derive_from_key(macB, 32, 1, (char*)ctx8, shared_B);



//copypaste kai allagh eswteriko ths fprintf se ola 

if (memcmp(shared_A, shared_B, sizeof shared_A) == 0)
    fprintf(f, "Shared secrets match!\n\n");
else
    fprintf(f, "Shared secrets zzzzon't match!\n\n");


    // TO OUTPUT FILE
sodium_bin2hex(hex, sizeof hex, encA, sizeof encA);
fprintf(f, "Alice's encryption key:\n%s\n\n", hex);
sodium_bin2hex(hex, sizeof hex, encB, sizeof encB);
fprintf(f, "Bob's encryption key:\n%s\n\n", hex);

if (memcmp(encA, encB, sizeof encB) == 0)
    fprintf(f, "encryption keys match!\n\n");
else
    fprintf(f, "encryptiin keys zzzzon't match!\n\n");

// TO OUTPUT FILE
sodium_bin2hex(hex, sizeof hex, macA, sizeof macA);
fprintf(f, "Alice's mac key:\n%s\n\n", hex);
sodium_bin2hex(hex, sizeof hex, macB, sizeof macB);
fprintf(f, "Bob's mac key:\n%s\n\n", hex);

if (memcmp(macA, macB, sizeof macB) == 0)
    fprintf(f, "mac keys match!\n\n");
else
    fprintf(f, "mac keys zzzzon't match!\n\n");



return 0;

}
