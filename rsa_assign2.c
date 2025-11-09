#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gmp.h>
#include <time.h>
#include <sodium.h> 
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

////////////////////////////  HELPER FUNCTIONS  //////////////////////////

static void usage(void) {
    printf(
        "Usage:\n"
        "  rsa_assign2 -g <bits>\n"
        "  rsa_assign2 -i <in> -o <out> -k <key> -e       (encrypt)\n"
        "  rsa_assign2 -i <in> -o <out> -k <key> -d       (decrypt)\n"
        "  rsa_assign2 -i <in> -o <sig> -k <priv> -s      (sign)\n"
        "  rsa_assign2 -i <in> -k <pub> -v <sig>          (verify)\n"
        "  rsa_assign2 -a <perf_out.txt>                  (performance)\n"
        "  rsa_assign2 -h                                  (help)\n"
    );
}

// saves the keys in their proper key files as TWO LINES.
// public key (n,e) and private key (n,d)
// therefore in the key files, line 1 is n, and line 2 is either the exponent n or d.

static void save_key_two_lines(const char *filename, const mpz_t n, const mpz_t exp) {
    // open the file
    FILE *f = fopen(filename, "w");
    if (!f) { 
      perror("fopen"); 
      exit(1); }

    //mpz_get_str converts a GMP very large int into a C string in base 16 (hex).
    //NULL tells GMP to allocate a new string for us using malloc internally.
    char *hn = mpz_get_str(NULL, 16, n);
    char *he = mpz_get_str(NULL, 16, exp);

    //safety measure : if allocation fails for some reason, then just print 0 instead of the key to avoid undefined behavior
    if (hn)
    fprintf(f, "%s\n", hn);
    else
    fprintf(f, "0\n");

    if (he)
    fprintf(f, "%s\n", he);
    else
    fprintf(f, "0\n");

    free(hn);
    free(he);
    fclose(f);
}

//read entire file into memory (binary)
static void read_all(const char *path, unsigned char **buf, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) { perror("fopen input"); exit(1); }
    if (fseek(f, 0, SEEK_END) != 0) { perror("fseek"); exit(1); }
    long sz = ftell(f);
    if (sz < 0) { perror("ftell"); exit(1); }
    rewind(f);
    *len = (size_t)sz;
    *buf = (unsigned char*)malloc(*len ? *len : 1);
    if (!*buf) { perror("malloc"); exit(1); }
    if (*len && fread(*buf, 1, *len, f) != *len) { perror("fread"); exit(1); }
    fclose(f);
}

// write a whole text buffer (null-terminated) to file
static void write_text(const char *path, const char *s) {
    FILE *f = fopen(path, "w");
    if (!f) { perror("fopen output"); exit(1); }
    fputs(s, f);
    fclose(f);
}

// load 2-line key, where line 1 is n, line 2 is e or d
static int load_key_two_lines(const char *filename, mpz_t a, mpz_t b) {
    FILE *f = fopen(filename, "r");
    if (!f) return -1;
    char *line = NULL; size_t cap = 0;
    // line 1
    if (getline(&line, &cap, f) <= 0) { fclose(f); free(line); return -1; }
    line[strcspn(line, "\r\n")] = 0;
    if (mpz_set_str(a, line, 16) != 0) { fclose(f); free(line); return -1; }
    // line 2
    if (getline(&line, &cap, f) <= 0) { fclose(f); free(line); return -1; }
    line[strcspn(line, "\r\n")] = 0;
    if (mpz_set_str(b, line, 16) != 0) { fclose(f); free(line); return -1; }
    fclose(f);
    free(line);
    return 0;
}


////////////////////////////  FUNCTIONS : KEY GEN, ENCRYPT, DECRYPT, SIGN, VERIFY, PERFORMANCE  //////////////////////////

static void keygen(int bits) {

    //set up random number gen, used to generate p,q
    // rs : random state context, will be used whenever we want to generate random numbers
    // initialize rs with GMP's default algorithm for random num generator, and then seed it with the UNIX timestamp

    gmp_randstate_t rs; // context
    gmp_randinit_default(rs); //initialize
    gmp_randseed_ui(rs, (unsigned long)time(NULL)); //seeeeed 

    mpz_t p,q,n,phi,e,d,g,p1,q1; //make all variables we will use as mpz_t : very large ints
    mpz_inits(p,q,n,phi,e,d,g,p1,q1, NULL); //init all vars to 0

    unsigned pbits=bits/2, qbits=bits-pbits;

    while (1) {
    // generate p,q ~ n/2 bits each
    mpz_urandomb(p, rs, pbits);// uniformly random, very large integer (of pbits length) using the random state rs.
    mpz_nextprime(p, p);  //finds the next prime number that's >= p and save it to p
    do {
        mpz_urandomb(q, rs, qbits); //do the same for q
        mpz_nextprime(q, q);
    } while (mpz_cmp(p, q) == 0);// to ensure that p,q are not the same number. IF THEY are, find new q.

    // n=p*q
    mpz_mul(n, p, q); 

    //compute φ(n)= (p-1)(q-1)
    mpz_sub_ui(p1, p, 1);
    mpz_sub_ui(q1, q, 1);
    mpz_mul(phi, p1, q1);

    mpz_set_ui(e, 65537); //set public exponent

    //check gcd(e, φ(n))
    mpz_gcd(g, e, phi);
    if (mpz_cmp_ui(g, 1) == 0) // if gcd = 1, we're good
        break;
    // else regenerate p,q again and repeat the gcd process
}

    // calculates d mod φ(n) = e^-1 and saves it into d if successful.
    // the modular inverse exists only if the gcd=1. therefore if the gcd check succeeded, this shouldn't fail. but life is a mystery, and we live and die alone.
    if (mpz_invert(d, e, phi) == 0) {
        fprintf(stderr, "Failed to invert e modulo phi; regenerate.\n");
        exit(1);
    }

    // write keys: public_<bits>.key has n,e ; private_<bits>.key has n,d
    char pubname[64], privname[64];
    snprintf(pubname, sizeof pubname, "public_%d.key", bits); // bits is the number of bits we request via cli -> 1024/2048/4096
    snprintf(privname, sizeof privname, "private_%d.key", bits);
    save_key_two_lines(pubname, n, e);
    save_key_two_lines(privname, n, d);

    printf("!! generated %d-bit RSA keys: \"%s\", \"%s\"\n", bits, pubname, privname);

    mpz_clears(p,q,n,phi,e,d,g,p1,q1, NULL); //free the mpz_t variables
    gmp_randclear(rs); //and the rng context
}


static void encrypt(const char *in, const char *out, const char *pubkey) {
    mpz_t n, e, M, C;
    mpz_inits(n, e, M, C, NULL);

    // 1. read public key (n,e), abort if it fails
    if (load_key_two_lines(pubkey, n, e)!=0) {
        fprintf(stderr, "Failed to read public key file: %s\n", pubkey);
        exit(1);
    }

    // 2. read input file as raw bytes
    unsigned char *buf = NULL; //buffer in memory to store file's bytes
    size_t len = 0; //number of bytes in the file
    read_all(in, &buf, &len); //write file's bytes into memory buffer

    // 3. convert bytes to a big integer (big-endian), and store into M. 
    mpz_import(M, len, 1 /*most significant word first*/, 1 /*word size=1 byte*/, 1 /*big endian*/, 0 /*nail*/, buf);
    free(buf); //then free buffer since it's no longer needed.

    // 4. ensure that plaitext M < n in bits. if M>n, it must be broken into multiple blocks (we're not doing that for this assignment)
    if (mpz_cmp(M, n) >= 0) {
        fprintf(stderr, "plaintext interpreted as integer M must be < n.\n");
        mpz_clears(n, e, M, C, NULL);
        exit(1);
    }

    // 5. do the encryption : C = M^e mod n
    mpz_powm(C, M, e, n); // C also < n !!

    // 6. write ciphertext as hex, back to the output file we specified in the cli 
    char *hex = mpz_get_str(NULL, 16, C);
    write_text(out, hex);

    free(hex);

    mpz_clears(n, e, M, C, NULL);
}

static void decrypt(const char *in, const char *out, const char *privkey) {
    mpz_t n, d, C, M;
    mpz_inits(n, d, C, M, NULL);

    // 1. read private key (n, d)
    if (load_key_two_lines(privkey, n, d) != 0) {
        fprintf(stderr, "Failed to read private key file: %s\n", privkey);
        exit(1);
    }

    // 2. read ciphertext (hex string form) from file into buffer
    unsigned char *buf = NULL;
    size_t len = 0;
    read_all(in, &buf, &len);

    // convert hex string -> mpz_t C
    buf[len] = '\0';
    if (mpz_set_str(C, (char *)buf, 16) != 0) {
        fprintf(stderr, "Invalid ciphertext hex format.\n");
        free(buf);
        mpz_clears(n, d, C, M, NULL);
        exit(1);
    }
    free(buf);

    // 3. do decryption:  M = C^d mod n
    mpz_powm(M, C, d, n);

    // 4. export M to bytes (big-endian)
    size_t count;
    unsigned char *outbuf = (unsigned char *)mpz_export(NULL, &count, 1, 1, 1, 0, M);

    // 5. write decrypted plaintext bytes to file
    FILE *f = fopen(out, "wb");
    if (!f) { perror("fopen output"); exit(1); }
    if (count && fwrite(outbuf, 1, count, f) != count) { perror("fwrite"); }
    fclose(f);
    free(outbuf);

    mpz_clears(n, d, C, M, NULL);
}

static void sign(const char *in, const char *sig_out, const char *privkey) {

    mpz_t n, d, H, S;
    mpz_inits(n, d, H, S, NULL);

    // load n = modulus, d = private exponent
    if (load_key_two_lines(privkey, n, d) != 0) {
        fprintf(stderr, "Failed to read private key file: %s\n", privkey);
        exit(1);
    }

    
    unsigned char *buf = NULL; 
    size_t len = 0;
    read_all(in, &buf, &len); // read plaintext file into memory (binary)

    // hashing happening 
    // digest = SHA256(plaintext)
    unsigned char digest[32];
    crypto_hash_sha256(digest, buf, (unsigned long long)len);
    free(buf);

    // convert digest (byte array, big-endian) → GMP integer H
    mpz_import(H, sizeof(digest), 1, 1, 1, 0, digest);

    // RSA signature: S = H^d mod n
    // (private-key exponentiation on the hash)
    mpz_powm(S, H, d, n);

    // write signature as hex text
    char *hex = mpz_get_str(NULL, 16, S);
    write_text(sig_out, hex);
    free(hex);

    mpz_clears(n, d, H, S, NULL); //clean upp peoplee
}



static void verify(const char *in, const char *sig, const char *pubkey) {
    mpz_t n, e, S, H, H2;
    mpz_inits(n, e, S, H, H2, NULL);

    // load public key, first line n, second line e
    if (load_key_two_lines(pubkey, n, e) != 0) {
        fprintf(stderr, "Failed to read public key file: %s\n", pubkey);
        exit(1);
    }

    //read the original message and compute SHA-256
    unsigned char *buf = NULL; 
    size_t len = 0;
    read_all(in, &buf, &len);

    unsigned char digest[32]; //256-bit digest
    crypto_hash_sha256(digest, buf, (unsigned long long)len);
    free(buf);

    // convert digest (byte array, big-endian) → GMP integer H
    mpz_import(H, sizeof(digest), 1, 1, 1, 0, digest);

    // read signature file (hex text) and parse into big integer S
    unsigned char *raw = NULL; size_t rlen = 0;
    read_all(sig, &raw, &rlen);
    char *hexsig = (char*)malloc(rlen + 1);
    if (!hexsig) {
         perror("malloc"); exit(1); }


    memcpy(hexsig, raw, rlen);
    hexsig[rlen] = '\0'; //mpz_set_str() needs a null-terminated C string, so we add it.
    free(raw);

    if (mpz_set_str(S, hexsig, 16) != 0) {//it converts a string into an integer, interpreting it in the given base
        fprintf(stderr, "Invalid signature hex format.\n");
        free(hexsig);
        mpz_clears(n, e, S, H, H2, NULL);
        exit(1);
    }
    free(hexsig);

    // recover the signed hash: H2 = S^e mod n
    mpz_powm(H2, S, e, n);

    // compare
    if (mpz_cmp(H, H2) == 0) printf("Signature is VALID\n");
    else                     printf("Signature is INVALID\n");

    mpz_clears(n, e, S, H, H2, NULL);//clean up
}


static void performance(){

    FILE *out_file = fopen("performance.txt", "w");
    if (out_file == NULL){
        fprintf(stderr, "Error! Could not open performance.txt for writing.\n");
        exit(1);        
    }

    printf("Running performance analysis...\n");

    int key_lengths[] = {1024, 2048, 4096};
    int num_lengths = sizeof(key_lengths) / sizeof(key_lengths[0]);

    //Temp files
    char *plaintext_file = "analysis_plaintext.txt";
    char *ciphertext_file = "analysis_cipher.txt";
    char *decrypted_file = "analysis_decrypted.txt";
    char *signature_file = "analysis_sig.sig";

    FILE *pt_file = fopen(plaintext_file, "w");
    if (pt_file == NULL) {
        fprintf(stderr, "Error! Could not create temp plaintext file.\n");
        fclose(out_file);
        exit(1);
    }
    fprintf(pt_file, "dummy file for the performance operation"); 
    fclose(pt_file);

    pid_t pid;
    struct rusage usage;    
    int status;
    double time_taken;
    long peak_mem;

    for (int i = 0; i < num_lengths; i++) {

        int key_len = key_lengths[i];
        char pub_key_file[50];
        char priv_key_file[50];

        sprintf(pub_key_file, "public_%d.key", key_len);
        sprintf(priv_key_file, "private_%d.key", key_len);

        fprintf(out_file, "Key Length: %d bits\n", key_len);

        keygen(key_len);



// We measure per-op by forking a child that runs exactly one operation.
// The parent waits with wait4() to collect the CHILD's rusage:
//   - ru_utime + ru_stime : child's CPU time
//   - ru_maxrss           : child's peak resident set size (KB on Linux)
// We call fflush(out_file) BEFORE fork() to avoid duplicated buffered text.

        //Encryption
        fflush(out_file);
        pid = fork();
        //child runs the op, parent measures
        if (pid == 0) { 
            encrypt(plaintext_file, ciphertext_file, pub_key_file);
            exit(0); 
        } else if (pid > 0) { 
            wait4(pid, &status, 0, &usage); 
            
        
           time_taken = (usage.ru_utime.tv_sec + usage.ru_stime.tv_sec) +
                        (usage.ru_utime.tv_usec + usage.ru_stime.tv_usec) / 1e6;
            
            peak_mem = usage.ru_maxrss; 
            
            fprintf(out_file, "Encryption Time: %.4fs\n", time_taken);
            fprintf(out_file, "Peak Memory Usage (Encryption): %ld KB\n", peak_mem);
        } else {
            fprintf(stderr, "Fork failed!\n");
        }

        //Decryption
        fflush(out_file);
        pid = fork();
        if (pid == 0) { 
            decrypt(ciphertext_file, decrypted_file, priv_key_file);
            exit(0);
        } else if (pid > 0) { 
            wait4(pid, &status, 0, &usage);

            
            time_taken = (usage.ru_utime.tv_sec + usage.ru_stime.tv_sec) +
                        (usage.ru_utime.tv_usec + usage.ru_stime.tv_usec) / 1e6;
            
            peak_mem = usage.ru_maxrss; 
            
            fprintf(out_file, "Decryption Time: %.4fs\n", time_taken);
            fprintf(out_file, "Peak Memory Usage (Decryption): %ld KB\n", peak_mem);
        } else {
            fprintf(stderr, "Fork failed!\n");
        }

        //Signing
        fflush(out_file);
        pid = fork();
        if (pid == 0) { 
            sign(plaintext_file, signature_file, priv_key_file);
            exit(0);
        } else if (pid > 0) { 
            wait4(pid, &status, 0, &usage);

           
            time_taken = (usage.ru_utime.tv_sec + usage.ru_stime.tv_sec) +
                        (usage.ru_utime.tv_usec + usage.ru_stime.tv_usec) / 1e6;
            
            peak_mem = usage.ru_maxrss; 

            fprintf(out_file, "Signing Time: %.4fs\n", time_taken);
            fprintf(out_file, "Peak Memory Usage (Signing): %ld KB\n", peak_mem);
        } else {
            fprintf(stderr, "Fork failed!\n");
        }

        //Verification
        fflush(out_file);
        pid = fork();
        if (pid == 0) { 
            verify(plaintext_file, signature_file, pub_key_file);
            exit(0);
        } else if (pid > 0) { 
            wait4(pid, &status, 0, &usage);

            
            time_taken = (usage.ru_utime.tv_sec + usage.ru_stime.tv_sec) +
                        (usage.ru_utime.tv_usec + usage.ru_stime.tv_usec) / 1e6;
            peak_mem = usage.ru_maxrss; 

            
            fprintf(out_file, "Verification Time: %.4fs\n", time_taken);
            fprintf(out_file, "Peak Memory Usage (Verification): %ld KB\n\n", peak_mem);
        } else {
            fprintf(stderr, "Fork failed!\n");
        }

        //keep workspace clean per iteration
        remove(pub_key_file);
        remove(priv_key_file);
        remove(ciphertext_file);
        remove(decrypted_file);
        remove(signature_file);
    }

    remove(plaintext_file);
    fclose(out_file);

    printf("\nResults saved to performance.txt\n");
}


int main(int argc, char **argv) {
    const char *in=NULL, *out=NULL, *key=NULL, *sig=NULL;
    int do_g=0, do_e=0, do_d=0, do_s=0, do_v=0, do_a=0, bits=0; //flags used for the menu

    if (argc == 1) { usage(); return 0; }

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-i") && i+1 < argc)        in  = argv[++i];
        else if (!strcmp(argv[i], "-o") && i+1 < argc)   out = argv[++i];
        else if (!strcmp(argv[i], "-k") && i+1 < argc)   key = argv[++i];
        else if (!strcmp(argv[i], "-g") && i+1 < argc) { do_g = 1; bits = atoi(argv[++i]); }
        else if (!strcmp(argv[i], "-d"))                 do_d = 1;
        else if (!strcmp(argv[i], "-e"))                 do_e = 1;
        else if (!strcmp(argv[i], "-s"))                 do_s = 1;
        else if (!strcmp(argv[i], "-v") && i+1 < argc) { do_v = 1; sig = argv[++i]; }
        else if (!strcmp(argv[i], "-a") && i+1 < argc) { do_a = 1; out = argv[++i]; }
        else if (!strcmp(argv[i], "-h")) { usage(); return 0; }
        else {
            fprintf(stderr, "Unknown/invalid option: %s\n", argv[i]);
            usage(); return 1;
        }
    }

    // Dispatch according to the assignment rules
    if (do_g) {
        if (bits != 1024 && bits != 2048 && bits != 4096) {
            fprintf(stderr, "Use -g 1024|2048|4096\n"); return 1;
        }
        keygen(bits);
        return 0;
    }
    if (do_e) {
        if (!in || !out || !key) { fprintf(stderr, "Encrypt needs -i -o -k\n"); return 1; }
        encrypt(in, out, key);
        return 0;
    }
    if (do_d) {
        if (!in || !out || !key) { fprintf(stderr, "Decrypt needs -i -o -k\n"); return 1; }
        decrypt(in, out, key);
        return 0;
    }
    if (do_s) {
        if (!in || !out || !key) { fprintf(stderr, "Sign needs -i -o -k (priv)\n"); return 1; }
        sign(in, out, key);
        return 0;
    }
    if (do_v) {
        if (!in || !key || !sig) { fprintf(stderr, "Verify needs -i -k (pub) -v <sig>\n"); return 1; }
        verify(in, sig, key);
        return 0;
    }
    if (do_a) {
        if (!out) { fprintf(stderr, "Performance needs -a <output.txt>\n"); return 1; }
        performance(out);
        return 0;
    }

    usage();
    return 0;
}
