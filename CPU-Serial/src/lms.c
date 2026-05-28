#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include "sha256.h"

// Precise Hardware Timing
// clock() is too inaccurate on Windows for microsecond measurements
// This function uses the CPU high resolution performance counter
#ifdef _WIN32
#include <windows.h>
double get_hw_time() {
    LARGE_INTEGER frequency, now;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&now);
    return (double)now.QuadPart / frequency.QuadPart;
}
#else
// Backup for Linux/macOS using standard monotonic clock
double get_hw_time() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}
#endif

// LM-OTS Parameters (Layer 1)
#define HASH_SIZE 32 // SHA-256 output size
#define LMOTS_LEN 34 // 32 blocks for message + 2 blocks for checksum

// LMS Parameters (Layer 2)
#define HEIGHT 13 // Merkle tree height
#define NUM_LEAVES (1 << HEIGHT) // 2^HEIGHT
#define NUM_NODES (2 * NUM_LEAVES) // 1 based array requires 2*leaves for full tree

////////////////////////////////////////////////////////////////////////////////////////////////////
// STRUCTURES
////////////////////////////////////////////////////////////////////////////////////////////////////

typedef struct {
    uint8_t blocks[LMOTS_LEN][HASH_SIZE]; // A single LM-OTS key contains 34 32 byte blocks
} lmots_key_t;

typedef struct {
    uint32_t index; // The leaf index used for this signature
    lmots_key_t lmots_sig; // LM-OTS signature
    uint8_t auth_path[HEIGHT][HASH_SIZE]; // Sibling nodes required to calculate root
} lms_signature_t;

////////////////////////////////////////////////////////////////////////////////////////////////////
// HELPER FUNCTIONS
////////////////////////////////////////////////////////////////////////////////////////////////////

// File Hashing
// Reads file into memory in 4KB chunks to avoid loading massive files into RAM all at once
int get_file_hash(const char *filename, uint8_t *hash_out) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        printf("Error: Could not open file '%s'\n", filename);
        return 0; 
    }

    SHA256_CTX ctx;
    sha256_init(&ctx);

    uint8_t buffer[4096];
    size_t bytes_read;

    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        sha256_update(&ctx, buffer, bytes_read);
    }

    sha256_final(&ctx, hash_out);
    fclose(file);
    return 1;
}

// Hex Dump to File
// Writes raw byte data to a text file in readable hexadecimal format
void write_hex_file(const char *filename, const uint8_t *data, size_t len) {
    FILE *f = fopen(filename, "w");
    if (!f) {
        printf("Error: Could not open %s for writing.\n", filename);
        return;
    }
    
    for (size_t i = 0; i < len; i++) {
        fprintf(f, "%02x", data[i]);
        // Add a new line every 32 bytes (64 hex characters) for readability
        if ((i + 1) % 32 == 0) {
            fprintf(f, "\n");
        }
    }
    fclose(f);
}

// Hash Combine
// Merges two 32 byte hashes into a 64 byte array and hashes it back down to 32 bytes
// Used for building Merkle tree branches
void hash_combine(const uint8_t *left, const uint8_t *right, uint8_t *out) {
    uint8_t buffer[HASH_SIZE * 2];
    memcpy(buffer, left, HASH_SIZE);
    memcpy(buffer + HASH_SIZE, right, HASH_SIZE);
    sha256(buffer, HASH_SIZE * 2, out);
}

////////////////////////////////////////////////////////////////////////////////////////////////////
// CORE FUNCTIONS
////////////////////////////////////////////////////////////////////////////////////////////////////

// Hash Chain
// Hashes input sequentially for a specific number of iterations
void hash_chain(const uint8_t *input, uint8_t *output, int iterations) {
    if (iterations == 0) { 
        memcpy(output, input, HASH_SIZE); 
        return; 
    }
    
    uint8_t temp[HASH_SIZE];
    memcpy(temp, input, HASH_SIZE);
    
    for (int i = 0; i < iterations; i++) {
        sha256(temp, HASH_SIZE, temp);
    }
    memcpy(output, temp, HASH_SIZE);
}

// Checksum Calculation
// Converts a 32 byte hash into 32 bytes (8 bit) and calculates the checksum
// Prevents attackers from simply hashing forward to forge a signature
void get_chain_lengths(const uint8_t *msg_hash, uint8_t *chain_lengths) {
    int checksum = 0;
    
    // Split 32 bytes into 32 bytes (8 bit)
    for (int i = 0; i < 32; i++) {
        chain_lengths[i] = msg_hash[i];
    }
    
    // Calculate checksum
    // Sum of (255 - chunk_value)
    for (int i = 0; i < 32; i++) {
        checksum += (255 - chain_lengths[i]);
    }
    
    // Append checksum as 2 additional chunks
    // Need to be able to store 32 chunks * 255 = 8160
    // Each chunk can only hold max value 255
    // 1 chunk max capacity = 255
    // 2 chunk max capacity = 65535
    // Use 0xFF mask to save all 8 bits (byte)
    chain_lengths[32] = (checksum >> 8) & 0xFF;
    chain_lengths[33] = checksum & 0xFF;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
// Leighton-Micali OTS Functions
////////////////////////////////////////////////////////////////////////////////////////////////////

// LM-OTS Key Generation
void lmots_keygen(lmots_key_t *sk, lmots_key_t *pk, uint8_t *master_seed, int leaf_index) {
    for (int i = 0; i < LMOTS_LEN; i++) {
        // Hash master_seed + leaf_index + chain_id to pseudo-randomly generate private key
        uint8_t seed_buffer[HASH_SIZE + 8]; 
        memcpy(seed_buffer, master_seed, HASH_SIZE);
        ((uint32_t*)(seed_buffer + HASH_SIZE))[0] = leaf_index; // leaf_index
        ((uint32_t*)(seed_buffer + HASH_SIZE))[1] = i; 
        
        sha256(seed_buffer, HASH_SIZE + 8, sk->blocks[i]);
        
        // Public block is the private block chained 255 times
        hash_chain(sk->blocks[i], pk->blocks[i], 255);
    }
}

// LM-OTS Signing
void lmots_sign(const lmots_key_t *sk, const uint8_t *msg_hash, lmots_key_t *sig) {
    uint8_t chains[LMOTS_LEN];
    get_chain_lengths(msg_hash, chains);
    
    // Hash each block a specific number of times based on the message chunk
    for (int i = 0; i < LMOTS_LEN; i++) {
        hash_chain(sk->blocks[i], sig->blocks[i], chains[i]);
    }
}

// Compress LM-OTS PK
// Takes 34 block public key and hashes it down to a single 32 byte Merkle leaf
void compress_lmots_pk(const lmots_key_t *pk, uint8_t *leaf_out) {
    SHA256_CTX ctx;
    sha256_init(&ctx);
    for(int i = 0; i < LMOTS_LEN; i++) {
        sha256_update(&ctx, pk->blocks[i], HASH_SIZE);
    }
    sha256_final(&ctx, leaf_out);
}

////////////////////////////////////////////////////////////////////////////////////////////////////
// LMS Merkle Tree Functions
////////////////////////////////////////////////////////////////////////////////////////////////////

// Tree Generation
void lms_keygen(lmots_key_t *sk_array, uint8_t tree[NUM_NODES][HASH_SIZE], uint8_t *master_seed) {
    lmots_key_t temp_pk;
    
    // Generate all leaves
    for (int i = 0; i < NUM_LEAVES; i++) {
        // Pass the master_seed and the current leaf index down to LM-OTS
        lmots_keygen(&sk_array[i], &temp_pk, master_seed, i);
        compress_lmots_pk(&temp_pk, tree[NUM_LEAVES + i]);
    }
    
    // Build tree bottom-up
    // tree[1] will hold the final Root Hash (LMS Public Key)
    for (int i = NUM_LEAVES - 1; i > 0; i--) {
        hash_combine(tree[2 * i], tree[2 * i + 1], tree[i]);
    }
}

// Signing
void lms_sign(lmots_key_t *sk_array, uint8_t tree[NUM_NODES][HASH_SIZE], uint32_t index, const uint8_t *msg_hash, lms_signature_t *sig) {
    sig->index = index;
    lmots_sign(&sk_array[index], msg_hash, &sig->lmots_sig);
    
    // Collect the authentication path (sibling nodes) needed to calculate the root
    int node = NUM_LEAVES + index;
    for (int i = 0; i < HEIGHT; i++) {
        int sibling = (node % 2 == 0) ? (node + 1) : (node - 1);
        memcpy(sig->auth_path[i], tree[sibling], HASH_SIZE);
        node /= 2;
    }
}

// Verification
int lms_verify(const uint8_t *lms_pk_root, const uint8_t *msg_hash, const lms_signature_t *sig) {
    uint8_t chains[LMOTS_LEN];
    get_chain_lengths(msg_hash, chains);
    
    lmots_key_t computed_lmots_pk;
    
    // 1. Rebuild the LM-OTS public key by hashing the remaining distance to 255
    for (int i = 0; i < LMOTS_LEN; i++) {
        int remaining = 255 - chains[i];
        hash_chain(sig->lmots_sig.blocks[i], computed_lmots_pk.blocks[i], remaining);
    }
    
    // 2. Compress it to get the presumed Merkle leaf
    uint8_t current_node[HASH_SIZE];
    compress_lmots_pk(&computed_lmots_pk, current_node);
    
    // 3. Follow the authentication path to rebuild the Merkle root
    int node_idx = NUM_LEAVES + sig->index;
    for (int i = 0; i < HEIGHT; i++) {
        if (node_idx % 2 == 0) {
            hash_combine(current_node, sig->auth_path[i], current_node);
        } else {
            hash_combine(sig->auth_path[i], current_node, current_node);
        }
        node_idx /= 2;
    }
    
    // 4. If our rebuilt root matches the known public key, the signature is valid
    return (memcmp(current_node, lms_pk_root, HASH_SIZE) == 0);
}

////////////////////////////////////////////////////////////////////////////////////////////////////
// MAIN FUNCTION
////////////////////////////////////////////////////////////////////////////////////////////////////

int main(int argc, char *argv[]) {
    //srand((unsigned int)time(NULL));
    srand(12345);

    // Check if user provided file path
    if (argc < 2) {
        printf("Usage: %s <path_to_file>\n", argv[0]);
        printf("Example: %s data/plaintext.txt\n", argv[0]);
        return 1;
    }

    printf("LMS Pipeline Benchmark (Tree Height: %d)\n\n", HEIGHT);

    // RAM allocation for large trees
    size_t memory_needed = ((NUM_LEAVES * sizeof(lmots_key_t)) + (NUM_NODES * HASH_SIZE)) / (1024 * 1024);
    printf("Allocating %zu MB of memory...\n\n", memory_needed);
          
    lmots_key_t *sk_array = (lmots_key_t *)malloc(NUM_LEAVES * sizeof(lmots_key_t));
    uint8_t (*tree)[HASH_SIZE] = malloc(NUM_NODES * HASH_SIZE);

    if (!sk_array || !tree) {
        printf("ERROR: Memory allocation failed. Please lower the tree HEIGHT.\n");
        return 1;
    }

    lms_signature_t sig;
    uint8_t master_seed[HASH_SIZE];

    // Generate random seed on CPU
    for(int i=0; i<HASH_SIZE; i++) {
        master_seed[i] = rand() % 256;
    }

    uint8_t file_hash[HASH_SIZE];
    double start_time, end_time;

    ////////////////////////////////////////////////////////////////////////////////////////////////////

    // File Hashing
    printf("Hashing file: %s...\n", argv[1]);
    start_time = get_hw_time();
    
    if (!get_file_hash(argv[1], file_hash)) {
        free(sk_array);
        free(tree);
        return 1;
    }

    end_time = get_hw_time();
    printf("\tFile hashing took: %.6f seconds\n\n", end_time - start_time);

    ////////////////////////////////////////////////////////////////////////////////////////////////////

    // Key Generation
    printf("Generating %d leaves (LMS KeyGen)...\n", NUM_LEAVES);
    start_time = get_hw_time();

    lms_keygen(sk_array, tree, master_seed);

    end_time = get_hw_time();
    printf("\tKey generation took: %.6f seconds\n\n", end_time - start_time);

    ////////////////////////////////////////////////////////////////////////////////////////////////////

    // Signing
    uint32_t test_index = 0;
    printf("Signing message at index %u...\n", test_index);
    start_time = get_hw_time();

    lms_sign(sk_array, tree, test_index, file_hash, &sig);

    end_time = get_hw_time();
    printf("\tSigning took: %.6f seconds\n", end_time - start_time);
    printf("\tSignature size: %zu bytes\n\n", sizeof(sig));

    ////////////////////////////////////////////////////////////////////////////////////////////////////

    // Verification
    printf("Verifying LMS signature...\n");
    start_time = get_hw_time();

    int valid = lms_verify(tree[1], file_hash, &sig);

    end_time = get_hw_time();
    if (valid) {
        printf("\tResult: SUCCESS (Valid)\n");
    }
    else {
        printf("\tResult: FAIL (Invalid)\n");
    }
    printf("\tVerification took: %.6f seconds\n\n", end_time - start_time);

    ////////////////////////////////////////////////////////////////////////////////////////////////////

    // Write output files
    printf("Exporting files to output directory...\n");
    write_hex_file("output/lms_hash.txt", file_hash, HASH_SIZE);
    write_hex_file("output/lms_public_key_root.txt", tree[1], HASH_SIZE);
    // Cast signature struct to byte array to dump its raw memory
    write_hex_file("output/lms_sig.txt", (const uint8_t *)&sig, sizeof(sig));
    printf("\tDone.\n\n");

    // Free memory
    free(sk_array);
    free(tree);

    return 0;
}