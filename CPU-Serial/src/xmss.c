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

// WOTS+ Parameters (Layer 1)
#define HASH_SIZE 32 // SHA-256 output size
#define WOTS_LEN 67 // 64 blocks for message + 3 blocks for checksum

// XMSS Parameters (Layer 2)
#define HEIGHT 13 // Merkle tree height
#define NUM_LEAVES (1 << HEIGHT) // 2^HEIGHT
#define NUM_NODES (2 * NUM_LEAVES) // 1 based array requires 2*leaves for full tree

////////////////////////////////////////////////////////////////////////////////////////////////////
// STRUCTURES
////////////////////////////////////////////////////////////////////////////////////////////////////

typedef struct {
    uint8_t blocks[WOTS_LEN][HASH_SIZE]; // A single WOTS+ key contains 67 32 byte blocks
} wots_key_t;

typedef struct {
    uint32_t index; // The leaf index used for this signature
    wots_key_t wots_sig; // WOTS+ signature
    uint8_t auth_path[HEIGHT][HASH_SIZE]; // Sibling nodes required to calculate root
} xmss_signature_t;

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
// Converts a 32 byte hash into 64 nibbles (4 bit) and calculates the checksum
// Prevents attackers from simply hashing forward to forge a signature
void get_chain_lengths(const uint8_t *msg_hash, uint8_t *chain_lengths) {
    int checksum = 0;
    
    // Split 32 bytes into 64 nibbles (4 bit)
    for (int i = 0; i < 32; i++) {
        chain_lengths[2 * i] = msg_hash[i] >> 4;
        chain_lengths[2 * i + 1] = msg_hash[i] & 0x0F;
    }
    
    // Calculate checksum
    // Sum of (15 - chunk_value)
    for (int i = 0; i < 64; i++) {
        checksum += (15 - chain_lengths[i]);
    }
    
    // Append checksum as 3 additional chunks
    // Need to be able to store 64 chunks * 15 = 960
    // Each chunk can only hold max value 15
    // 1 chunk max capacity = 15
    // 2 chunk max capacity = 255
    // 3 chunk max capacity = 4095
    // Use 0x0F mask to only save the bottom 4 bits (nibble)
    chain_lengths[64] = (checksum >> 8) & 0x0F;
    chain_lengths[65] = (checksum >> 4) & 0x0F;
    chain_lengths[66] = checksum & 0x0F;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
// Winternitz OTS Functions
////////////////////////////////////////////////////////////////////////////////////////////////////

// WOTS+ Key Generation
void wots_keygen(wots_key_t *sk, wots_key_t *pk, uint8_t *master_seed, int leaf_index) {
    for (int i = 0; i < WOTS_LEN; i++) {
        // Hash master_seed + leaf_index + chain_id to pseudo-randomly generate private key
        uint8_t seed_buffer[HASH_SIZE + 8]; 
        memcpy(seed_buffer, master_seed, HASH_SIZE);
        ((uint32_t*)(seed_buffer + HASH_SIZE))[0] = leaf_index; // leaf_index
        ((uint32_t*)(seed_buffer + HASH_SIZE))[1] = i; 
        
        sha256(seed_buffer, HASH_SIZE + 8, sk->blocks[i]);
        
        // Public block is the private block chained 15 times
        hash_chain(sk->blocks[i], pk->blocks[i], 15);
    }
}

// WOTS+ Signing
void wots_sign(const wots_key_t *sk, const uint8_t *msg_hash, wots_key_t *sig) {
    uint8_t chains[WOTS_LEN];
    get_chain_lengths(msg_hash, chains);
    
    // Hash each block a specific number of times based on the message chunk
    for (int i = 0; i < WOTS_LEN; i++) {
        hash_chain(sk->blocks[i], sig->blocks[i], chains[i]);
    }
}

// Compress WOTS PK
// Takes 67 block public key and hashes it down to a single 32 byte Merkle leaf
void compress_wots_pk(const wots_key_t *pk, uint8_t *leaf_out) {
    SHA256_CTX ctx;
    sha256_init(&ctx);
    for(int i = 0; i < WOTS_LEN; i++) {
        sha256_update(&ctx, pk->blocks[i], HASH_SIZE);
    }
    sha256_final(&ctx, leaf_out);
}

////////////////////////////////////////////////////////////////////////////////////////////////////
// XMSS Merkle Tree Functions
////////////////////////////////////////////////////////////////////////////////////////////////////

// Tree Generation
void xmss_keygen(wots_key_t *sk_array, uint8_t tree[NUM_NODES][HASH_SIZE], uint8_t *master_seed) {
    wots_key_t temp_pk;
    
    // Generate all leaves
    for (int i = 0; i < NUM_LEAVES; i++) {
        // Pass the master_seed and the current leaf index down to WOTS+
        wots_keygen(&sk_array[i], &temp_pk, master_seed, i);
        compress_wots_pk(&temp_pk, tree[NUM_LEAVES + i]);
    }
    
    // Build tree bottom-up
    // tree[1] will hold the final Root Hash (XMSS Public Key)
    for (int i = NUM_LEAVES - 1; i > 0; i--) {
        hash_combine(tree[2 * i], tree[2 * i + 1], tree[i]);
    }
}

// Signing
void xmss_sign(wots_key_t *sk_array, uint8_t tree[NUM_NODES][HASH_SIZE], uint32_t index, const uint8_t *msg_hash, xmss_signature_t *sig) {
    sig->index = index;
    wots_sign(&sk_array[index], msg_hash, &sig->wots_sig);
    
    // Collect the authentication path (sibling nodes) needed to calculate the root
    int node = NUM_LEAVES + index;
    for (int i = 0; i < HEIGHT; i++) {
        int sibling = (node % 2 == 0) ? (node + 1) : (node - 1);
        memcpy(sig->auth_path[i], tree[sibling], HASH_SIZE);
        node /= 2;
    }
}

// Verification
int xmss_verify(const uint8_t *xmss_pk_root, const uint8_t *msg_hash, const xmss_signature_t *sig) {
    uint8_t chains[WOTS_LEN];
    get_chain_lengths(msg_hash, chains);
    
    wots_key_t computed_wots_pk;
    
    // 1. Rebuild the WOTS public key by hashing the remaining distance to 15
    for (int i = 0; i < WOTS_LEN; i++) {
        int remaining = 15 - chains[i];
        hash_chain(sig->wots_sig.blocks[i], computed_wots_pk.blocks[i], remaining);
    }
    
    // 2. Compress it to get the presumed Merkle leaf
    uint8_t current_node[HASH_SIZE];
    compress_wots_pk(&computed_wots_pk, current_node);
    
    // 3. Follow the authentication path to rebuild the Merkle root
    int node_idx = NUM_LEAVES + sig->index;
    for (int i = 0; i < HEIGHT; i++) {
        if (node_idx % 2 == 0) {
            hash_combine(current_node, sig->auth_path[i], current_node);
        }
        else {
            hash_combine(sig->auth_path[i], current_node, current_node);
        }
        node_idx /= 2;
    }
    
    // 4. If our rebuilt root matches the known public key, the signature is valid
    return (memcmp(current_node, xmss_pk_root, HASH_SIZE) == 0);
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

    printf("XMSS Pipeline Benchmark (Tree Height: %d)\n\n", HEIGHT);

    // RAM allocation for large trees
    size_t memory_needed = ((NUM_LEAVES * sizeof(wots_key_t)) + (NUM_NODES * HASH_SIZE)) / (1024 * 1024);
    printf("Allocating %zu MB of memory...\n\n", memory_needed);
          
    wots_key_t *sk_array = (wots_key_t *)malloc(NUM_LEAVES * sizeof(wots_key_t));
    uint8_t (*tree)[HASH_SIZE] = malloc(NUM_NODES * HASH_SIZE);

    if (!sk_array || !tree) {
        printf("ERROR: Memory allocation failed. Please lower the tree HEIGHT.\n");
        return 1;
    }

    xmss_signature_t sig;
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
    printf("Generating %d leaves (XMSS KeyGen)...\n", NUM_LEAVES);
    start_time = get_hw_time();

    xmss_keygen(sk_array, tree, master_seed);

    end_time = get_hw_time();
    printf("\tKey generation took: %.6f seconds\n\n", end_time - start_time);

    ////////////////////////////////////////////////////////////////////////////////////////////////////

    // Signing
    uint32_t test_index = 0;
    printf("Signing message at index %u...\n", test_index);
    start_time = get_hw_time();

    xmss_sign(sk_array, tree, test_index, file_hash, &sig);

    end_time = get_hw_time();
    printf("\tSigning took: %.6f seconds\n", end_time - start_time);
    printf("\tSignature size: %zu bytes\n\n", sizeof(sig));

    ////////////////////////////////////////////////////////////////////////////////////////////////////

    // Verification
    printf("Verifying XMSS signature...\n");
    start_time = get_hw_time();

    int valid = xmss_verify(tree[1], file_hash, &sig);

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
    write_hex_file("output/xmss_hash.txt", file_hash, HASH_SIZE);
    write_hex_file("output/xmss_public_key_root.txt", tree[1], HASH_SIZE);
    // Cast signature struct to byte array to dump its raw memory
    write_hex_file("output/xmss_sig.txt", (const uint8_t *)&sig, sizeof(sig));
    printf("\tDone.\n\n");

    // Free memory
    free(sk_array);
    free(tree);

    return 0;
}