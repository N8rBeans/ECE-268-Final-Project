#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include "sha256.cuh"

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

// Hash Combine (CUDA function)
// Merges two 32 byte hashes into a 64 byte array and hashes it back down to 32 bytes
// Used for building Merkle tree branches
__device__ void hash_combine(const uint8_t *left, const uint8_t *right, uint8_t *out) {
    uint8_t buffer[HASH_SIZE * 2];
    memcpy(buffer, left, HASH_SIZE);
    memcpy(buffer + HASH_SIZE, right, HASH_SIZE);
    sha256(buffer, HASH_SIZE * 2, out);
}

// memcmp CPU Equivalent (CUDA function)
__device__ int device_memcmp(const void *s1, const void *s2, size_t n) {
    const uint8_t *p1 = (const uint8_t *)s1;
    const uint8_t *p2 = (const uint8_t *)s2;
    for (size_t i = 0; i < n; i++) {
        if (p1[i] != p2[i]) {
            return p1[i] < p2[i] ? -1 : 1;
        }
    }
    return 0;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
// CORE FUNCTIONS
////////////////////////////////////////////////////////////////////////////////////////////////////

// Hash Chain (CUDA function)
// Hashes input sequentially for a specific number of iterations
__device__ void hash_chain(const uint8_t *input, uint8_t *output, int iterations) {
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

// Checksum Calculation (CUDA function)
// Converts a 32 byte hash into 32 bytes (8 bit) and calculates the checksum
// Prevents attackers from simply hashing forward to forge a signature
__device__ void get_chain_lengths(const uint8_t *msg_hash, uint8_t *chain_lengths) {
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

// LM-OTS Key Generation (CUDA function)
__device__ void lmots_keygen(lmots_key_t *sk, lmots_key_t *pk, uint8_t *master_seed, int leaf_index) {
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

// LM-OTS Signing (CUDA function)
__device__ void lmots_sign(const lmots_key_t *sk, const uint8_t *msg_hash, lmots_key_t *sig) {
    uint8_t chains[LMOTS_LEN];
    get_chain_lengths(msg_hash, chains);
    
    // Hash each block a specific number of times based on the message chunk
    for (int i = 0; i < LMOTS_LEN; i++) {
        hash_chain(sk->blocks[i], sig->blocks[i], chains[i]);
    }
}

// Compress LM-OTS PK (CUDA function)
// Takes 34 block public key and hashes it down to a single 32 byte Merkle leaf
__device__ void compress_lmots_pk(const lmots_key_t *pk, uint8_t *leaf_out) {
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

// Tree Generation 1 (CUDA kernel)
__global__ void lms_generate_leaves(lmots_key_t *sk_array, uint8_t tree[NUM_NODES][HASH_SIZE], uint8_t *master_seed) {
    int tx = threadIdx.x;
    int bx = blockIdx.x;

    int bs = blockDim.x;
    int gs = gridDim.x;

    // Grid stride loop
    for (int i = bx * bs + tx; i < NUM_LEAVES; i += gs * bs) {
        lmots_key_t temp_pk;

        // Pass the master_seed and the current leaf index down to WOTS+
        lmots_keygen(&sk_array[i], &temp_pk, master_seed, i);
        compress_lmots_pk(&temp_pk, tree[NUM_LEAVES + i]);
    }
}

// Tree Generation 2 (CUDA kernel)
__global__ void lms_build_tree_layer(uint8_t tree[NUM_NODES][HASH_SIZE], int num_nodes_in_layer, int offset) {
    int tx = threadIdx.x;
    int bx = blockIdx.x;

    int bs = blockDim.x;
    int gs = gridDim.x;

    // Grid stride loop
    for (int i = bx * bs + tx; i < num_nodes_in_layer; i += gs * bs) {
        int node_idx = offset + i;
        // tree[1] will hold the final Root Hash (LMS Public Key)
        // Hash the two children to create the parent
        hash_combine(tree[2 * node_idx], tree[2 * node_idx + 1], tree[node_idx]);
    }
}

// Signing (CUDA kernel)
__global__ void lms_sign(lmots_key_t *sk_array, uint8_t tree[NUM_NODES][HASH_SIZE], uint32_t index, const uint8_t *msg_hash, lms_signature_t *sig) {
    int tx = threadIdx.x;
    int bx = blockIdx.x;

    int bs = blockDim.x;
    int gs = gridDim.x;

    // Shared memory between threads
    __shared__ uint8_t chains[LMOTS_LEN];

    // Thread 0 sets up metadata and calculates checksum chains
    if (tx == 0) {
        sig->index = index;
        get_chain_lengths(msg_hash, chains);
    }
    // Wait for Thread 0 to finish setup
    __syncthreads();

    // All 34 threads compute their specific blocks hash chain in parallel
    if (tx < LMOTS_LEN) {
        hash_chain(sk_array[index].blocks[tx], sig->lmots_sig.blocks[tx], chains[tx]);
    }

    // Thread 0 collects the auth path 
    // Only 16 items, fast enough serially
    if (tx == 0) {
        int node = NUM_LEAVES + index;
        for (int i = 0; i < HEIGHT; i++) {
            int sibling = (node % 2 == 0) ? (node + 1) : (node - 1);
            memcpy(sig->auth_path[i], tree[sibling], HASH_SIZE);
            node /= 2;
        }
    }
}

// Verification (CUDA kernel)
__global__ void lms_verify(const uint8_t *lms_pk_root, const uint8_t *msg_hash, const lms_signature_t *sig, int *is_valid) {
    int tx = threadIdx.x;
    int bx = blockIdx.x;

    int bs = blockDim.x;
    int gs = gridDim.x;

    // Shared memory so threads can communicate
    __shared__ uint8_t chains[LMOTS_LEN];
    __shared__ lmots_key_t computed_lmots_pk;

    // Thread 0 set up
    if (tx == 0) {
        get_chain_lengths(msg_hash, chains);
    }
    // Wait for Thread 0 to finish setup
    __syncthreads();

    // 1. Rebuild the WOTS public key by hashing the remaining distance to 255
    // All 34 threads rebuild the WOTS public key blocks simultaneously
    if (tx < LMOTS_LEN) {
        int remaining = 255 - chains[tx];
        hash_chain(sig->lmots_sig.blocks[tx], computed_lmots_pk.blocks[tx], remaining);
    }
    // Wait for all 34 blocks to be done
    __syncthreads();

    // Thread 0 handles the Merkle math (it is inherently sequential)
    if (tx == 0) {
        // 2. Compress it to get the presumed Merkle leaf
        uint8_t current_node[HASH_SIZE];
        compress_lmots_pk(&computed_lmots_pk, current_node);

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
        *is_valid = (device_memcmp(current_node, lms_pk_root, HASH_SIZE) == 0);
    }
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
    printf("Allocating %zu MB of Unified GPU memory...\n\n", memory_needed);
          
    lmots_key_t *sk_array;
    cudaMallocManaged(&sk_array, NUM_LEAVES * sizeof(lmots_key_t));
    uint8_t (*tree)[HASH_SIZE];
    cudaMallocManaged(&tree, NUM_NODES * HASH_SIZE);

    lms_signature_t *sig;
    cudaMallocManaged(&sig, sizeof(lms_signature_t));
    uint8_t *master_seed;
    cudaMallocManaged(&master_seed, HASH_SIZE);
    int *is_valid;
    cudaMallocManaged(&is_valid, sizeof(int));
   
    // Generate random seed on CPU to pass to GPU
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
        cudaFree(sk_array);
        cudaFree(tree);
        return 1;
    }

    end_time = get_hw_time();
    printf("\tFile hashing took: %.6f seconds\n\n", end_time - start_time);

    ////////////////////////////////////////////////////////////////////////////////////////////////////

    // Copy file hash to GPU memory using unified memory
    uint8_t *d_msg_hash;
    cudaMallocManaged(&d_msg_hash, HASH_SIZE);
    memcpy(d_msg_hash, file_hash, HASH_SIZE);

    ////////////////////////////////////////////////////////////////////////////////////////////////////

    // Key Generation
    printf("Generating %d leaves (LMS KeyGen)...\n", NUM_LEAVES);

    // Set up CUDA: 256 threads per block
    int threadsPerBlock = 256;
    int blocksPerGrid = (NUM_LEAVES + threadsPerBlock - 1) / threadsPerBlock;

    start_time = get_hw_time();

    // Tree Generation 1
    lms_generate_leaves<<<blocksPerGrid, threadsPerBlock>>>(sk_array, tree, master_seed);
    cudaDeviceSynchronize();
    
    // Tree Generation 2 (Parallel Reduction Loop)
    // Start at the bottom layer (4096 nodes) and halve the nodes every step
    for (int layer_size = NUM_LEAVES / 2; layer_size > 0; layer_size /= 2) {
        int blocks = (layer_size + threadsPerBlock - 1) / threadsPerBlock;
        lms_build_tree_layer<<<blocks, threadsPerBlock>>>(tree, layer_size, layer_size);
        cudaDeviceSynchronize(); 
    }

    end_time = get_hw_time();
    printf("\tKey generation took: %.6f seconds\n\n", end_time - start_time);

    ////////////////////////////////////////////////////////////////////////////////////////////////////

    // Signing
    uint32_t test_index = 0;
    printf("Signing message at index %u...\n", test_index);
    start_time = get_hw_time();

    lms_sign<<<1, LMOTS_LEN>>>(sk_array, tree, test_index, d_msg_hash, sig);
    cudaDeviceSynchronize();

    end_time = get_hw_time();
    printf("\tSigning took: %.6f seconds\n", end_time - start_time);
    printf("\tSignature size: %zu bytes\n\n", sizeof(*sig));

    ////////////////////////////////////////////////////////////////////////////////////////////////////

    // Verification
    printf("Verifying LMS signature...\n");
    start_time = get_hw_time();

    lms_verify<<<1, LMOTS_LEN>>>(tree[1], d_msg_hash, sig, is_valid);
    cudaDeviceSynchronize();

    end_time = get_hw_time();
    if (*is_valid) {
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
    write_hex_file("output/lms_sig.txt", (const uint8_t *)sig, sizeof(*sig));
    printf("\tDone.\n\n");

    // Free memory
    cudaFree(sk_array);
    cudaFree(tree);
    cudaFree(sig);
    cudaFree(master_seed);
    cudaFree(is_valid);
    cudaFree(d_msg_hash);

    return 0;
}