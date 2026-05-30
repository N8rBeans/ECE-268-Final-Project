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

// Lamport Parameters
#define HASH_SIZE 32 // SHA-256 produces a 32 byte (256 bit) message hash
#define NUM_BITS 256 // Must sign every single bit of the 256 bit message hash

////////////////////////////////////////////////////////////////////////////////////////////////////
// STRUCTURES
////////////////////////////////////////////////////////////////////////////////////////////////////

// Structures
// Lamport requires pair of blocks for every bit of the hash (256 bits * 2 blocks)
typedef struct {
    uint8_t blocks[NUM_BITS][2][HASH_SIZE]; // Private keys (random data)
} secret_key_t;

typedef struct {
    uint8_t blocks[NUM_BITS][2][HASH_SIZE]; // Public keys (hashed private keys)
} public_key_t;

typedef struct {
    uint8_t blocks[NUM_BITS][HASH_SIZE]; // The revealed signature (1 block per bit)
} signature_t;

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

// Bit Extraction
// Safely pulls a single bit (0 or 1) from the 32 byte message hash using provided index
__device__ int get_bit(const uint8_t *bytes, int bit_idx) {
    int byte_idx = bit_idx / 8;
    int bit_offset = 7 - (bit_idx % 8); 
    return (bytes[byte_idx] >> bit_offset) & 1;
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

//TODO
// Key Generation
// Fills secret key array with random numbers, then hashes each one once to create public key array
__global__ void keygen(secret_key_t *s, public_key_t *p, uint8_t *master_seed) {

    int tx = threadIdx.x;
    int bx = blockIdx.x;

    int bs = blockDim.x;
    int gs = gridDim.x;

    secret_key_t *sk = &s[bx];
    public_key_t *pk = &p[bx];

    for (int i = tx; i < NUM_BITS; i += bs) {
        for (int j = 0; j < 2; j++) {
            // Hash master_seed + key_index + i + j to pseudo-randomly generate private key
            uint8_t seed_buffer[HASH_SIZE + 12];
            memcpy(seed_buffer, master_seed, HASH_SIZE);
            ((uint32_t*)(seed_buffer + HASH_SIZE))[0] = bx; 
            ((uint32_t*)(seed_buffer + HASH_SIZE))[1] = i; 
            ((uint32_t*)(seed_buffer + HASH_SIZE))[2] = j;

            sha256(seed_buffer, HASH_SIZE + 12, sk->blocks[i][j]);

            // Public key is simply the hash of that private key
            sha256(sk->blocks[i][j], HASH_SIZE, pk->blocks[i][j]);
        }
    }
}

//TODO
// Signing
// Looks at message bit by bit
// If the bit is 0, reveal the first secret block
// If the bit is 1, reveal the second secret block
__global__ void sign_message(const secret_key_t *sk, const uint8_t *msg_hash, signature_t *sig) {

    int tx = threadIdx.x;
    int bx = blockIdx.x;

    int bs = blockDim.x;
    int gs = gridDim.x;

    if (bx == 0 && tx == 0) {
        for (int i = bx * bs + tx; i < NUM_BITS; i += gs * bs) {
            int bit = get_bit(msg_hash, i);
            memcpy(sig->blocks[i], sk->blocks[i][bit], HASH_SIZE);
        }
    }
}

//TODO
// Verification
// Takes blocks provided in the signature, hashes them, and checks if they match the corresponding public key blocks
__global__ void verify_signature(const public_key_t *pk, const uint8_t *msg_hash, const signature_t *sig, int *is_valid) {

    int tx = threadIdx.x;
    int bx = blockIdx.x;

    int bs = blockDim.x;
    int gs = gridDim.x;
    
    if (bx == 0 && tx == 0) {
        uint8_t computed_hash[HASH_SIZE];

        *is_valid = 1;
        for (int i = 0; i < NUM_BITS; i++) {
            int bit = get_bit(msg_hash, i);
            
            // Hash the data the signer gave us
            sha256(sig->blocks[i], HASH_SIZE, computed_hash);
            
            // If it doesnt match the public key, the signature is forged or invalid
            if (device_memcmp(computed_hash, pk->blocks[i][bit], HASH_SIZE) != 0){
                *is_valid = 0;
                break;
            };
        }
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

    printf("Lamport One-Time Signature Benchmark\n\n");

    int num_keys = 65536;
    secret_key_t *sk;
    cudaMallocManaged(&sk, num_keys*sizeof(secret_key_t));
    public_key_t *pk;
    cudaMallocManaged(&pk, num_keys*sizeof(public_key_t));
    signature_t *sig;
    cudaMallocManaged(&sig, sizeof(signature_t));
    uint8_t *master_seed;
    cudaMallocManaged(&master_seed, HASH_SIZE);
    int *is_valid;
    cudaMallocManaged(&is_valid, sizeof(int));

    // Generate random seed on CPU
    for(int i=0; i<HASH_SIZE; i++) {
        master_seed[i] = rand() % 256;
    }

    uint8_t file_hash[HASH_SIZE];
    double start_time, end_time;

    ////////////////////////////////////////////////////////////////////////////////////////////////////

    // Hash the file
    printf("Hashing file: %s...\n", argv[1]);
    start_time = get_hw_time();
    
    if (!get_file_hash(argv[1], file_hash)) {
        //free(sk);
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
    
    printf("Generating %d Lamport key pairs...\n", num_keys);

    int threadsPerBlock = 256;
    int blocksPerGrid = (NUM_BITS + threadsPerBlock - 1) / threadsPerBlock;

    start_time = get_hw_time();

    keygen<<<num_keys, threadsPerBlock>>>(sk, pk, master_seed);
    cudaDeviceSynchronize(); 

    end_time = get_hw_time();
    printf("\tKey generation took: %.6f seconds\n\n", end_time - start_time);

    ////////////////////////////////////////////////////////////////////////////////////////////////////

    // Signing
    printf("Signing the file hash...\n");
    start_time = get_hw_time();

    sign_message<<<1,1>>>(&sk[num_keys - 1], d_msg_hash, sig);
    cudaDeviceSynchronize();

    end_time = get_hw_time();
    printf("\tSigning took: %.6f seconds\n", end_time - start_time);
    printf("\tSignature size: %zu bytes\n\n", sizeof(*sig));

    ////////////////////////////////////////////////////////////////////////////////////////////////////

    // Verifying
    printf("Verifying signature...\n");
    start_time = get_hw_time();

    verify_signature<<<1, 1>>>(&pk[num_keys - 1], d_msg_hash, sig, is_valid);
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
    write_hex_file("output/lamport_hash.txt", file_hash, HASH_SIZE);
    // Cast signature struct to byte array to dump its raw memory
    write_hex_file("output/lamport_sig.txt", (const uint8_t *)sig, sizeof(*sig));
    printf("\tDone.\n\n");

    cudaFree(sk);
    cudaFree(pk);
    cudaFree(sig);
    cudaFree(master_seed);
    cudaFree(is_valid);
    cudaFree(d_msg_hash);

    return 0;
}