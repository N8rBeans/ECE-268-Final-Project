#include <string.h> 
#include "sha256.h"

// BITWISE LOGIC MACROS
// For scrambling the bits
#define ROTLEFT(a,b) (((a) << (b)) | ((a) >> (32-(b))))
#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))

// CH (Choose):
// For every bit:
// If x is 1, choose y
// If x is 0, choose z
#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))

// MAJ (Majority):
// Looks at same bit in x, y, and z
// Returns whichever bit (0 or 1) is most common
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

// Specific patterns of rotating and shifting bits
// Ensures that flipping just 1 input bit causes massive changes
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

// CONSTANTS
// Fractional parts of cube roots of first 64 prime numbers
// Chosen to introduce "chaos" or "fake randomness"
static const uint32_t k[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

// CORE COMPRESSION FUNCTION
// Takes 64 byte block of data and uses it to scramble the running 32 byte hash state
static void sha256_transform(SHA256_CTX *ctx, const uint8_t data[]) {
    uint32_t a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

    // STEP 1: Message Schedule Expansion
    // 64 bytes (16 chunks of 32 bits) of input data
    // Pack those 16 chunks into the first 16 slots of array m
    for (i = 0, j = 0; i < 16; ++i, j += 4) {
        m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
    }
        
    // Need 64 chunks for 64 rounds, so expand the 16 chunks into 64 chunks
    for ( ; i < 64; ++i) {
        m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];
    }

    // STEP 2: Initialize Working Variables
    // Copy current hash state into 8 temporary variables (a through h)
    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];

    // STEP 3: 64 Rounds of Scrambling
    // For 64 rounds, we mix the working variables, the prime constants k, and our message chunks m
    for (i = 0; i < 64; ++i) {
        // t1 calculates massive cascade of bit flips based on variables e, f, g, h
        t1 = h + EP1(e) + CH(e,f,g) + k[i] + m[i];
        
        // t2 calculates another cascade based on variables a, b, c
        t2 = EP0(a) + MAJ(a,b,c);
        
        // Shift all the variables down one letter, and inject new t1 and t2 into a and e
        h = g; 
        g = f; 
        f = e; 
        e = d + t1;
        d = c; 
        c = b; 
        b = a; 
        a = t1 + t2;
    }

    // STEP 4: Save State
    // Add scrambled working variables back into main state tracker
    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

// INITIALIZATION
// Starting state is always the fractional parts of the square roots of the first 8 prime numbers
void sha256_init(SHA256_CTX *ctx) {
    ctx->datalen = 0;
    ctx->bitlen = 0;
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
}

// FEEDING DATA
// Feed data into 64 byte buffer
// Every time the buffer hits exactly 64 bytes, stop, run "sha256_transform", empty buffer, and continue
void sha256_update(SHA256_CTX *ctx, const uint8_t data[], size_t len) {
    for (size_t i = 0; i < len; ++i) {
        ctx->data[ctx->datalen] = data[i];
        ctx->datalen++;
        
        // The buffer is full
        if (ctx->datalen == 64) {
            sha256_transform(ctx, ctx->data);
            ctx->bitlen += 512; // 64 bytes = 512 bits
            ctx->datalen = 0; // Reset buffer index
        }
    }
}

// FINISHING THE HASH
// Every message must be multiple of 64 bytes 
// Add mathematical padding to the very end of the message to ensure it fits perfectly
void sha256_final(SHA256_CTX *ctx, uint8_t hash[]) {
    uint32_t i;
    i = ctx->datalen;
    
    // STEP 1: The '1' Bit
    // Always append a single binary '1' (0x80 in hex) to mark the end of real data
    if (ctx->datalen < 56) {
        ctx->data[i++] = 0x80;
        // Pad the rest with zeros until byte 56
        while (i < 56) {
            ctx->data[i++] = 0x00;
        }
    }
    else {
        // If not enough room for length data at the end, pad block, compress it, and make new block just for data
        ctx->data[i++] = 0x80;
        while (i < 64) {
            ctx->data[i++] = 0x00;
        }
        sha256_transform(ctx, ctx->data);
        memset(ctx->data, 0, 56);
    }
    
    // STEP 2: The Length Value
    // Final 8 bytes of block MUST contain the length of the original message in bits
    // Prevents attackers from easily appending data to hash
    ctx->bitlen += ctx->datalen * 8;
    ctx->data[63] = ctx->bitlen; 
    ctx->data[62] = ctx->bitlen >> 8;
    ctx->data[61] = ctx->bitlen >> 16; 
    ctx->data[60] = ctx->bitlen >> 24;
    ctx->data[59] = ctx->bitlen >> 32; 
    ctx->data[58] = ctx->bitlen >> 40;
    ctx->data[57] = ctx->bitlen >> 48; 
    ctx->data[56] = ctx->bitlen >> 56;
    
    // Transform final padded block.
    sha256_transform(ctx, ctx->data);

    // STEP 3: Format the Output
    // Convert 8 32 bit internal state variables back into flat 32 byte array
    for (i = 0; i < 4; ++i) {
        hash[i]      = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 4]  = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 8]  = (ctx->state[2] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0x000000ff;
    }
}

// Simple wrapper function
void sha256(const uint8_t *data, size_t len, uint8_t *hash) {
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, hash);
}