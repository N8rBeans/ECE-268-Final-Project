#ifndef SHA256_H
#define SHA256_H

#include <stdint.h>
#include <stddef.h>

// SHA-256 State Tracker
// For remebering the math between 64 byte chunks of data
typedef struct {
    uint8_t data[64]; // 64 byte buffer to be scramble
    uint32_t datalen; // How many bytes currently in buffer
    unsigned long long bitlen; // Total length of message in bits
    uint32_t state[8]; // 8 32 bit integer "Hash" being built
} SHA256_CTX;

// Core functions to process data in a stream
void sha256_init(SHA256_CTX *ctx);
void sha256_update(SHA256_CTX *ctx, const uint8_t data[], size_t len);
void sha256_final(SHA256_CTX *ctx, uint8_t hash[]);

// Simple wrapper function
void sha256(const uint8_t *data, size_t len, uint8_t *hash);

#endif