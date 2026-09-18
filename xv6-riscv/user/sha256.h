/**
 * @file sha256.h
 * @brief SHA-256 cryptographic hash function implementation for xv6-riscv
 *
 * @author @cybermeen
 * @date 26th Nov 2025
 *
 * @details
 * This header defines the structures and function prototypes for computing
 * SHA-256 hashes within the xv6-riscv operating system environment. SHA-256
 * is a widely used cryptographic hash function that produces a fixed-size
 * 256-bit (32-byte) digest from an arbitrary-length input. This implementation
 * supports incremental hashing, allowing large messages or files to be processed
 * in chunks, which is essential for memory-constrained environments like xv6.
 *
 * The header provides:
 * - `SHA256_CTX`: Context structure to maintain the state of the hash computation.
 * - `sha256_init()`: Initializes the hashing context.
 * - `sha256_update()`: Updates the hash with a new data block.
 * - `sha256_final()`: Finalizes the hash computation and produces the digest.
 * - `sha256_hash()`: Function to compute hash in one call.
 * - `sha256_transform()`: Low-level function to process a 512-bit block (optional, mostly for internal use).
 * - Utility functions to convert and print the hash in hexadecimal format.
 *
 * This implementation ensures compatibility with standard SHA-256 outputs and
 * allows hashing of files, network streams, or any data that can be processed
 * in memory-limited environments. It is suitable for verifying file integrity,
 * authentication, and other cryptographic applications within xv6-riscv.
 *
 * @note Draws inspiration from https://lucidar.me/en/dev-c-cpp/sha-256-in-c-cpp/
 */

#ifndef SHA256_H
#define SHA256_H

#include "kernel/types.h"
#include "user.h"

 // Basic integer typedefs
typedef unsigned char BYTE;   // 8-bit
typedef uint32 WORD;          // 32-bit (using xv6's uint32)

/**
 * @struct SHA256_CTX
 * @brief SHA-256 context structure
 *
 * @details
 * - state[8]: Internal hash state (a..h)
 * - data[64]: Current 512-bit block being processed
 * - bitlen: Total message length in bits (updated per byte)
 * - datalen: Number of bytes in current data buffer (0-63)
 */
typedef struct {
  uint32 state[8];      // Internal hash state
  uint8 data[64];       // Current block buffer
  uint64 bitlen;        // Total bits processed
  uint8 datalen;        // Bytes in current buffer
} SHA256_CTX;

/**
 * @brief Initialize SHA-256 context
 * @param ctx Pointer to SHA256_CTX to initialize
 */
void sha256_init(SHA256_CTX* ctx);

/**
 * @brief Update SHA-256 hash with new data
 * @param ctx Pointer to SHA256_CTX
 * @param data Input data buffer
 * @param len Length of input data in bytes
 */
void sha256_update(SHA256_CTX* ctx, const BYTE data[], uint32 len);

/**
 * @brief Finalize SHA-256 hash and output digest
 * @param ctx Pointer to SHA256_CTX
 * @param hash Output buffer for 32-byte hash
 */
void sha256_final(SHA256_CTX* ctx, BYTE hash[]);

/**
 * @brief Compute SHA-256 hash in one call
 * @param data Input data buffer
 * @param len Length of input data in bytes
 * @param hash Output buffer for 32-byte hash
 */
void sha256_hash(const BYTE data[], uint32 len, BYTE hash[32]);

/**
 * @brief Process a single 512-bit block (deprecated, for compatibility)
 * @param ctx Pointer to SHA256_CTX
 * @param data 64-byte block to process
 */
void sha256_transform(SHA256_CTX* ctx, const BYTE data[]);

/**
 * @brief Convert 32-byte hash to 64-character hex string
 * @param hash Input hash (32 bytes)
 * @param hex Output buffer (must be at least 65 bytes)
 */
void sha256_to_hex(const BYTE hash[32], char hex[65]);

/**
 * @brief Print 32-byte hash in hexadecimal format
 * @param hash The hash to print (32 bytes)
 */
void sha256_print(const BYTE hash[32]);

#endif // SHA256_H
