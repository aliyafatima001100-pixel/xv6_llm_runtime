/**
 * @file sha256.c
 * @brief SHA-256 cryptographic hash function implementation for xv6-riscv
 *
 * @author @cybermeen
 * @date 26th Nov 2025
 *
 * @details
 * This file provides a full implementation of the SHA-256 hash algorithm
 * optimized for the xv6-riscv operating system. It uses a 16-element rotating
 * buffer technique to minimize stack usage and memory footprint while computing
 * hashes of arbitrary-length messages. The implementation includes functions
 * for:
 * - Initializing the hash context (`sha256_init`)
 * - Incrementally updating the hash with new data (`sha256_update`)
 * - Finalizing the hash computation with proper padding (`sha256_final`)
 * - Converting the resulting 32-byte hash to a hexadecimal string (`sha256_to_hex`)
 * - Printing the hash in human-readable hexadecimal format (`sha256_print`)
 *
 * The algorithm follows the standard SHA-256 specification, handling data
 * in 512-bit (64-byte) blocks. It supports large messages and ensures correct
 * padding, bit-length encoding, and endianness for producing consistent
 * cryptographic digests. This implementation is suitable for file integrity
 * checks, authentication, and other cryptographic operations in resource-limited
 * environments like xv6.
 *
 * @note Draws inspiration from https://lucidar.me/en/dev-c-cpp/sha-256-in-c-cpp/
 */

#include "sha256.h"

 // Rotate right
#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32 - (b))))

// Σ-functions - mixes bits by rotating and shifting
#define SIG0(x) (ROTRIGHT(x,7)  ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

static uint32 STEP1(uint32 e, uint32 f, uint32 g) {
  return (ROTRIGHT(e, 6) ^ ROTRIGHT(e, 11) ^ ROTRIGHT(e, 25)) + ((e & f) ^ ((~e) & g));
}

static uint32 STEP2(uint32 a, uint32 b, uint32 c) {
  return (ROTRIGHT(a, 2) ^ ROTRIGHT(a, 13) ^ ROTRIGHT(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
}

/**
 * @brief Update the message schedule array for SHA-256 block processing.
 * @param m Pointer to the 16-element message schedule array.
 * @param i Current iteration index (0-63).
 * @param buffer Pointer to the 64-byte input block.
 *
 * @details
 * For i < 16, loads big-endian words from buffer.
 * For i >= 16, computes the next word using SIG0 and SIG1 functions.
 */
static inline void update_m(uint32* m, int i, const uint8* buffer) {
  int j;
  for (j = 0; j < 16; j++) {
    if (i < 16) {
      m[j] = ((uint32)buffer[0] << 24) | ((uint32)buffer[1] << 16) |
        ((uint32)buffer[2] << 8) | ((uint32)buffer[3]);
      buffer += 4;
    }
    else {
      uint32 a = m[(j + 1) & 15];
      uint32 b = m[(j + 14) & 15];
      uint32 s0 = (SIG0(a));
      uint32 s1 = (SIG1(b));
      m[j] += m[(j + 9) & 15] + s0 + s1;
    }
  }
}

/**
 * @brief Process a single 512-bit block through the SHA-256 compression function.
 * @param ctx Pointer to SHA256_CTX containing the current state and data block.
 *
 * @details
 * Updates the hash state by processing the current 64-byte data block using
 * the SHA-256 round functions and constants.
 */
static void sha256_block(SHA256_CTX* ctx) {
  // State of the program
  uint32* state = ctx->state;

  // Declare the K constant
  static const uint32 k[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
  };

  uint32 lo[4], hi[4];
  for (int i = 0; i < 4; i++) {
    lo[i] = state[i];
    hi[i] = state[i + 4];
  }

  uint32 m[16];  // Only 16 elements instead of 64!

  int i, j;
  for (i = 0; i < 64; i += 16) {
    update_m(m, i, ctx->data);

    for (j = 0; j < 16; j += 4) {
      uint32 temp;

      /// @todo Merge into a single loop
      temp = hi[3] + STEP1(hi[0], hi[1], hi[2]) + k[i + j + 0] + m[j + 0];
      hi[3] = temp + lo[3];
      lo[3] = temp + STEP2(lo[0], lo[1], lo[2]);

      temp = hi[2] + STEP1(hi[3], hi[0], hi[1]) + k[i + j + 1] + m[j + 1];
      hi[2] = temp + lo[2];
      lo[2] = temp + STEP2(lo[3], lo[0], lo[1]);

      temp = hi[1] + STEP1(hi[2], hi[3], hi[0]) + k[i + j + 2] + m[j + 2];
      hi[1] = temp + lo[1];
      lo[1] = temp + STEP2(lo[2], lo[3], lo[0]);

      temp = hi[0] + STEP1(hi[1], hi[2], hi[3]) + k[i + j + 3] + m[j + 3];
      hi[0] = temp + lo[0];
      lo[0] = temp + STEP2(lo[1], lo[2], lo[3]);
    }
  }

  // Add lo[] back into state
  for (int i = 0; i < 4; i++) {
    state[i] += lo[i];
    state[i + 4] += hi[i];
  }

}

/**
 * @brief Append a single byte to the SHA-256 context data buffer.
 * @param ctx Pointer to SHA256_CTX.
 * @param byte The byte to append.
 *
 * @details
 * Adds the byte to the data buffer and increments bit length.
 * If the buffer becomes full (64 bytes), processes the block.
 */
static void sha256_append_byte(SHA256_CTX* ctx, uint8 byte) {
  ctx->data[ctx->datalen++] = byte;
  ctx->bitlen += 8;

  if (ctx->datalen == 64) {
    ctx->datalen = 0;
    sha256_block(ctx);
  }
}

/**
 * @brief Finalize the SHA-256 hash by padding the message.
 * @param ctx Pointer to SHA256_CTX.
 *
 * @details
 * Appends the padding bit (0x80), zero padding, and the original message
 * length in bits (big-endian) to complete the hash computation.
 */
static void sha256_finalize(SHA256_CTX* ctx) {
  int i;
  uint64 n_bits = ctx->bitlen;  // Save bitlen BEFORE padding

  sha256_append_byte(ctx, 0x80);

  while (ctx->datalen != 56) {
    sha256_append_byte(ctx, 0);
  }

  // Append the saved bit length (big-endian)
  for (i = 7; i >= 0; i--) {
    uint8 byte = (n_bits >> (8 * i)) & 0xff;
    sha256_append_byte(ctx, byte);
  }
}

void sha256_init(SHA256_CTX* ctx) {
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

void sha256_update(SHA256_CTX* ctx, const BYTE data[], uint32 len) {
  uint32 i;
  const uint8* bytes = (const uint8*)data;

  for (i = 0; i < len; i++) {
    sha256_append_byte(ctx, bytes[i]);
  }
}

void sha256_final(SHA256_CTX* ctx, BYTE hash[]) {
  int i, j;
  sha256_finalize(ctx);

  // Convert state to big-endian hash output
  uint8* ptr = (uint8*)hash;
  for (i = 0; i < 8; i++) {
    for (j = 3; j >= 0; j--) {
      *ptr++ = (ctx->state[i] >> (j * 8)) & 0xff;
    }
  }
}

void sha256_hash(const BYTE data[], uint32 len, BYTE hash[32]) {
  SHA256_CTX ctx;
  sha256_init(&ctx);
  sha256_update(&ctx, data, len);
  sha256_final(&ctx, hash);
}

void sha256_to_hex(const BYTE hash[32], char hex[65]) {
  const char hex_chars[] = "0123456789abcdef";
  for (int i = 0; i < 32; i++) {
    hex[i * 2] = hex_chars[(hash[i] >> 4) & 0x0F];
    hex[i * 2 + 1] = hex_chars[hash[i] & 0x0F];
  }
  hex[64] = '\0';
}

void sha256_print(const BYTE hash[32]) {
  for (int i = 0; i < 32; i++) {
    if (hash[i] < 16) printf("0");
    printf("%x", hash[i]);
  }
}
