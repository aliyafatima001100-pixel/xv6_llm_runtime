/**
 * @file testsha.c
 * @brief Test program for validating SHA-256 implementation on buffers of varying sizes.
 *
 * @author @cybermeen
 * @date 26th Nov 2025
 *
 * @details
 * It generates buffers of various sizes,  fills them with deterministic patterns,
 * computes their SHA-256 hashes, and compares the results to precomputed expected
 * hashes. The program tests small, medium, and very large buffers to ensure that
 * the implementation handles different data sizes correctly, including potential
 * edge cases such as partial blocks and memory boundaries.
 *
 * Test coverage includes:
 * - Single-byte buffers
 * - Kilobyte to multi-megabyte buffers
 * - Deterministic patterns to facilitate reproducibility
 */

#include "kernel/types.h"
#include "user.h"
#include "sha256.h"
#include "testutil.h"

 /**
  * @brief Convert two hexadecimal characters into a byte.
  *
  * @param high The high nibble character ('0'-'9', 'a'-'f')
  * @param low The low nibble character ('0'-'9', 'a'-'f')
  * @return BYTE The combined byte value
  */
static BYTE hex_to_byte(char high, char low) {
  BYTE h = (high <= '9') ? high - '0' : (high - 'a' + 10);
  BYTE l = (low <= '9') ? low - '0' : (low - 'a' + 10);
  return (h << 4) | l;
}

/**
 * @brief Convert a 64-character hexadecimal string into a 32-byte array.
 *
 * @param hex Input hexadecimal string (must be 64 chars)
 * @param out Output array of 32 bytes
 */
void hex_to_bytes(const char* hex, BYTE out[32]) {
  for (int i = 0; i < 32; i++) {
    out[i] = hex_to_byte(hex[2 * i], hex[2 * i + 1]);
  }
}

/**
 * @brief Compare two 32-byte SHA-256 hashes for equality.
 *
 * @param h1 First hash
 * @param h2 Second hash
 * @return int 1 if equal, 0 if not
 */
int hashes_equal(BYTE h1[32], BYTE h2[32]) {
  for (int i = 0; i < 32; i++)
    if (h1[i] != h2[i])
      return 0;
  return 1;
}

/**
 * @brief Run a SHA-256 test on a given buffer and compare to expected hash.
 *
 * @param test_num Numeric identifier for the test
 * @param title Title of the test
 * @param buf Pointer to the buffer to hash
 * @param len Length of the buffer in bytes
 * @param expected_hex Expected hash as a hexadecimal string (64 chars)
 * @return int 0 on success, 1 on failure
 */
int run_test_buf(int test_num, char* title, const unsigned char* buf, int len, const char* expected_hex) {
  BYTE hash[32];
  BYTE expected[32];
  char hex_output[65];

  sha256_hash((BYTE*)buf, len, hash);

  hex_to_bytes(expected_hex, expected);

  info(title);
  printf("  Input length: %d bytes\n", len);
  printf("  SHA256: ");
  sha256_print(hash);
  printf("\n");

  if (hashes_equal(hash, expected)) {
    pass("Hash matches expected value\n");
    return 0;
  }
  else {
    sha256_to_hex(hash, hex_output);
    printf("  Computed: %s\n", hex_output);
    printf("  Expected: %s\n", expected_hex);
    failnoex("Hash mismatch\n");
    return 1;
  }
}

/**
 * @brief Main function to run SHA-256 tests on buffers of varying sizes.
 *
 * Allocates buffers, fills them with deterministic patterns, hashes them,
 * and compares results to expected SHA-256 hashes.
 *
 * @return int Always exits with 0 (success) after printing test summary
 */
int main() {
  set_tag("SHA256");
  info("Starting SHA-256 large buffer tests...");
  printf("\n");

  // Buffer sizes to test (in bytes)
  int sizes[] = { 1, 1024, 1048576, 10485760, 20971520, 31457280,
                 41943040, 52428800, 62914560 };

  // Corresponding expected SHA-256 hashes
  char* hashes[] = {
      "4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a",
      "80fa0f6d1caca9aad2b012051399b33bcd1976b145f3f3eea0f7ba10637761b0",
      "d4ddc71d11f7222bd670dabcd29832602b2db542e1070c882386de1ba5d5f082",
      "6f22c2e43af8bc2d16b7666deffd9a4fb99d44284fe3caa69adbaddd247d8250",
      "5fd3b8e177f15e9e56e4e9e6e847541d6176d74dc68a99f1322761e6c88669c9",
      "63228e9d76bf52f9c7f2b19d1e6590bd97df344e2658fac26e717d1d3b92d603",
      "61965ff0d8cc82dad42be150830c4bf4c8663146bb70a44aa3d0c6d551191798",
      "b4f161275d8501d570675ad9f2eee61a1f6aed7883d7ccdcc1db61aa681fbfd2",
      "28d2d813f0e634fe977d8092cb0f0ff5ca3eb9d4db205241f946e3c2745e6807"
  };

  int total = sizeof(sizes) / sizeof(sizes[0]);
  int failures = 0;

  /** @brief Loop through all buffer sizes and run SHA-256 tests */
  for (int t = 0; t < total; t++) {
    int sz = sizes[t];
    unsigned char* buf = (unsigned char*)malloc(sz);
    if (!buf) {
      fail(" Failed to allocate buffer");
      exit(1);
    }

    // Fill buffer with deterministic pattern
    if (sz >= 4) {
      int count = sz / 4;
      int* ibuf = (int*)buf;
      for (int i = 0; i < count; i++)
        ibuf[i] = i + 1;
      for (int i = count * 4; i < sz; i++)
        buf[i] = 0;
    }
    else {
      for (int i = 0; i < sz; i++)
        buf[i] = 1;
    }

    printf("Test %d: Buffer size: %d bytes\n", t + 1, sz);
    failures += run_test_buf(t + 1, "SHA256 buffer test", buf, sz, hashes[t]);
    free(buf);
  }

  return summary(total - failures, total);

}
