/**
 * @file testftp.c
 * @author Hamna Sajid
 * @date 22nd November 2025
 *
 * @brief Test harness for the UDP-based LLM file transfer client.
 *
 * @details
 * This program tests the functionality of the UDP client by fetching
 * model weights and tokenizer files from a server, printing their sizes
 * and SHA-256 hashes for verification.
 */

#include "kernel/types.h"
#include "user.h"
#include "ftpclient.h"
#include "testutil.h"
#include "sha256.h"
#include "xstrlib.h"

 /**
  * @brief Test fetching a file and verifying its hash.
  * @param file_id File identifier (FILE_WEIGHTS or FILE_TOKENIZER).
  * @param file_name Name of the file for logging.
  * @return 0 on success, -1 on failure.
  */
static int test_fetch_file(uint8_t file_id, const char* file_name) {
  int file_size;
  char* file_data;
  char buf[256];
  char hex[65];

  file_data = llm_fetch_file(file_id, &file_size);
  if (!file_data) {
    xsprintf(buf, "Failed to fetch %s", file_name);
    failnoex(" %s", buf);
    return -1;
  }

  xsprintf(buf, "Successfully fetched %s: %d bytes", file_name, file_size);
  pass(" %s", buf);

  /* Verify the hash */
  unsigned char hash[32];

  sha256_hash((unsigned char*)file_data, file_size, hash);

  sha256_to_hex(hash, hex);

  xsprintf(buf, "Final SHA-256: %s", hex);
  info("  %s", buf);

  free(file_data);
  return 0;
}

/**
 * @brief Test harness main() that fetches weights and tokenizer via UDP.
 * @param argc Argument count (unused).
 * @param argv Argument vector (unused).
 * @return Exits with code 0 on success, 1 if any test failed.
 */
int main(int argc, char* argv[]) {
  int failed = 0;

  set_tag("LLMFTP");

  info("Starting LLM file transfer test...");


  if (test_fetch_file(FILE_TOKENIZER, "tokenizer") < 0) failed = 1;

  info("---");

  if (test_fetch_file(FILE_WEIGHTS, "weights") < 0) failed = 1;
  if (failed) fail("LLM file transfer test failed");

  pass("LLM file transfer test completed");
  exit(0);
}
