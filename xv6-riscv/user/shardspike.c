/**
 * @file shardspike.c
 * @brief Feasibility spike for DistInf shard fetching (L3, increment I1).
 *
 * @details
 * Fetches one byte range of a model checkpoint from the LLM-RFTP weight server
 * straight into a persistent shared-memory segment, then reports the SHA-256 of
 * what landed, how long it took, and how much RAM the node is using.
 *
 * It exists to answer three questions before any pipeline code is written:
 *
 *  1. Does a shard-sized window (~27 MB for one 110M layer) fit in a single
 *     shared-memory segment on a 256 MB node? MAX_PAGES_PER_SEG caps a segment
 *     at ~70 MB, so per-layer segments must stay under that.
 *  2. Is the range arithmetic right, including the head/tail trim when the
 *     window does not start or end on a 512-byte chunk boundary? The host
 *     computes the same range's digest from the file and the two must agree.
 *  3. How fast is LLM-RFTP over the bridge, i.e. how long a worker would spend
 *     downloading its shard before it can serve inference?
 *
 * Usage:
 *   shardspike <file_id> <byte_off> <byte_len> [server_ip] [segment_name] [bulk]
 *
 * `bulk` defaults to 1; pass 0 to leave the transfer subject to the kernel's
 * per-source UDP rate limiter (used by the regression gate as the control case).
 *
 * Example (one 110M layer's worth of bytes, deliberately unaligned):
 *   shardspike 3 28 28311552 10.0.0.1 spike0
 */

#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"
#include "user/ftpclient.h"
#include "user/sha256.h"

/**
 * @brief Parse a dotted-decimal IPv4 address into host byte order.
 * @param s Address text, "a.b.c.d".
 * @return The address in host byte order.
 *
 * @note xv6 has no inet_aton(); this mirrors the parser in distinf.c.
 */
static uint32
parse_ip(const char *s)
{
  uint32 a, b, c, d;

  a = b = c = d = 0;
  while (*s && *s != '.') a = a * 10 + (*s++ - '0');
  if (*s) s++;
  while (*s && *s != '.') b = b * 10 + (*s++ - '0');
  if (*s) s++;
  while (*s && *s != '.') c = c * 10 + (*s++ - '0');
  if (*s) s++;
  while (*s)              d = d * 10 + (*s++ - '0');

  return FTP_IPV4(a, b, c, d);
}

/**
 * @brief Report RAM in use, in bytes and MB.
 */
static void
report_ram(const char *label)
{
  uint64 used = getramused();
  printf("%s: %lu bytes (%lu MB)\n", label, used, used / (1024 * 1024));
}

int
main(int argc, char *argv[])
{
  if (argc < 4) {
    printf("usage: shardspike <file_id> <byte_off> <byte_len> [server_ip] [segment]\n");
    return -1;
  }

  uint8_t file_id = (uint8_t)atoi(argv[1]);
  uint32_t byte_off = (uint32_t)atoi(argv[2]);
  uint32_t byte_len = (uint32_t)atoi(argv[3]);
  uint32 server_ip = argc > 4 ? parse_ip(argv[4]) : FTP_IPV4(10, 0, 0, 1);
  const char *segment = argc > 5 ? argv[5] : "spike0";
  int use_bulk = argc > 6 ? atoi(argv[6]) : 1;

  llm_set_server(server_ip, 0);
  llm_set_bulk(use_bulk);

  printf("shardspike: file=%d window=[%d,%d) len=%d server=%d.%d.%d.%d segment=%s\n",
         file_id, byte_off, byte_off + byte_len, byte_len,
         (server_ip >> 24) & 0xff, (server_ip >> 16) & 0xff,
         (server_ip >> 8) & 0xff, server_ip & 0xff, segment);
  printf("shardspike: bulk flow declaration %s\n", use_bulk ? "on" : "off");

  report_ram("ram before");

  /*
   * Create the segment first and fetch into it, so the window is never resident
   * twice. This is the whole point of llm_fetch_range(): a 27 MB shard assembled
   * in the heap and then copied into shared memory would need 54 MB at once, and
   * the same pattern at whole-checkpoint sizes does not fit on a 256 MB node.
   */
  int shmid = shmget(segment, byte_len, IPC_CREAT | SHM_PERSIST);
  if (shmid < 0) {
    printf("shardspike: FAIL shmget(%s, %d) — segment too large or table full\n",
           segment, byte_len);
    return -1;
  }

  void *shmaddr = shmat(shmid, 0, SHM_RDWR);
  if (shmaddr == (void *)-1) {
    printf("shardspike: FAIL shmat(id=%d)\n", shmid);
    return -1;
  }
  printf("shardspike: segment created (id=%d, %d bytes)\n", shmid, byte_len);
  report_ram("ram after segment");

  int t0 = uptime();
  int r = llm_fetch_range(file_id, (char *)shmaddr, byte_off, byte_len);
  int ticks = uptime() - t0;

  if (r < 0) {
    printf("shardspike: FAIL fetch\n");
    shmdt(shmaddr);
    return -1;
  }

  /* ticks are 10 Hz; report deciseconds without floating point */
  printf("shardspike: fetched %d bytes in %d ticks (%d.%d s)\n",
         byte_len, ticks, ticks / 10, ticks % 10);
  if (ticks > 0)
    printf("shardspike: throughput ~%d KB/s\n", (byte_len / 1024) * 10 / ticks);

  report_ram("ram after fetch");

  unsigned char digest[32];
  char hex[65];
  sha256_hash((unsigned char *)shmaddr, byte_len, digest);
  sha256_to_hex(digest, hex);
  printf("shardspike: sha256=%s\n", hex);
  printf("shardspike: OK\n");

  shmdt(shmaddr);
  return 0;
}
