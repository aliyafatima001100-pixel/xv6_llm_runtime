/**
 * @file ftpclient.c
 * @brief User-space UDP client for fetching files from the LLM UDP server.
 * @author Hamna Sajid
 * @date 22nd November 2025
 *
 * @details
 * Implements a simple application-level protocol over UDP used to fetch
 * large files (model weights, tokenizer) from a remote server. The client
 * performs three main operations:
 *  - META_REQ / META_RESP to learn file size, chunk count and expected SHA-256
 *  - DATA_RANGE_REQ to request contiguous ranges of chunks
 *  - RETRANS_REQ to explicitly request retransmission of missing chunks
 *
 * The client reassembles the file from fixed-size chunks, verifies integrity
 * with SHA-256, and returns an allocated buffer containing the file on
 * success. This module is intended to run inside xv6 userland for testing
 * the kernel UDP facilities.
 */

#include "kernel/types.h"
#include "user.h"
#include "ftpclient.h"
#include "sha256.h"

 /**
  * @struct transfer_ctx_t
  * @brief Context tracking an in-progress transfer of a byte window of a file.
  *
  * @details
  * Holds the per-transfer mutable state:
  * - file_buf: caller-supplied destination for the window (never owned here)
  * - received: a per-chunk bitmap over the window (one byte per chunk, 1 = received)
  * - file_size / total_chunks: whole-file metadata from META_RESP
  * - win_off / win_len: the requested byte window, [win_off, win_off + win_len)
  * - first_chunk / n_chunks: the chunks that intersect that window
  * - file_sha256: expected whole-file SHA-256 digest (32 bytes)
  *
  * A whole-file transfer is just the window [0, file_size), for which
  * first_chunk == 0 and n_chunks == total_chunks; every index below is
  * window-relative (chunk_idx - first_chunk) so both cases share one code path.
  *
  * Memory lifecycle:
  * - file_buf belongs to the caller (malloc'd by llm_fetch_file, or a shared
  *   memory segment when streaming) and is never freed here
  * - received is allocated and freed by the transfer function
  */
typedef struct {
  char* file_buf;           // destination buffer for the window (caller-owned)
  char* received;           // bitmap: 1 = chunk received, 0 = missing
  int file_size;
  int total_chunks;
  uint32_t win_off;         // first byte of the requested window
  uint32_t win_len;         // length of the requested window in bytes
  uint32_t first_chunk;     // first chunk index intersecting the window
  uint32_t n_chunks;        // chunks in the window == size of received[]
  unsigned char file_sha256[32];  // Expected SHA-256
} transfer_ctx_t;

/**
 * @brief Receive one datagram with a bounded wait.
 * @param port Bound client port to receive on.
 * @param buf Destination buffer.
 * @param maxlen Size of @p buf in bytes.
 * @return Bytes received (> 0), or -1 if the wait expired.
 *
 * @details
 * The receive loops below used a plain blocking recv(), which wedges the whole
 * transfer forever if every packet of a requested range is lost — there is no
 * other thread to wake it. A bounded wait turns that into an ordinary missing
 * chunk, which the RETRANS_REQ path already knows how to recover.
 */
static int recv_timed(uint16_t port, unsigned char* buf, int maxlen) {
  uint32 src_ip;
  uint16 src_port;

  int len = recvtimeo(port, &src_ip, &src_port, (char*)buf, maxlen, RECV_TIMEOUT_TICKS);
  if (len < 0) return -1;   // -2 = timeout, -1 = error; both mean "nothing arrived"
  return len;
}

/* ----------------------------------------------------------------------------
 * Server endpoint
 *
 * Every request in this file is addressed to this endpoint. It starts at the
 * compile-time default (FTP_SERVER_IP:SERVER_PORT, set per QEMU networking mode
 * by the Makefile) and can be redirected at run time by llm_set_server().
 */
static uint32_t g_server_ip = SERVER_IP;
static uint16_t g_server_port = SERVER_PORT;

/*
 * Whether a transfer declares itself a bulk flow (see llm_fetch_window). On by
 * default; the regression gate turns it off to show that an undeclared flow is
 * still metered by the kernel's token bucket.
 */
static int g_bulk_enabled = 1;

void llm_set_bulk(int enabled) { g_bulk_enabled = enabled; }

/*
 * Optional progress hook, fired between chunk batches during a transfer.
 *
 * A transfer of a multi-megabyte model tensor runs for minutes on the calling
 * thread, blocking it in recv the whole time. The master has no servicing thread
 * (cooperative single-threaded design), so without a chance to run mid-fetch its
 * workers would miss enough heartbeats to age out (EXPIRED_TIMEOUT) before the
 * fetch returned. This hook lets the caller interleave its own soft-state
 * servicing -- the master points it at a non-blocking heartbeat pump. NULL by
 * default and never set by the workers, so their transfers are unaffected.
 */
void (*g_ftp_progress_hook)(void) = 0;

void llm_set_server(uint32_t ip, uint16_t port) {
  g_server_ip = ip;
  if (port != 0) g_server_port = port;
}

uint32_t llm_server_ip(void) { return g_server_ip; }

uint16_t llm_server_port(void) { return g_server_port; }

/**
 * @brief Check whether all chunks in a transfer context have been received.
 * @param ctx Pointer to transfer_ctx_t describing the transfer state.
 * @return 1 if all chunks are received, 0 otherwise.
 *
 * @note Simple linear scan of the received bitmap. Used to determine
 *       whether transfer is complete.
 */
static int all_chunks_received(transfer_ctx_t* ctx) {
  for (uint32_t i = 0; i < ctx->n_chunks; i++) {
    if (!ctx->received[i]) {
      return 0;
    }
  }
  return 1;
}

/**
 * @brief Test whether an absolute chunk index falls inside the transfer window.
 * @param ctx Pointer to transfer_ctx_t.
 * @param chunk_idx Absolute chunk index as it appears on the wire.
 * @return 1 if the index is tracked by this transfer, 0 otherwise.
 */
static int chunk_in_window(transfer_ctx_t* ctx, uint32_t chunk_idx) {
  return chunk_idx >= ctx->first_chunk && chunk_idx < ctx->first_chunk + ctx->n_chunks;
}

/**
 * @brief Count how many chunks are missing in [start, end).
 * @param ctx Pointer to transfer_ctx_t.
 * @param start Inclusive start index (absolute chunk index).
 * @param end Exclusive end index (absolute chunk index).
 * @return Number of missing chunks inside the given range.
 *
 * @note Range is clipped against the transfer window.
 */
static int count_missing_in_range(transfer_ctx_t* ctx, uint32_t start, uint32_t end) {
  int count = 0;
  for (uint32_t i = start; i < end; i++) {
    if (!chunk_in_window(ctx, i)) continue;
    if (!ctx->received[i - ctx->first_chunk]) {
      count++;
    }
  }
  return count;
}

/**
 * @brief Populate an indices array with up to MAX_RETRANS missing chunk indices.
 * @param ctx Pointer to transfer_ctx_t.
 * @param start Inclusive start index.
 * @param end Exclusive end index.
 * @param indices Preallocated array to receive missing indices (caller-supplied).
 * @param count Out parameter set to the number of indices written.
 *
 * @details Writes at most MAX_RETRANS indices. Clips the search to total_chunks.
 */
static void get_missing_in_range(transfer_ctx_t* ctx, uint32_t start, uint32_t end, uint32_t* indices, int* count) {
  *count = 0;
  for (uint32_t i = start; i < end && *count < MAX_RETRANS; i++) {
    if (!chunk_in_window(ctx, i)) continue;
    if (!ctx->received[i - ctx->first_chunk]) {
      indices[(*count)++] = i;
    }
  }
}

int llm_meta_request(uint8_t file_id, uint32_t* file_size, uint32_t* total_chunks, unsigned char* file_hash) {
  // Bind to a random port
  uint16_t port = 10000 + (getpid() % 1000); // Use PID to get somewhat unique port
  if (bind(port) < 0) {
    printf("Failed to bind to port %d\n", port);
    return -1;
  }

  // Prepare META_REQ message
  unsigned char req[4];
  req[0] = MSG_META_REQ;
  req[1] = file_id;
  req[2] = 0; // reserved
  req[3] = 0; // reserved

  // Send request
  if (send(port, g_server_ip, g_server_port, (char*)req, 4) < 0) {
    printf("Failed to send META_REQ\n");
    unbind(port);
    return -1;
  }
  // printf("META_REQ sent, waiting for response...\n");

  // Receive response
  unsigned char resp[48];
  uint32 src_ip;
  uint16 src_port;
  int len = recv(port, &src_ip, &src_port, (char*)resp, sizeof(resp));

  if (len < 48 || resp[0] != MSG_META_RESP) {
    printf("Invalid META_RESP: len=%d, type=%d\n", len, resp[0]);
    unbind(port);
    return -1;
  }

  // Parse META_RESP (big-endian)
  *file_size = (resp[4] << 24) | (resp[5] << 16) | (resp[6] << 8) | resp[7];
  // chunk_size = (resp[8] << 24) | (resp[9] << 16) | (resp[10] << 8) | resp[11]; // Should be 512
  *total_chunks = (resp[12] << 24) | (resp[13] << 16) | (resp[14] << 8) | resp[15];

  // Copy SHA-256 hash
  for (int i = 0; i < 32; i++) {
    file_hash[i] = resp[16 + i];
  }
  unbind(port);
  return 0;
}

int llm_data_range_request(uint8_t file_id, uint32_t start_idx, uint16_t count) {
  uint16_t port = 10000 + (getpid() % 1000);

  // Prepare DATA_RANGE_REQ message
  unsigned char req[12];
  req[0] = MSG_DATA_RANGE_REQ;
  req[1] = file_id;
  req[2] = (count >> 8) & 0xFF;  // big-endian
  req[3] = count & 0xFF;
  req[4] = 0; // reserved
  req[5] = 0;
  req[6] = 0;
  req[7] = 0;
  req[8] = (start_idx >> 24) & 0xFF;
  req[9] = (start_idx >> 16) & 0xFF;
  req[10] = (start_idx >> 8) & 0xFF;
  req[11] = start_idx & 0xFF;

  if (send(port, g_server_ip, g_server_port, (char*)req, 12) < 0) {
    printf("Failed to send DATA_RANGE_REQ\n");
    return -1;
  }

  return 0;
}


int llm_retrans_request(uint8_t file_id, uint32_t* indices, uint16_t count) {
  uint16_t port = 10000 + (getpid() % 1000);

  // Prepare RETRANS_REQ message
  int msg_size = 4 + 4 * count;
  unsigned char* req = malloc(msg_size);
  if (!req) {
    printf("Memory allocation failed for RETRANS_REQ\n");
    return -1;
  }

  req[0] = MSG_RETRANS_REQ;
  req[1] = file_id;
  req[2] = (count >> 8) & 0xFF;
  req[3] = count & 0xFF;

  // Add indices (big-endian)
  for (int i = 0; i < count; i++) {
    int offset = 4 + i * 4;
    req[offset] = (indices[i] >> 24) & 0xFF;
    req[offset + 1] = (indices[i] >> 16) & 0xFF;
    req[offset + 2] = (indices[i] >> 8) & 0xFF;
    req[offset + 3] = indices[i] & 0xFF;
  }

  int result = send(port, g_server_ip, g_server_port, (char*)req, msg_size);
  free(req);

  if (result < 0) {
    printf("Failed to send RETRANS_REQ\n");
    return -1;
  }

  return 0;
}

/**
 * @brief Count how many chunks have been received so far.
 * @param ctx Pointer to transfer_ctx_t.
 * @return Number of chunks that have been successfully received.
 */
static int count_received_chunks(transfer_ctx_t* ctx) {
  int count = 0;
  for (uint32_t i = 0; i < ctx->n_chunks; i++) {
    if (ctx->received[i]) count++;
  }
  return count;
}

/**
 * @brief Parse and process a received DATA_PACKET into transfer context buffer.
 * @param ctx Pointer to the transfer context.
 * @param packet Raw packet bytes received from recv().
 * @param len Length of the received packet in bytes.
 * @return -1 on malformed packet or error,
 *          0 if duplicate packet / already received,
 *          1 if a new chunk was processed successfully.
 *
 * @details
 * Expects packet[0] == MSG_DATA_PACKET, header fields are big-endian.
 *
 * The chunk carries file bytes [chunk_idx * CHUNK_SIZE, + payload_len); only the
 * part of it that intersects the requested window is copied, so the first and
 * last chunk of a range are trimmed here rather than in a bounce buffer.
 *
 * Checks performed:
 *   1. Datagram is long enough to hold the 12-byte header.
 *   2. Message type is MSG_DATA_PACKET.
 *   3. Chunk index is inside the file and inside this transfer's window.
 *   4. Declared payload_len does not exceed the bytes actually delivered
 *      (the RFC 1122 §1.2.2 declared-vs-actual rule, applied to this protocol).
 *   5. The chunk does not claim to extend past the end of the file.
 *   6. Duplicates are ignored rather than re-copied.
 *   7. The copy is clipped to the window on both ends, so no write can land
 *      outside file_buf[0, win_len).
 */
static int process_data_packet(transfer_ctx_t* ctx, unsigned char* packet, int len) {
  if (len < 12) return -1; // Too short

  if (packet[0] != MSG_DATA_PACKET) return -1; // Wrong message type

  // Parse header (big-endian)
  uint32_t chunk_idx = (packet[4] << 24) | (packet[5] << 16) | (packet[6] << 8) | packet[7];
  uint16_t payload_len = (packet[8] << 8) | packet[9];

  if (chunk_idx >= ctx->total_chunks) return -1; // Invalid chunk index
  if (!chunk_in_window(ctx, chunk_idx)) return -1; // Outside the requested window
  if (len < 12 + payload_len) return -1; // Packet too short for claimed payload

  uint32_t chunk_start = chunk_idx * CHUNK_SIZE;
  if (chunk_start + payload_len > ctx->file_size) return -1; // Claims to run past EOF

  if (ctx->received[chunk_idx - ctx->first_chunk]) return 0; // Duplicate, but not an error

  // Intersect the chunk's byte span with the requested window
  uint32_t chunk_end = chunk_start + payload_len;
  uint32_t win_end = ctx->win_off + ctx->win_len;
  uint32_t copy_start = chunk_start > ctx->win_off ? chunk_start : ctx->win_off;
  uint32_t copy_end = chunk_end < win_end ? chunk_end : win_end;

  if (copy_start < copy_end) {
    uint32_t src_off = copy_start - chunk_start;   // offset inside this chunk
    uint32_t dst_off = copy_start - ctx->win_off;  // offset inside the window
    memcpy(ctx->file_buf + dst_off, packet + 12 + src_off, copy_end - copy_start);
  }

  // Mark as received
  ctx->received[chunk_idx - ctx->first_chunk] = 1;

  return 1; // Successfully processed new chunk
}


/**
 * @brief Request a range of chunks and receive responses.
 * @param ctx Pointer to transfer_ctx_t.
 * @param file_id File identifier for the request.
 * @param start_idx Starting chunk index.
 * @param count Number of chunks to request.
 * @param client_port Port to receive on.
 * @param attempt Current retry attempt number (for display).
 * @return Number of new chunks received in this batch.
 */
static int request_chunk_range(transfer_ctx_t* ctx, uint8_t file_id, uint32_t start_idx, uint16_t count, uint16_t client_port, int attempt) {
  // Skip if all chunks in this range are already received
  if (count_missing_in_range(ctx, start_idx, start_idx + count) == 0) {
    return 0;
  }

  if (llm_data_range_request(file_id, start_idx, count) < 0) {
    printf("Failed to request chunks %d-%d\n", start_idx, start_idx + count - 1);
    return 0;
  }

  int new_chunks = 0;
  int idle = 0;

  // Receive and process packets
  for (int spins = 0; spins < MAX_RECEIVE_SPINS / 10; spins++) {
    unsigned char buffer[12 + CHUNK_SIZE];

    int len = recv_timed(client_port, buffer, sizeof(buffer));
    if (len > 0) {
      idle = 0;
      if (process_data_packet(ctx, buffer, len) == 1) new_chunks++;
    } else if (++idle >= MAX_IDLE_RECVS) {
      // Nothing is arriving for this range; leave the rest to the RETRANS pass
      break;
    }

    // Early exit if we've received all chunks in this range
    if (count_missing_in_range(ctx, start_idx, start_idx + count) == 0) {
      break;
    }
  }

  return new_chunks;
}

/**
 * @brief Request retransmission of specific missing chunks.
 * @param ctx Pointer to transfer_ctx_t.
 * @param file_id File identifier.
 * @param client_port Port to receive on.
 * @return Number of chunks successfully retransmitted.
 */
static int handle_missing_chunks(transfer_ctx_t* ctx, uint8_t file_id, uint16_t client_port) {
  int total_recovered = 0;
  uint32_t missing_indices[MAX_RETRANS];
  int missing_count;

  uint32_t win_end = ctx->first_chunk + ctx->n_chunks;
  for (uint32_t start = ctx->first_chunk; start < win_end; start += MAX_RETRANS) {
    get_missing_in_range(ctx, start, start + MAX_RETRANS, missing_indices, &missing_count);

    if (missing_count > 0) {
      // printf("\nRequesting retransmission of %d missing chunks...", missing_count);

      if (llm_retrans_request(file_id, missing_indices, missing_count) == 0) {
        int idle = 0;

        // Receive retransmitted packets
        for (int spins = 0; spins < MAX_RECEIVE_SPINS / 10; spins++) {
          unsigned char buffer[12 + CHUNK_SIZE];

          int len = recv_timed(client_port, buffer, sizeof(buffer));
          if (len > 0) {
            idle = 0;
            int result = process_data_packet(ctx, buffer, len);
            if (result == 1) total_recovered++;
          } else if (++idle >= MAX_IDLE_RECVS) {
            break;  // give up on this batch; the outer retry round will revisit it
          }

          // Check if we've received all requested retransmissions
          int still_missing = 0;
          for (int i = 0; i < missing_count; i++) {
            if (!ctx->received[missing_indices[i] - ctx->first_chunk]) {
              still_missing = 1;
              break;
            }
          }
          if (!still_missing) break;
        }
      }
    }
  }

  return total_recovered;
}

/**
 * @brief Verify file integrity using SHA-256.
 * @param file_buf Buffer containing the complete file data.
 * @param file_size Size of the file in bytes.
 * @param expected_hash Expected SHA-256 hash (32 bytes).
 * @return 1 if hash matches, 0 otherwise.
 */
static int verify_file_integrity(char* file_buf, int file_size, unsigned char* expected_hash) {
  unsigned char computed_hash[32];

  sha256_hash((unsigned char*)file_buf, file_size, computed_hash);

  if (memcmp(computed_hash, expected_hash, 32) != 0) {
    // print the hash
    char hex[65];
    sha256_to_hex(computed_hash, hex);
    printf("Computed SHA-256: %s\n", hex);
    sha256_to_hex(expected_hash, hex);
    printf("Expected SHA-256: %s\n", hex);
    return 0; // Hash mismatch
  }

  return 1; // Hash matches
}

/**
 * @brief Fetch a byte window of a file into a caller-supplied buffer.
 * @param file_id File identifier (FILE_WEIGHTS or FILE_TOKENIZER).
 * @param dst Destination buffer, at least @p byte_len bytes.
 * @param byte_off First file byte to fetch.
 * @param byte_len Number of bytes to fetch; 0 means "to the end of the file".
 * @param size_out Optional out parameter receiving the whole file's size.
 * @return 0 on success, -1 on failure.
 *
 * @details
 * The core transfer routine; llm_fetch_file() and llm_fetch_range() are both
 * thin wrappers over it. Writing straight into a caller-supplied buffer is what
 * lets a caller stream into a shared-memory segment instead of assembling the
 * file in the heap first and copying it in — at model-weight sizes that copy
 * doubles peak RAM and does not fit in a 256 MB node.
 *
 * Transfer process:
 * 1. Request metadata (file size, chunk count, expected hash)
 * 2. Request the chunks intersecting the window, in batches of MAX_RANGE
 * 3. If chunks are missing, retry with RETRANS_REQ (up to MAX_RETRY_ROUNDS)
 * 4. Verify SHA-256 when the window is the whole file (see @note)
 *
 * Checks performed:
 *   1. META_RESP must be obtained before anything is requested.
 *   2. The window must lie inside the file ([EINVAL]-style failure otherwise).
 *   3. The per-chunk bitmap allocation must succeed.
 *   4. Every chunk intersecting the window must arrive, or the transfer fails
 *      rather than returning a partially-filled buffer.
 *
 * @note
 * The server's META_RESP carries a digest of the *whole file*, so integrity can
 * only be verified end-to-end for a whole-file transfer. A partial window is
 * covered by chunk-completeness accounting plus the UDP checksum (RFC 768),
 * which the hardened receive path already validates; a per-range digest would
 * need a protocol extension and is left as future work.
 */
int llm_fetch_window(uint8_t file_id, char* dst, uint32_t byte_off, uint32_t byte_len,
                     uint32_t* size_out) {
  uint32_t file_size, total_chunks;
  unsigned char expected_hash[32];
  transfer_ctx_t ctx;
  uint16_t client_port = 10000 + (getpid() % 1000);

  if (!dst) return -1;

  // Step 1: Request metadata
  if (llm_meta_request(file_id, &file_size, &total_chunks, expected_hash) < 0) {
    printf("Failed to get file metadata\n");
    return -1;
  }

  if (size_out) *size_out = file_size;

  if (byte_len == 0) byte_len = file_size - byte_off;
  if (byte_off >= file_size || byte_off + byte_len > file_size) {
    printf("Requested window [%d,%d) lies outside the %d-byte file\n",
           byte_off, byte_off + byte_len, file_size);
    return -1;
  }

  ctx.file_buf = dst;
  ctx.file_size = file_size;
  ctx.total_chunks = total_chunks;
  ctx.win_off = byte_off;
  ctx.win_len = byte_len;
  ctx.first_chunk = byte_off / CHUNK_SIZE;
  ctx.n_chunks = ((byte_off + byte_len + CHUNK_SIZE - 1) / CHUNK_SIZE) - ctx.first_chunk;
  memcpy(ctx.file_sha256, expected_hash, 32);

  ctx.received = malloc(ctx.n_chunks);
  if (!ctx.received) {
    printf("Memory allocation failed\n");
    return -1;
  }
  for (uint32_t i = 0; i < ctx.n_chunks; i++) ctx.received[i] = 0;

  // Bind to client port for receiving
  if (bind(client_port) < 0) {
    printf("Failed to bind to port %d\n", client_port);
    free(ctx.received);
    return -1;
  }

  /*
   * Declare this transfer a bulk flow from the weight server.
   *
   * Without it the kernel's per-source token bucket (UDP_RL_BURST, refilled one
   * token per tick) admits roughly ten datagrams a second, so a 512-byte-chunk
   * transfer of a model shard would take hours and most chunks would be dropped
   * and re-requested. The exemption covers only this port and only datagrams
   * from the server we are talking to; a flood from anywhere else is still
   * metered. Best-effort: if the process lacks CAP_NET_ADMIN the transfer still
   * works, just at the metered rate.
   */
  if (g_bulk_enabled)
    udp_bulk(client_port, g_server_ip);

  // Step 2: Request the window's chunks in batches
  uint32_t win_end_chunk = ctx.first_chunk + ctx.n_chunks;
  for (uint32_t start_idx = ctx.first_chunk; start_idx < win_end_chunk; start_idx += MAX_RANGE) {
    uint16_t count = (start_idx + MAX_RANGE > win_end_chunk) ?
      (win_end_chunk - start_idx) : MAX_RANGE;

    request_chunk_range(&ctx, file_id, start_idx, count, client_port, 1);
    if (g_ftp_progress_hook) g_ftp_progress_hook();   // let the caller service soft state
  }

  // Step 3: Retransmit missing chunks until the transfer completes.
  //
  // Keep retrying while progress is being made -- a large fetch under loss can
  // need many rounds to recover its last stragglers, and each round re-requests
  // only the still-missing chunks (RETRANS_REQ), so it is cheap. Stop when
  // RETRANS_STALL_LIMIT consecutive rounds recover nothing (a chunk the server
  // cannot deliver, or a dead link) so the transfer fails cleanly instead of
  // spinning forever; MAX_RETRY_ROUNDS is a hard backstop.
  int round = 0;
  int stalled = 0;
  while (!all_chunks_received(&ctx) &&
         stalled < RETRANS_STALL_LIMIT &&
         round < MAX_RETRY_ROUNDS) {
    int before = count_received_chunks(&ctx);
    handle_missing_chunks(&ctx, file_id, client_port);
    int after = count_received_chunks(&ctx);
    stalled = (after > before) ? 0 : stalled + 1;
    round++;
    if (g_ftp_progress_hook) g_ftp_progress_hook();   // let the caller service soft state
  }

  if (!all_chunks_received(&ctx)) {
    int got = count_received_chunks(&ctx);
    printf("Transfer failed: received only %d/%d chunks after %d rounds\n",
           got, ctx.n_chunks, round);
    unbind(client_port);
    free(ctx.received);
    return -1;
  }

  // Step 4: Verify integrity — only meaningful for a whole-file window
  if (byte_off == 0 && byte_len == file_size &&
      !verify_file_integrity(dst, file_size, expected_hash)) {
    printf("SHA-256 verification failed!\n");
    unbind(client_port);
    free(ctx.received);
    return -1;
  }

  unbind(client_port);
  free(ctx.received);
  return 0;
}

int llm_fetch_range(uint8_t file_id, char* dst, uint32_t byte_off, uint32_t byte_len) {
  if (byte_len == 0) return -1;   // an empty range is a caller bug, not "to EOF"
  return llm_fetch_window(file_id, dst, byte_off, byte_len, 0);
}

int llm_fetch_file_into(uint8_t file_id, char* dst, uint32_t dst_len, uint32_t* size_out) {
  uint32_t file_size, total_chunks;
  unsigned char expected_hash[32];

  // Learn the size first so the destination can be bounds-checked before any
  // data lands in it.
  if (llm_meta_request(file_id, &file_size, &total_chunks, expected_hash) < 0) {
    printf("Failed to get file metadata\n");
    return -1;
  }
  if (size_out) *size_out = file_size;

  if (file_size > dst_len) {
    printf("Destination too small: file is %d bytes, buffer is %d\n", file_size, dst_len);
    return -1;
  }

  return llm_fetch_window(file_id, dst, 0, file_size, 0);
}

/**
 * @brief Main file transfer function - fetches a whole file into a new buffer.
 * @param file_id File identifier (FILE_WEIGHTS or FILE_TOKENIZER).
 * @param size_out Output parameter for file size.
 * @return Pointer to allocated file buffer on success, NULL on failure.
 *
 * @details
 * Convenience wrapper over llm_fetch_window() for callers that want the whole
 * file and are happy to pay for a heap buffer. Callers that already have a
 * destination (a shared-memory segment, say) should use llm_fetch_file_into()
 * and avoid the second copy entirely.
 *
 * Caller must free() the returned buffer.
 */
char* llm_fetch_file(uint8_t file_id, int* size_out) {
  uint32_t file_size, total_chunks;
  unsigned char expected_hash[32];

  if (llm_meta_request(file_id, &file_size, &total_chunks, expected_hash) < 0) {
    printf("Failed to get file metadata\n");
    return 0;
  }

  char* buf = malloc(file_size);
  if (!buf) {
    printf("Memory allocation failed\n");
    return 0;
  }

  if (llm_fetch_window(file_id, buf, 0, file_size, 0) < 0) {
    free(buf);
    return 0;
  }

  *size_out = file_size;
  return buf;
}

// LLM-specific wrapper functions
char* fetch_model_weights(int* size_out) {
  // printf("Fetching model weights (stories15M.bin)...\n");
  return llm_fetch_file(FILE_WEIGHTS, size_out);
}

char* fetch_tokenizer(int* size_out) {
  // printf("Fetching tokenizer (tokenizer.bin)...\n");
  return llm_fetch_file(FILE_TOKENIZER, size_out);
}

