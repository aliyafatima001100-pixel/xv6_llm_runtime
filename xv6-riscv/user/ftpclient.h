/**
 * @file ftpclient.h
 * @author Hamna Sajid
 * @date 22nd November 2025
 * 
 * @brief Public API and protocol constants for the user-space LLM UDP client.
 *
 * @details
 * This header exposes the simple application-level protocol used by the UDP
 * client (ftpclient.c). It provides:
 *  - high-level functions to fetch files from the server (llm_fetch_file and wrappers)
 *  - low-level protocol operations (META/DATA/RETRANS requests)
 *  - protocol message type and size constants
 *  - file identifier constants used by the server
 *
 * All multi-byte fields in wire messages are encoded in big-endian (network) order.
 */

#ifndef FTPCLIENT_H
#define FTPCLIENT_H

#include "kernel/types.h"
#include <stdint.h>

/**
 * @brief Send META_REQ and parse META_RESP from server.
 * @param file_id File identifier to query.
 * @param file_size Out parameter for total file size in bytes.
 * @param total_chunks Out parameter for number of chunks.
 * @param file_hash Out buffer (32 bytes) to receive expected SHA-256 hash.
 * @return 0 on success, -1 on failure.
 *
 * @protocol
 * Sends a 4-byte META_REQ and expects a 48-byte META_RESP. Fields are parsed
 * as big-endian per-wire format.
 *
 * @details
 * Returns -1 if send/recv fail, response length is unexpected, or response type
 * doesn't match MSG_META_RESP.
 */
int llm_meta_request(uint8_t file_id, uint32_t *file_size, uint32_t *total_chunks, unsigned char *file_hash);

/**
 * @brief Request a contiguous range of chunks from the server.
 * @param file_id File identifier.
 * @param start_idx Starting chunk index (0-based).
 * @param count Number of chunks requested (16-bit).
 * @return 0 on success, -1 on failure.
 *
 * @details Sends a DATA_RANGE_REQ. All multi-byte fields are encoded in
 * big-endian (network) order.
 */
int llm_data_range_request(uint8_t file_id, uint32_t start_idx, uint16_t count);

/**
 * @brief Request retransmission for specific missing chunk indices.
 * @param file_id File identifier.
 * @param indices Array of chunk indices to retransmit (host order).
 * @param count Number of indices in the array (<= MAX_RETRANS).
 * @return 0 on success, -1 on failure.
 *
 * @details Constructs a RETRANS_REQ containing count 32-bit big-endian indices.
 */
int llm_retrans_request(uint8_t file_id, uint32_t *indices, uint16_t count);

/**
 * @brief Fetch a complete file from server using the LLM UDP protocol.
 * @param file_id ID of the file to fetch (FILE_WEIGHTS, FILE_TOKENIZER, etc).
 * @param size_out Out parameter receiving the total file size in bytes on success.
 * @return Pointer to malloc'd buffer containing file contents on success (caller must free),
 *         NULL (0) on failure.
 *
 * @details
 * Implements the full file transfer workflow:
 * 1. META_REQ to obtain file_size, total_chunks and expected SHA-256
 * 2. Iteratively request ranges with DATA_RANGE_REQ and process incoming DATA_PACKETs
 * 3. Use RETRANS_REQ to request specific missing chunks
 * 4. On completion, verify SHA-256 and return assembled buffer
 *
 * @note
 * Uses bounded retries (MAX_RETRY_ROUNDS) and per-range/backoff receive spins
 * to handle packet loss. Performs input validation and memory checks.
 */
char* llm_fetch_file(uint8_t file_id, int *size_out);

/**
 * @brief Fetch a byte window of a file into a caller-supplied buffer.
 * @param file_id File identifier to fetch from.
 * @param dst Destination buffer of at least @p byte_len bytes.
 * @param byte_off First file byte to fetch.
 * @param byte_len Bytes to fetch; 0 means "through the end of the file".
 * @param size_out Optional out parameter receiving the whole file's size.
 * @return 0 on success, -1 on failure.
 *
 * @details
 * The core transfer routine behind llm_fetch_file(), llm_fetch_range() and
 * llm_fetch_file_into(). Only the chunks intersecting the window are requested,
 * and the first/last chunk are trimmed to the window as they arrive.
 *
 * @note
 * SHA-256 is verified only when the window covers the whole file — META_RESP
 * carries a whole-file digest. A partial window relies on chunk-completeness
 * accounting plus the UDP checksum (RFC 768).
 */
int llm_fetch_window(uint8_t file_id, char *dst, uint32_t byte_off, uint32_t byte_len,
                     uint32_t *size_out);

/**
 * @brief Fetch a contiguous byte range of a file into a caller-supplied buffer.
 * @param file_id File identifier to fetch from.
 * @param dst Destination buffer of at least @p byte_len bytes.
 * @param byte_off First file byte to fetch.
 * @param byte_len Number of bytes to fetch (must be non-zero).
 * @return 0 on success, -1 on failure.
 *
 * @details
 * The shard-fetch primitive: a node that owns part of a model requests only the
 * byte ranges holding its own tensors instead of the entire checkpoint.
 */
int llm_fetch_range(uint8_t file_id, char *dst, uint32_t byte_off, uint32_t byte_len);

/**
 * @brief Fetch an entire file directly into a caller-supplied buffer.
 * @param file_id File identifier to fetch from.
 * @param dst Destination buffer.
 * @param dst_len Size of @p dst in bytes.
 * @param size_out Optional out parameter receiving the file size.
 * @return 0 on success, -1 on failure.
 *
 * @details
 * Same result as llm_fetch_file() without the intermediate heap buffer, so the
 * destination (typically a shared-memory segment) is filled in place.
 *
 * Checks performed:
 *   1. The file must fit in @p dst_len; the size is learned from META_RESP
 *      before any payload is written.
 *   2. SHA-256 is verified over the assembled file.
 */
int llm_fetch_file_into(uint8_t file_id, char *dst, uint32_t dst_len, uint32_t *size_out);

/* ----------------------------------------------------------------------------
 * Server endpoint selection
 */

/**
 * @brief Point the client at a weight server other than the compile-time default.
 * @param ip Server IPv4 address in host byte order (see FTP_IPV4).
 * @param port Server UDP port; pass 0 to keep the current port.
 *
 * @details
 * The default endpoint is FTP_SERVER_IP:SERVER_PORT, which the qemu-node*
 * targets set to the bridge host. A caller that learns the server address at
 * run time (e.g. a worker told where to fetch its shard from) calls this once
 * before any llm_* transfer function.
 *
 * Checks performed:
 *   1. A zero @p port leaves the configured port untouched (partial override).
 *   2. A zero @p ip is accepted verbatim — 0.0.0.0 is the historical default
 *      and rejecting it would break the user-mode networking path.
 */
void llm_set_server(uint32_t ip, uint16_t port);

/**
 * @brief Current server IPv4 address in host byte order.
 * @return The address set by llm_set_server(), or FTP_SERVER_IP if unset.
 */
uint32_t llm_server_ip(void);

/**
 * @brief Current server UDP port.
 * @return The port set by llm_set_server(), or SERVER_PORT if unset.
 */
uint16_t llm_server_port(void);

/**
 * @brief Enable or disable the bulk-flow declaration made by transfers.
 * @param enabled Non-zero to declare transfers bulk (the default), 0 to leave
 *        them subject to the kernel's per-source UDP rate limiter.
 *
 * @details
 * Exists so the regression gate can demonstrate both sides of the policy: a
 * declared flow sustains throughput, an undeclared one is metered. Production
 * callers should leave it enabled.
 */
void llm_set_bulk(int enabled);

/* ----------------------------------------------------------------------------
 * Convenience wrappers
 */

/**
 * fetch_model_weights
 * @brief Convenience wrapper to download the model weights file.
 * @param size_out Out parameter for returned file size.
 * @return malloc'd buffer with weights on success, NULL on failure.
 */
char* fetch_model_weights(int *size_out);

/**
 * fetch_tokenizer
 * @brief Convenience wrapper to download the tokenizer file.
 * @param size_out Out parameter for returned file size.
 * @return malloc'd buffer with tokenizer on success, NULL on failure.
 */
char* fetch_tokenizer(int *size_out);

/* ----------------------------------------------------------------------------
 * Protocol message types (wire values)
 *
 * These values appear as the first byte of protocol messages exchanged with
 * the LLM UDP server.
 */
#define MSG_META_REQ      0x01
#define MSG_META_RESP     0x02
#define MSG_DATA_RANGE_REQ 0x03
#define MSG_RETRANS_REQ   0x04
#define MSG_DATA_PACKET   0x05
#define MSG_ERROR         0x06

/* ----------------------------------------------------------------------------
 * Protocol constants
 *
 * - SERVER_PORT / SERVER_IP: compile-time default server endpoint
 * - CHUNK_SIZE: size of each data chunk on the wire
 * - MAX_RANGE: maximum number of chunks requested per DATA_RANGE_REQ
 * - MAX_RETRANS: maximum indices in a RETRANS_REQ
 * - MAX_RECEIVE_SPINS / MAX_RETRY_ROUNDS: client-side retry/backoff parameters
 */

/** @brief Assemble a host-order IPv4 address from its four octets. */
#define FTP_IPV4(a, b, c, d) \
  (((uint32_t)(a) << 24) | ((uint32_t)(b) << 16) | ((uint32_t)(c) << 8) | (uint32_t)(d))

#define SERVER_PORT 9999

/*
 * Default server address: the host end of the 10.0.0.0/24 the guest lives on.
 *
 * This was 0.0.0.0, which is not a routable destination -- a fetch with it fails
 * in ARP resolution ("sys_send: ARP resolution failed for dst ip 0x0") before a
 * single request leaves the node. Every topology in use puts the weight server
 * at 10.0.0.1: the bridge setup (host end of br0) and the root-free user-mode
 * setup (`-netdev user,net=10.0.0.0/24,host=10.0.0.1`) alike.
 *
 * Override with -DFTP_SERVER_IP at build time, or llm_set_server() at run time
 * (which is what a worker told where to fetch its shard from will use).
 */
#ifndef FTP_SERVER_IP
#define FTP_SERVER_IP FTP_IPV4(10, 0, 0, 1)
#endif
#define SERVER_IP FTP_SERVER_IP

#define CHUNK_SIZE 512
#define MAX_RANGE 8
#define MAX_RETRANS 16
#define MAX_RECEIVE_SPINS 100000
/*
 * Retransmission rounds. MAX_RETRY_ROUNDS is a hard upper bound; the transfer
 * actually stops earlier, when RETRANS_STALL_LIMIT consecutive rounds recover no
 * new chunks (see llm_fetch_window). A large fetch under loss needs many rounds
 * to recover its last few stragglers -- a 93 MB embedding is ~192k chunks, and
 * losing even 0.02% of them (~40 chunks) exceeded the old fixed 3 rounds and
 * failed the transfer at 99.98% complete. Each round re-requests only the missing
 * chunks (RETRANS_REQ), so raising the cap is cheap.
 */
#define MAX_RETRY_ROUNDS 50
#define RETRANS_STALL_LIMIT 6

/*
 * Receive pacing. RECV_TIMEOUT_TICKS bounds a single recvtimeo() wait (xv6 ticks,
 * 10 Hz); MAX_IDLE_RECVS is how many consecutive expiries end a receive loop and
 * hand the remaining chunks to the RETRANS_REQ path. Together they cap a stalled
 * range at ~600 ms instead of blocking forever.
 */
#define RECV_TIMEOUT_TICKS 2
#define MAX_IDLE_RECVS 3

/* ----------------------------------------------------------------------------
 * File identifiers used with protocol message header
 */
#define FILE_WEIGHTS 0x01
#define FILE_TOKENIZER 0x02

/*
 * Optional per-batch progress hook (see ftpclient.c). Set it to a non-blocking
 * callback to interleave work while a long transfer runs on this thread; NULL
 * (the default) leaves transfers behaving exactly as before.
 */
extern void (*g_ftp_progress_hook)(void);

#endif // FTPCLIENT_H