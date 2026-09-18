/**
 * @file distinf.h
 * @brief Wire payloads for the DistInf inference pipeline (L3).
 *
 * @details
 * Three payloads ride inside the RPC envelope defined by rpc.h:
 *
 *   PROC_ASSIGN_LAYERS  master -> worker : "you own layers [a,b) of this model,
 *                                          fetch them from this server"
 *   PROC_SHARD_READY    worker -> master : "my layers are resident" (or why not)
 *   PROC_INFER_REQ      ring hop         : one activation vector, worker -> next
 *                                          worker, and last worker -> master
 *
 * **Encoding.** These are XDR-encoded per RFC 4506: unsigned integers as 32-bit
 * big-endian (§4.2) and the activation as a fixed-length array of IEEE 754
 * binary32 in canonical big-endian order (§4.6, §4.12). Note this differs from
 * the older discovery payloads (worker_info_t, set_neighbor_t, cap_ack_t), which
 * are raw little-endian C structs -- a known divergence from RFC 4506 recorded
 * in README.md and left alone here rather than churning working, gated code.
 * New payloads follow the standard; the legacy three are migrated separately.
 *
 * **Sizing.** A hop carries INFER_HOP_HDR_WORDS words plus `dim` floats. At
 * dim=768 that is 3100 bytes: inside RPC_PAYLOAD_MAX (4096) and deliberately
 * above the 1500-byte MTU, so every hop exercises the hardened IP reassembly
 * path (RFC 791) rather than leaving it theoretical.
 */

#ifndef DISTINF_H
#define DISTINF_H

#include "kernel/types.h"

/** @brief 32-bit words preceding the activation in a PROC_INFER_REQ payload.
 *  Six protocol fields plus one metrics field (compute_us) the ring accumulates;
 *  see infer_hop_t. Kept a raw little-endian struct like the other legacy hops. */
#define INFER_HOP_HDR_WORDS 7

/** @brief Largest activation a hop may declare, bounding what we will decode. */
#define INFER_MAX_FLOATS 1024

/** @brief Per-token deadline and retry budget for the master's ring traversal.
 *
 *  The product must stay well under SUSPECTED_TIMEOUT (discovery.h), so a lost
 *  datagram is diagnosed as a lost datagram (retry) before the lifecycle
 *  diagnoses it as a dead node (evict) -- the two mechanisms must not race. */
#define INFER_TOKEN_TIMEOUT_MS 15000
#define INFER_MAX_RETRIES      2

/** @brief Ticks (10 Hz) the master waits for one worker's shard to load before
 *  giving up. Sized for the largest shard fetched serially over the segment: a
 *  ~110 MB range at the measured ~600 KB/s is ~3 min, so 600 s is generous. */
#define SHARD_LOAD_TIMEOUT_TICKS 12000

/** @brief flags bit: this hop carries the final activation back to the master. */
#define INFER_FLAG_FINAL 0x1

/** @brief PROC_ASSIGN_LAYERS payload (13 words, XDR-encoded). */
typedef struct {
  uint32 session_id;     /**< epoch; bumped on any membership change      */
  uint32 model_id;       /**< LLM-RFTP file identifier of the checkpoint  */
  uint32 layer_start;    /**< first layer owned (inclusive)               */
  uint32 layer_end;      /**< last layer owned (exclusive)                */
  uint32 n_layers_total; /**< layers in the whole model                   */
  uint32 dim;            /**< model geometry, cross-checked by the worker */
  uint32 hidden_dim;
  uint32 n_heads;
  uint32 n_kv_heads;
  uint32 seq_len;
  uint32 vocab_size;
  uint32 max_seq;        /**< KV-cache cap the worker should allocate     */
  uint32 weights_ip;     /**< weight server, host byte order              */
  uint32 weights_port;
} assign_layers_t;
#define ASSIGN_LAYERS_WORDS 14

/** @brief PROC_SHARD_READY payload (5 words, XDR-encoded). */
typedef struct {
  uint32 session_id;
  uint32 worker_id;
  uint32 layer_start;
  uint32 layer_end;
  uint32 status;         /**< 0 = resident and ready, non-zero = failed   */
} shard_ready_t;
#define SHARD_READY_WORDS 5

/** @brief PROC_INFER_REQ header; `n_floats` activations follow it on the wire. */
typedef struct {
  uint32 session_id;     /**< must match the live session (epoch)         */
  uint32 seq;            /**< strictly increasing; older is a replay      */
  uint32 pos;            /**< token position, for RoPE and the KV cache   */
  uint32 hop;            /**< index of the node expected to handle this   */
  uint32 n_floats;       /**< activation length; must equal dim           */
  uint32 flags;          /**< INFER_FLAG_*                                */
  uint32 compute_us;     /**< cumulative shard_forward time (us) so far    */
} infer_hop_t;

/* ---------------------------------------------------------------------------
 * XDR helpers (RFC 4506 §4.2, §4.6): 32-bit big-endian words.
 *
 * Kept as small static inlines rather than routed through xdr.c's stream API,
 * because these payloads are fixed-shape records with no discriminated unions
 * or variable arrays -- the encoding is what must be conformant, and it is.
 * ------------------------------------------------------------------------ */

/** @brief Write one unsigned integer in XDR canonical (big-endian) order. */
static inline void xdr_put_u32(uint8* p, uint32 v)
{
  p[0] = (uint8)(v >> 24); p[1] = (uint8)(v >> 16);
  p[2] = (uint8)(v >> 8);  p[3] = (uint8)v;
}

/** @brief Read one unsigned integer from XDR canonical (big-endian) order. */
static inline uint32 xdr_get_u32(const uint8* p)
{
  return ((uint32)p[0] << 24) | ((uint32)p[1] << 16) |
         ((uint32)p[2] << 8)  | (uint32)p[3];
}

/**
 * @brief Encode a float as XDR single-precision (RFC 4506 §4.6).
 * @details IEEE 754 binary32, written in canonical big-endian order. The bit
 * pattern is taken by aliasing through a union: RISC-V floats are already
 * binary32, so only byte order has to change.
 */
static inline void xdr_put_float(uint8* p, float f)
{
  union { float f; uint32 u; } c;
  c.f = f;
  xdr_put_u32(p, c.u);
}

/** @brief Decode an XDR single-precision float (RFC 4506 §4.6). */
static inline float xdr_get_float(const uint8* p)
{
  union { float f; uint32 u; } c;
  c.u = xdr_get_u32(p);
  return c.f;
}

#endif /* DISTINF_H */
