/**
 * @file shard.h
 * @brief Model sharding for DistInf: fetch and run a contiguous range of layers.
 *
 * @details
 * A worker owns layers [layer_start, layer_end) of a checkpoint and never holds
 * the whole model. Two problems follow, and this module solves both:
 *
 * 1. **Which bytes to fetch.** The llama2.c checkpoint is *tensor-major*, not
 *    layer-major: every layer's `wq` sits in one contiguous array, then every
 *    layer's `wk`, and so on. A range of layers is therefore not one byte range
 *    but **nine** -- one slice per per-layer tensor -- each computed from the
 *    Config header. shard_load() fetches exactly those nine ranges with
 *    llm_fetch_range() and nothing else.
 *
 * 2. **Where to put them.** Each layer is packed into its own persistent shared
 *    memory segment (`shard_L<i>`), in the fixed order below. One segment per
 *    layer keeps every allocation far under MAX_PAGES_PER_SEG (~70 MB) -- a
 *    110M layer is 27 MB -- and lets a restarted worker re-attach instead of
 *    re-downloading, since the segment is keyed by layer index.
 *
 * Packed per-layer segment layout (float32, in this order):
 *
 *     rms_att [dim]  wq [dim*dim]      wk [dim*kv_dim]  wv [dim*kv_dim]
 *     wo [dim*dim]   rms_ffn [dim]     w1 [dim*hidden]  w2 [hidden*dim]
 *     w3 [dim*hidden]
 *
 * which is exactly the field order of llama_layer_t, so shard_load() hands the
 * shared kernels (llama_block) the same pointers a whole-checkpoint run would
 * derive with llama_layer_at() -- and therefore computes identical results.
 */

#ifndef SHARD_H
#define SHARD_H

#include "user/llama_core.h"

/** @brief Most layers one worker may own (a 110M model has 12 in total). */
#define SHARD_MAX_LAYERS 16

/** @brief Default cap on sequence length, and so on the KV cache we allocate. */
#define SHARD_DEFAULT_MAX_SEQ 256

/**
 * @brief A worker's slice of the model: its layers, their memory, its run state.
 */
typedef struct {
  Config cfg;          /**< the model's real configuration, from the header    */
  Config local;        /**< cfg with n_layers = owned layers, seq_len = max_seq;
                            this is what the kernels are called with, so the KV
                            cache and attention buffers are sized for the shard */
  int layer_start;     /**< first layer owned (inclusive)                      */
  int layer_end;       /**< last layer owned (exclusive)                       */
  llama_layer_t layers[SHARD_MAX_LAYERS];  /**< pointers into the segments     */
  void* segs[SHARD_MAX_LAYERS];            /**< attached shm segments          */
  RunState state;      /**< scratch buffers + KV cache for the owned layers    */
  int loaded;          /**< non-zero once every layer is resident              */
} shard_t;

/**
 * @brief Read a checkpoint's Config header straight from the weight server.
 * @param file_id LLM-RFTP file identifier.
 * @param out Receives the seven-field header.
 * @return 0 on success, -1 on failure.
 *
 * @details
 * A worker calls this itself rather than trusting the geometry handed to it by
 * the master, so a master that lies about (or simply disagrees on) the model
 * cannot make a worker mis-address its weights.
 *
 * Checks performed:
 *   1. The header transfer must succeed.
 *   2. Every field must be positive and the head count must divide `dim`,
 *      otherwise the file is not a checkpoint this build can run.
 */
int shard_fetch_config(uint8_t file_id, Config* out);

/**
 * @brief Fetch and map layers [l0, l1) into per-layer shared-memory segments.
 * @param sh Shard to populate.
 * @param file_id LLM-RFTP file identifier to fetch from.
 * @param cfg Model configuration (as returned by shard_fetch_config()).
 * @param l0 First layer to own (inclusive).
 * @param l1 Last layer to own (exclusive).
 * @param max_seq Cap on positions, sizing the KV cache; 0 selects the default.
 * @return 0 on success, -1 on failure.
 *
 * Checks performed:
 *   1. The range is non-empty, inside [0, n_layers), and no wider than
 *      SHARD_MAX_LAYERS.
 *   2. max_seq is clamped to the model's own seq_len.
 *   3. Each layer's segment is created (or re-attached, if a previous run left
 *      it cached) before any of its bytes are requested, so weights stream in
 *      once rather than being assembled in the heap and copied.
 *   4. Every one of the nine slices must transfer, or the shard fails to load
 *      rather than computing on partially-filled weights.
 */
int shard_load(shard_t* sh, uint8_t file_id, const Config* cfg,
               int l0, int l1, int max_seq);

/**
 * @brief Run the shard's layers over an activation vector, in place.
 * @param sh A loaded shard.
 * @param x Activation, [dim] floats, updated in place.
 * @param pos Position of the current token in the sequence.
 * @return 0 on success, -1 if the shard is not loaded or pos is out of range.
 *
 * Checks performed:
 *   1. The shard must be fully loaded.
 *   2. pos must be below the KV-cache capacity (max_seq), since a larger value
 *      would index past the cache allocated for this shard.
 */
int shard_forward(shard_t* sh, float* x, int pos);

/**
 * @brief Detach a shard's segments and free its run state.
 * @param sh Shard to release. Segments are persistent, so they survive for the
 *        next run to re-attach; only this process's mappings go away.
 */
void shard_release(shard_t* sh);

#endif /* SHARD_H */
