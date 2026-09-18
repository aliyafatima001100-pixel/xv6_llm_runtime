/**
 * @file shard.c
 * @brief Model sharding for DistInf — see shard.h for the layout rationale.
 */

#include "user/shard.h"
#include "user/ftpclient.h"

/* Header of a llama2.c checkpoint: seven int32 fields, then float32 weights. */
#define CKPT_HEADER_BYTES ((uint32_t)(7 * 4))

/**
 * @brief Per-tensor geometry of a checkpoint, in float32 elements.
 *
 * @details
 * `base[i]` is the offset of tensor i's first element (counting from the first
 * float after the header) and `stride[i]` is how many elements each layer
 * contributes. A layer range [l0,l1) therefore occupies, for every i,
 * elements [base[i] + l0*stride[i], base[i] + l1*stride[i]).
 *
 * The order matches llama_layer_t, and so also the packed segment layout.
 */
typedef struct {
  uint64 base[9];
  uint64 stride[9];
} ckpt_geom_t;

/**
 * @brief Compute the nine per-layer tensor offsets from a Config.
 * @param p Model configuration.
 * @param g Receives the geometry.
 *
 * @details
 * Mirrors memory_map_weights() in llama_core.c, which walks the same tensors in
 * the same order for the monolithic case; the two must agree or a shard would
 * read the wrong bytes. Arithmetic is done in 64-bit because a 110M checkpoint
 * already exceeds what a 32-bit element count comfortably holds.
 */
static void
ckpt_geometry(const Config* p, ckpt_geom_t* g)
{
  uint64 dim = p->dim;
  uint64 hidden = p->hidden_dim;
  uint64 n_layers = p->n_layers;
  uint64 head_size = dim / p->n_heads;
  uint64 kv_dim = head_size * p->n_kv_heads;
  uint64 vocab = p->vocab_size < 0 ? -p->vocab_size : p->vocab_size;

  uint64 off = vocab * dim;          /* token_embedding_table comes first */

  g->base[0] = off; g->stride[0] = dim;            off += n_layers * dim;        /* rms_att */
  g->base[1] = off; g->stride[1] = dim * dim;      off += n_layers * dim * dim;  /* wq */
  g->base[2] = off; g->stride[2] = dim * kv_dim;   off += n_layers * dim * kv_dim; /* wk */
  g->base[3] = off; g->stride[3] = dim * kv_dim;   off += n_layers * dim * kv_dim; /* wv */
  g->base[4] = off; g->stride[4] = dim * dim;      off += n_layers * dim * dim;  /* wo */
  g->base[5] = off; g->stride[5] = dim;            off += n_layers * dim;        /* rms_ffn */
  g->base[6] = off; g->stride[6] = dim * hidden;   off += n_layers * dim * hidden; /* w1 */
  g->base[7] = off; g->stride[7] = hidden * dim;   off += n_layers * hidden * dim; /* w2 */
  g->base[8] = off; g->stride[8] = dim * hidden;   /* w3 (last per-layer tensor) */
}

int
shard_fetch_config(uint8_t file_id, Config* out)
{
  char buf[CKPT_HEADER_BYTES];

  if (llm_fetch_range(file_id, buf, 0, CKPT_HEADER_BYTES) < 0) {
    printf("shard: could not fetch checkpoint header\n");
    return -1;
  }
  memcpy(out, buf, sizeof(Config));

  int vocab = out->vocab_size < 0 ? -out->vocab_size : out->vocab_size;
  if (out->dim <= 0 || out->hidden_dim <= 0 || out->n_layers <= 0 ||
      out->n_heads <= 0 || out->n_kv_heads <= 0 || vocab <= 0 ||
      out->seq_len <= 0 || (out->dim % out->n_heads) != 0) {
    printf("shard: implausible checkpoint header (dim=%d layers=%d heads=%d)\n",
           out->dim, out->n_layers, out->n_heads);
    return -1;
  }
  return 0;
}

/**
 * @brief Name the shared-memory segment holding layer @p l.
 * @param out Buffer of at least 16 bytes.
 * @param l Absolute layer index.
 *
 * @note Keyed by layer index alone, so a worker that is reassigned the same
 *       layers after a restart re-attaches instead of re-downloading.
 */
static void
shard_segment_name(char* out, int l)
{
  char* p = out;
  *p++ = 's'; *p++ = 'h'; *p++ = 'a'; *p++ = 'r'; *p++ = 'd'; *p++ = '_'; *p++ = 'L';
  if (l >= 10) *p++ = '0' + (l / 10);
  *p++ = '0' + (l % 10);
  *p = '\0';
}

int
shard_load(shard_t* sh, uint8_t file_id, const Config* cfg,
           int l0, int l1, int max_seq)
{
  ckpt_geom_t g;
  char name[16];

  if (l0 < 0 || l1 > cfg->n_layers || l0 >= l1) {
    printf("shard: bad layer range [%d,%d) for a %d-layer model\n",
           l0, l1, cfg->n_layers);
    return -1;
  }
  if (l1 - l0 > SHARD_MAX_LAYERS) {
    printf("shard: range [%d,%d) exceeds SHARD_MAX_LAYERS (%d)\n",
           l0, l1, SHARD_MAX_LAYERS);
    return -1;
  }

  memset(sh, 0, sizeof(*sh));
  sh->cfg = *cfg;
  sh->layer_start = l0;
  sh->layer_end = l1;

  if (max_seq <= 0) max_seq = SHARD_DEFAULT_MAX_SEQ;
  if (max_seq > cfg->seq_len) max_seq = cfg->seq_len;

  /*
   * The kernels are driven with a Config describing *this shard*: as many
   * layers as we own, and seq_len capped at max_seq. malloc_run_state() then
   * sizes the KV cache and attention buffers for the shard rather than the
   * whole model, and llama_block()'s cache offset (kv_layer * seq_len * kv_dim)
   * stays consistent with it.
   */
  sh->local = *cfg;
  sh->local.n_layers = l1 - l0;
  sh->local.seq_len = max_seq;

  ckpt_geometry(cfg, &g);

  uint64 per_layer_floats = 0;
  for (int i = 0; i < 9; i++) per_layer_floats += g.stride[i];
  uint64 per_layer_bytes = per_layer_floats * sizeof(float);

  printf("shard: loading layers [%d,%d) — %d MB each, max_seq=%d\n",
         l0, l1, (int)(per_layer_bytes / (1024 * 1024)), max_seq);

  for (int l = l0; l < l1; l++) {
    int idx = l - l0;
    shard_segment_name(name, l);

    int shmid = shmget(name, per_layer_bytes, IPC_CREAT | SHM_PERSIST);
    if (shmid < 0) {
      printf("shard: shmget(%s, %d bytes) failed\n", name, (int)per_layer_bytes);
      return -1;
    }
    void* seg = shmat(shmid, 0, SHM_RDWR);
    if (seg == (void*)-1) {
      printf("shard: shmat(%s) failed\n", name);
      return -1;
    }
    sh->segs[idx] = seg;

    /* Fetch the nine slices straight into the segment, packed in order. */
    float* dst = (float*)seg;
    float** fields = (float**)&sh->layers[idx];   /* nine pointers, in order */

    for (int i = 0; i < 9; i++) {
      uint64 elems = g.stride[i];
      uint64 src_off = CKPT_HEADER_BYTES + (g.base[i] + (uint64)l * g.stride[i]) * sizeof(float);

      fields[i] = dst;
      if (llm_fetch_range(file_id, (char*)dst, (uint32_t)src_off,
                          (uint32_t)(elems * sizeof(float))) < 0) {
        printf("shard: layer %d tensor %d fetch failed\n", l, i);
        return -1;
      }
      dst += elems;
    }
    printf("shard: layer %d resident\n", l);
  }

  malloc_run_state(&sh->state, &sh->local);
  sh->loaded = 1;
  printf("shard: ready, %d layer(s)\n", l1 - l0);
  return 0;
}

int
shard_forward(shard_t* sh, float* x, int pos)
{
  if (!sh->loaded) return -1;
  if (pos < 0 || pos >= sh->local.seq_len) return -1;

  for (int l = sh->layer_start; l < sh->layer_end; l++) {
    int idx = l - sh->layer_start;
    /* kv_layer is the *local* index: the cache only covers our own layers. */
    llama_block(&sh->layers[idx], &sh->local, &sh->state, x, idx, pos);
  }
  return 0;
}

void
shard_release(shard_t* sh)
{
  if (!sh->loaded) return;
  free_run_state(&sh->state);
  for (int i = 0; i < sh->layer_end - sh->layer_start; i++)
    if (sh->segs[i]) shmdt(sh->segs[i]);
  sh->loaded = 0;
}
