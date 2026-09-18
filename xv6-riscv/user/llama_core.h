/**
 * @file llama_core.h
 * @brief Transformer kernels shared by the single-node runtime and the DistInf shards.
 *
 * @author Hadiya Muneeb (original llama.c implementation)
 *
 * @details
 * The arithmetic that was inside llama.c now lives here and in llama_core.c, so
 * that exactly one copy of it exists. llama.c keeps the single-node driver
 * (argument parsing, weight fetching, the generate/chat loops); a DistInf worker
 * links the same object and runs a *subset* of the layers on an activation that
 * arrived over RPC.
 *
 * Why one copy matters: the distributed correctness gate asserts that a sharded
 * run reproduces the single-node token stream exactly. That claim is only sound
 * if both paths execute the identical kernels -- including the 8-way unrolled
 * accumulation in dot_product_unrolled(), whose summation order differs from a
 * naive loop. A second, "equivalent" implementation would silently drift.
 *
 * Layer addressing. In the monolithic checkpoint every per-layer tensor is one
 * big array indexed `base + l * stride`. A worker holds only its own layers, so
 * that arithmetic cannot be applied to a shard. llama_layer_t therefore carries
 * the nine already-offset pointers for a single layer: llama_layer_at() derives
 * it from a whole checkpoint, and a shard builds one directly from its segment.
 * Both feed the same llama_block(), so both compute bit-identical results.
 */

#ifndef LLAMA_CORE_H
#define LLAMA_CORE_H

#include "kernel/types.h"
#include <stdint.h>   /* int8_t, used by encode() */
#include "user/user.h"
#include "user/xstdlib.h"
#include "user/xstrlib.h"
#include "user/xmath.h"
#include "user/perf.h"

 // stdlib functions
#define calloc   xcalloc
#define bsearch  xbsearch
#define qsort    xqsort
#define atoi     xatoi
#define atof     xatof

// strlib functions
#define sprintf  xsprintf
#define sscanf   xsscanf
#define isprint  xisprint
#define isspace  xisspace

// Math function macros
#define sqrtf    xsqrtf
#define expf     xexpf
#define powf     xpowf
#define cosf     xcosf
#define sinf     xsinf
#define abs      xfabsf
#define floorf   xfloorf

#define stdout 1 // fd for standard output
#define stderr 2 // fd for standard error

// Exit codes
#define EXIT_FAILURE 1
#define EXIT_SUCCESS 0

#define WEIGHTS_SEGMENT "llm_weights" // name of shared memory region holding model weights
#define TOKENIZER_SIZE 433869  // expected tokenizer binary size (bytes)
#define WEIGHTS_SIZE 60816028 // expected model weight buffer size (bytes)

typedef uint32 size_t;
#define NULL ((void*)0)
#define eprintf(fmt, ...) printf(fmt, ##__VA_ARGS__) // xv6 replacement for fprintf(stderr, ...)

/* ---------------------------------------------------------------------------
 * Model, run-state and thread-pool types (moved verbatim from llama.c)
 * ------------------------------------------------------------------------ */

typedef struct {
  int dim;
  int hidden_dim;
  int n_layers;
  int n_heads;
  int n_kv_heads;
  int vocab_size;
  int seq_len;
} Config;

typedef struct {
  float* token_embedding_table;
  float* rms_att_weight;
  float* rms_ffn_weight;
  float* wq;
  float* wk;
  float* wv;
  float* wo;
  float* w1;
  float* w2;
  float* w3;
  float* rms_final_weight;
  float* wcls;
} TransformerWeights;

typedef struct {
  float* x;
  float* xb;
  float* xb2;
  float* hb;
  float* hb2;
  float* q;
  float* k;
  float* v;
  float* att;
  float* logits;
  float* key_cache;
  float* value_cache;
} RunState;

typedef enum {
    TASK_NONE = 0,
    TASK_MATMUL = 1,
    TASK_ATTENTION = 2
} TaskType;

typedef struct {
    float* xout;
    float* x;
    float* w;
    int n;
    int d;
    int start_row;
    int end_row;
} MatmulWork; 

typedef struct {
    RunState* s;
    Config* p;
    TransformerWeights* w;
    unsigned long long layer;
    int pos;
    int head_start;
    int head_end;
} AttentionWork;

typedef struct {
    int thread_id;
    
    // Task definition
    volatile int task_type; // TaskType enum
    MatmulWork* mm_work;
    AttentionWork* att_work;

    // Synchronization flags
    volatile int* work_ready;
    volatile int* work_done;
    volatile int* should_exit;
} ThreadPoolWorker;

typedef struct {
  Config config; 
  TransformerWeights weights; 
  RunState state; 
} Transformer;

typedef struct {
  char* str;
  int id;
} TokenIndex;

typedef struct {
  char** vocab;
  float* vocab_scores;
  TokenIndex* sorted_vocab;
  int vocab_size;
  unsigned int max_token_length;
  unsigned char byte_pieces[512]; // stores all single-byte strings
} Tokenizer;

typedef struct {
  float prob;
  int index;
} ProbIndex; // struct used when sorting probabilities during top-p sampling

typedef struct {
  int vocab_size;
  ProbIndex* probindex; // buffer used in top-p sampling
  float temperature;
  float topp;
  unsigned long long rng_state;
} Sampler;

/* ---------------------------------------------------------------------------
 * Shared state
 * ------------------------------------------------------------------------ */

/** @brief Matmul/attention worker-thread count; set by the driver's -x flag. */
extern volatile int g_num_threads;

/**
 * @brief Release resources and terminate. Defined by the driver (llama.c).
 * @param code Process exit status.
 *
 * @details Declared here because the core calls it on an unrecoverable
 * allocation failure, but what needs releasing (shared-memory segments, the
 * thread pool) is the driver's business, not the arithmetic's.
 */
void release_and_exit(int code);

/* ---------------------------------------------------------------------------
 * Numeric kernels
 * ------------------------------------------------------------------------ */
void init_thread_pool(void);
void shutdown_thread_pool(void);
void matmul(float* xout, float* x, float* w, int n, int d);
void rmsnorm(float* o, float* x, float* weight, int size);
void softmax(float* x, int size);

/* ---------------------------------------------------------------------------
 * Model construction
 * ------------------------------------------------------------------------ */
void memory_map_weights(TransformerWeights* w, Config* p, float* ptr, int shared_weights);

/**
 * @brief Byte offset and length of the head/tail tensors a master node holds.
 * @param p Model configuration (from the checkpoint header).
 * @param shared_weights Non-zero if the classifier aliases the embedding table.
 * @param embed_off,embed_bytes Range of token_embedding_table in the checkpoint.
 * @param final_off,final_bytes Range of rms_final_weight.
 * @param wcls_off,wcls_bytes Range of the classifier; equals the embedding when
 *        @p shared_weights, otherwise a separate tensor at the tail.
 *
 * @details Lets the master fetch only the tensors it uses (embedding, final norm,
 * and classifier) instead of the whole checkpoint. Offsets mirror
 * memory_map_weights() exactly so they cannot diverge from the mapped layout.
 */
void llama_head_tail_offsets(const Config* p, int shared_weights,
                             uint64* embed_off, uint64* embed_bytes,
                             uint64* final_off, uint64* final_bytes,
                             uint64* wcls_off,  uint64* wcls_bytes);
void build_transformer(Transformer* t, void* weights_ptr);
void free_transformer(Transformer* t);
void malloc_run_state(RunState* s, Config* p);
/* Lean variant: only the buffers llama_embed + llama_head touch (master node). */
void malloc_run_state_head(RunState* s, Config* p);
void free_run_state(RunState* s);
float* forward(Transformer* transformer, int token, int pos);

/* ---------------------------------------------------------------------------
 * Pipeline-parallel entry points
 *
 * forward() is exactly llama_embed() + llama_block() over every layer +
 * llama_head(). A worker calls llama_block() for its own range only; the master
 * calls llama_embed() at the start of a token and llama_head() at the end.
 * ------------------------------------------------------------------------ */

/** @brief The nine weight tensors of one transformer layer, already offset. */
typedef struct {
  float* rms_att;   /**< attention RMSNorm gain,      [dim]              */
  float* wq;        /**< query projection,            [dim x dim]        */
  float* wk;        /**< key projection,              [dim x kv_dim]     */
  float* wv;        /**< value projection,            [dim x kv_dim]     */
  float* wo;        /**< attention output projection, [dim x dim]        */
  float* rms_ffn;   /**< FFN RMSNorm gain,            [dim]              */
  float* w1;        /**< FFN gate projection,         [dim x hidden_dim] */
  float* w2;        /**< FFN down projection,         [hidden_dim x dim] */
  float* w3;        /**< FFN up projection,           [dim x hidden_dim] */
} llama_layer_t;

/**
 * @brief Address layer @p l inside a whole-checkpoint weight mapping.
 * @param w Weights mapped by memory_map_weights().
 * @param p Model configuration.
 * @param l Absolute layer index.
 * @return The nine tensor pointers for that layer.
 */
llama_layer_t llama_layer_at(const TransformerWeights* w, const Config* p, int l);

/**
 * @brief Write a token's embedding row into the activation vector.
 * @param w Weights holding token_embedding_table.
 * @param p Model configuration.
 * @param x Destination activation, [dim] floats.
 * @param token Token id to embed.
 */
void llama_embed(const TransformerWeights* w, const Config* p, float* x, int token);

/**
 * @brief Run one transformer layer over the activation, in place.
 * @param layer The layer's nine tensors (whole checkpoint or shard alike).
 * @param p Model configuration.
 * @param s Run state; supplies the scratch buffers and the KV cache.
 * @param x Activation vector, [dim] floats, updated in place.
 * @param kv_layer Index of this layer *within s->key_cache/value_cache*. On a
 *        whole model this equals the absolute layer index; on a shard holding
 *        layers [a,b) it is the local index (absolute - a), because the shard
 *        only allocates cache for the layers it owns.
 * @param pos Position of the current token in the sequence.
 */
void llama_block(const llama_layer_t* layer, Config* p, RunState* s,
                 float* x, int kv_layer, int pos);

/**
 * @brief Final RMSNorm + classifier, producing logits.
 * @param w Weights holding rms_final_weight and wcls.
 * @param p Model configuration.
 * @param s Run state; s->logits receives the result.
 * @param x Activation after the last layer, [dim] floats (normalised in place).
 * @return s->logits, [vocab_size] floats.
 */
float* llama_head(const TransformerWeights* w, const Config* p, RunState* s, float* x);

/* ---------------------------------------------------------------------------
 * Tokenizer and sampler
 * ------------------------------------------------------------------------ */
void build_tokenizer(Tokenizer* t, void* tokenizer_data, int vocab_size);
void free_tokenizer(Tokenizer* t);
void encode(Tokenizer* t, char* text, int8_t bos, int8_t eos, int* tokens, int* n_tokens);
char* decode(Tokenizer* t, int prev_token, int token);
void safe_printf(char* piece);
void build_sampler(Sampler* sampler, int vocab_size, float temperature, float topp,
                   unsigned long long rng_seed);
void free_sampler(Sampler* sampler);
int sample(Sampler* sampler, float* logits);

#endif /* LLAMA_CORE_H */
