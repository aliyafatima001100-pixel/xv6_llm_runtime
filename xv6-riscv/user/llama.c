/**
 * @file llama.c
 * @brief Pure C llama inference program integrated with xv6 userland and persistent shared memory caching.
 *
 * @author Hadiya Muneeb
 *
 * @date 29th November 2025
 *
 * @details
 * This program provides a fully self-contained llama inference engine designed for
 * execution inside xv6 user space. All model weights and tokenizer data are loaded
 * exclusively from persistent shared memory, eliminating any dependency on the
 * filesystem or mmap-based checkpoint loading.
 *
 * The program integrates:
 * - A memory-mapped weight parser for the Transformer architecture (without file I/O)
 * - A tokenizer implementation that constructs vocab, scores, and lookup tables
 *   directly from a raw binary buffer present in shared memory
 * - A sampler (top-p, temperature scaling, greedy sampling)
 * - End-to-end generation and chat loops consistent with the llama 2 Chat schema
 *
 * Changes and enhancements introduced in this implementation:
 * - Shared Memory Model Loading
 * - Shared Memory Tokenizer Loading
 * - Filesystem-Free Execution
 * - xv6 Compatibility Adjustments
 * - Retention of Original llama Inference Logic
 *
 * This file serves as a fully operational llama runtime inside xv6, relying
 * solely on shared memory, UDP-based model distribution, and xv6-compatible
 * minimal C library abstractions.
 */

#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"

#include "user/xstdlib.h"
#include "user/xstrlib.h"
#include "user/xmath.h"
#include "user/ftpclient.h"
#include "user/perf.h"

#include "testutil.h"
#include "ftpclient.h"

#include "user/llama_core.h"


void* GLOBAL_WEIGHTS_PTR = NULL; // global pointer to the model weights in shared memory
void* GLOBAL_TOKENIZER_PTR = NULL; // global pointer to the tokenizer data in shared memory

void shutdown_thread_pool(void);

/**
 * @brief Print performance metrics.
 */
void release_and_exit(int code) {
  shutdown_thread_pool();
  // clean up any global state here if needed
  shmdt(GLOBAL_WEIGHTS_PTR);
  shmdt(GLOBAL_TOKENIZER_PTR);
  exit(code);
}

/**
 * @brief Print current RAM usage.
 */
void print_ram_usage(const char* msg) {
  uint64 used = getramused();
  printf("%s: %lu bytes (%lu KB, %lu MB)\n", msg, used, used / 1024, used / (1024 * 1024));
}

/**
 * @brief Fetch or attach to cached model data in shared memory.
 *
 * @param segment_name Name of the shared memory segment.
 * @param expected_size Expected size of the file in bytes.
 * @param file_id LLM-RFTP file identifier to fetch on a cache miss.
 *
 * @return void* Pointer to the shared memory containing the data, or 0 on failure.
 *
 * @details
 * On a miss the file is streamed **directly into the attached segment** by
 * llm_fetch_file_into(). The earlier version assembled the whole file in a
 * malloc'd buffer and then memcpy'd it into the segment, which needs twice the
 * file size resident at once — 120 MB for a 60 MB checkpoint, and fatal for the
 * larger models on a 256 MB node. Streaming keeps peak usage at one copy.
 *
 * Checks performed:
 *   1. An existing segment of the expected size is reused read-only (cache hit).
 *   2. A newly created segment is attached read-write before any data arrives.
 *   3. The transfer must report success and the size reported by META_RESP must
 *      equal @p expected_size, otherwise the segment is left detached and 0 is
 *      returned rather than handing back a partially-filled mapping.
 */
void* fetch_if_not_cached(const char* segment_name, int expected_size, uint8_t file_id) {
  int shmid;
  void* shmaddr;
  uint32_t size = 0;

  // Try to get existing shared memory segment with correct size
  shmid = shmget(segment_name, expected_size, 0);
  if (shmid >= 0) {
    shmaddr = shmat(shmid, 0, SHM_RDONLY);
    if (shmaddr == (void*)-1) {
      failnoex(" Failed to attach to existing shared memory segment");
      return 0;
    }
    pass(" Cached data found (segment: %s, ID: %d). Ready for use.", segment_name, shmid);
    return shmaddr;
  }

  // Segment not found → create it, then stream the file straight into it
  info(" No cached data found for %s. Fetching from server...", segment_name);

  shmid = shmget(segment_name, expected_size, IPC_CREAT | SHM_PERSIST);
  if (shmid < 0) {
    failnoex(" Failed to create shared memory segment for %s", segment_name);
    return 0;
  }

  shmaddr = shmat(shmid, 0, SHM_RDWR);
  if (shmaddr == (void*)-1) {
    failnoex(" Failed to attach to newly created shared memory segment");
    return 0;
  }

  if (llm_fetch_file_into(file_id, (char*)shmaddr, expected_size, &size) < 0 ||
      size != (uint32_t)expected_size) {
    failnoex(" Failed to fetch %s or size mismatch (got %d, expected %d)",
             segment_name, size, expected_size);
    shmdt(shmaddr);
    return 0;
  }

  pass(" %s fetched and cached in shared memory (ID: %d).\n", segment_name, shmid);
  return shmaddr;
}


// ----------------------------------------------------------------------------
// generation loop

void generate(Transformer* transformer, Tokenizer* tokenizer, Sampler* sampler, char* prompt, int steps) {
  perf_start_function("generate");

  char* empty_prompt = "";
  if (prompt == NULL) { prompt = empty_prompt; }

  // encode the (string) prompt into tokens sequence
  int num_prompt_tokens = 0;
  int* prompt_tokens = (int*)malloc((strlen(prompt) + 3) * sizeof(int)); // +3 for '\0', ?BOS, ?EOS

  encode(tokenizer, prompt, 1, 0, prompt_tokens, &num_prompt_tokens);
  if (num_prompt_tokens < 1) {
    eprintf("something is wrong, expected at least 1 prompt token\n");
    release_and_exit(EXIT_FAILURE);
  }

  // start the main loop
  long start = 0;  // used to time our code, only initialized after first iteration
  int next;        // will store the next token in the sequence
  int token = prompt_tokens[0]; // kick off with the first token in the prompt
  int pos = 0;     // position in the sequence
  int first_token_generated = 0;  // flag to track when first token is generated

  while (pos < steps) {
    // forward the transformer to get logits for the next token
    float* logits = forward(transformer, token, pos);

    // advance the state machine
    if (pos < num_prompt_tokens - 1) {
      // if we are still processing the input prompt, force the next prompt token
      next = prompt_tokens[pos + 1];
    }
    else {
      // otherwise sample the next token from the logits
      next = sample(sampler, logits);
    }
    pos++;

    // data-dependent terminating condition: the BOS (=1) token delimits sequences
    if (next == 1) { break; }

    // print the token as string, decode it with the Tokenizer object
    char* piece = decode(tokenizer, token, next);

    safe_printf(piece); // same as printf("%s", piece), but skips "unsafe" bytes
    token = next;

    // Track Time to First Token (TTFT) - capture when first output token is generated
    if (!first_token_generated && pos > num_prompt_tokens) {
      perf_metrics.time_to_first_token_ms = perf_time_in_ms() - perf_metrics.start_time_ms;
      first_token_generated = 1;
    }

    // init the timer here because the first iteration can be slower
    if (start == 0) { start = perf_time_in_ms(); }
  }
  printf("\n");

  // report achieved tok/s (pos-1 because the timer starts after first iteration)
  if (pos > 1) {
    long end = perf_time_in_ms();
    eprintf("\nachieved tok/s: %f\n", (pos - 1) / (double)(end - start) * 1000);
    perf_metrics.total_tokens_generated = pos - 1;
    perf_metrics.total_inference_time_ms = end - start;
    perf_metrics.tokens_per_second = (pos - 1) / (double)(end - start) * 1000;
  }

  free(prompt_tokens);
  perf_end_function("generate");
}

void read_stdin(const char* guide, char* buffer, size_t bufsize)
{
  // read a line from stdin, up to but not including \n
  printf("%s", guide);
  // Use xv6's gets function
  if (gets(buffer, bufsize) == 0) {
    // Handle EOF or error
    buffer[0] = '\0';
  }

  // Remove trailing newline if present (gets might include it)
  size_t len = strlen(buffer);
  if (len > 0 && buffer[len - 1] == '\n') {
    buffer[len - 1] = '\0';
  }
}

// ----------------------------------------------------------------------------
// chat loop
// I manually inspected the tokens for a few chat conversations compared to
// python reference and that seemed ok, but this was not thoroughly tested and
// is not safely implemented, it's more a proof of concept atm.

void chat(Transformer* transformer, Tokenizer* tokenizer, Sampler* sampler,
  char* cli_user_prompt, char* cli_system_prompt, int steps) {
  perf_start_function("chat");

  // buffers for reading the system prompt and user prompt from stdin
  // you'll notice they are soomewhat haphazardly and unsafely set atm
  char system_prompt[512];
  char user_prompt[512];
  char rendered_prompt[1152];
  int num_prompt_tokens = 0;
  int* prompt_tokens = (int*)malloc(1152 * sizeof(int));
  int user_idx;

  // start the main loop
  int8_t user_turn = 1; // user starts
  int next = 0;        // will store the next token in the sequence
  int token;       // stores the current token to feed into the transformer
  // int prev_token;
  int pos = 0;     // position in the sequence
  while (pos < steps) {

    // when it is the user's turn to contribute tokens to the dialog...
    if (user_turn) {
      // get the (optional) system prompt at position 0
      if (pos == 0) {
        // at position 0, the user can also contribute a system prompt
        if (cli_system_prompt == NULL) {
          // system prompt was not passed in, attempt to get it from stdin
          read_stdin("Enter system prompt (optional): ", system_prompt, sizeof(system_prompt));
        }
        else {
          // system prompt was passed in, use it
          strcpy(system_prompt, cli_system_prompt);
        }
      }
      // get the user prompt
      if (pos == 0 && cli_user_prompt != NULL) {
        // user prompt for position 0 was passed in, use it
        strcpy(user_prompt, cli_user_prompt);
      }
      else {
        // otherwise get user prompt from stdin
        read_stdin("User: ", user_prompt, sizeof(user_prompt));
      }
      // render user/system prompts into the Llama 2 Chat schema
      if (pos == 0 && system_prompt[0] != '\0') {
        char system_template[] = "[INST] <<SYS>>\n%s\n<</SYS>>\n\n%s [/INST]";
        sprintf(rendered_prompt, system_template, system_prompt, user_prompt);
      }
      else {
        char user_template[] = "[INST] %s [/INST]";
        sprintf(rendered_prompt, user_template, user_prompt);
      }
      // encode the rendered prompt into tokens
      encode(tokenizer, rendered_prompt, 1, 0, prompt_tokens, &num_prompt_tokens);
      user_idx = 0; // reset the user index
      user_turn = 0;
      printf("Assistant: ");
    }

    // determine the token to pass into the transformer next
    if (user_idx < num_prompt_tokens) {
      // if we are still processing the input prompt, force the next prompt token
      token = prompt_tokens[user_idx++];
    }
    else {
      // otherwise use the next token sampled from previous turn
      token = next;
    }
    // EOS (=2) token ends the Assistant turn
    if (token == 2) { user_turn = 1; }

    // forward the transformer to get logits for the next token
    float* logits = forward(transformer, token, pos);
    next = sample(sampler, logits);
    pos++;

    if (user_idx >= num_prompt_tokens && next != 2) {
      // the Assistant is responding, so print its output
      char* piece = decode(tokenizer, token, next);
      safe_printf(piece); // same as printf("%s", piece), but skips "unsafe" bytes
    }
    if (next == 2) { printf("\n"); }
  }
  printf("\n");
  free(prompt_tokens);
  perf_end_function("chat");
}

// ----------------------------------------------------------------------------
// CLI, include only if not testing
#ifndef TESTING

/**
 * @brief Parse a dotted-decimal IPv4 address into host byte order.
 * @param s Address text, "a.b.c.d".
 * @return The address in host byte order.
 *
 * @note xv6 has no inet_aton(); this mirrors the parsers in distinf.c/shardspike.c.
 */
static uint32_t parse_server_ip(const char* s) {
  uint32_t a, b, c, d;

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

void error_usage() {
  eprintf("Usage:   llama [options]\n");
  eprintf("Example: llama -n 256 -i \"Once upon a time\"\n");
  eprintf("Options:\n");
  eprintf("  -t <float>  temperature in [0,inf], default 1.0\n");
  eprintf("  -p <float>  p value in top-p (nucleus) sampling in [0,1] default 0.9\n");
  eprintf("  -s <int>    random seed, default time(NULL)\n");
  eprintf("  -n <int>    number of steps to run for, default 256. 0 = max_seq_len\n");
  eprintf("  -i <string> input prompt\n");
  eprintf("  -m <string> mode: generate|chat, default: generate\n");
  eprintf("  -y <string> (optional) system prompt in chat mode\n");
  eprintf("  -x <int>    number of matmul worker threads (default: 3)\n");
  eprintf("  -a <ip>     weight server address, dotted decimal (default: 10.0.0.1)\n");
  exit(EXIT_FAILURE);
}

// ----------------------------------------------------------------------------
// Argument parsing

/**
 * @brief Structure to hold command-line arguments.
 *
 * @author Syed Taha
 * @date   1st December 2025
 *
 * @details
 * This structure encapsulates the various command-line arguments that can be
 * passed to the program. It includes parameters for temperature, top-p sampling,
 * number of steps, input prompt, random seed, mode of operation, and an optional
 * system prompt for chat mode.
 */
typedef struct {
  float temperature;
  float topp;
  int steps;
  char* prompt;
  unsigned long long rng_seed;
  char* mode;
  char* system_prompt;
  int num_threads; // -x flag: number of matmul worker threads
  uint32_t server_ip; // -a flag: LLM-RFTP weight server address (host byte order)
} Args; 

/**
 * @brief Parse command-line arguments and populate the Args structure.
 *
 * @param argc Number of command-line arguments.
 * @param argv Array of command-line argument strings.
 * @param args Pointer to Args structure to populate.
 * @return int Returns 0 on success, -1 on failure.
 *
 * @author Syed Taha
 * @date   1st December 2025
 *
 * @details
 * This function processes the command-line arguments provided to the program,
 * extracting values for temperature, top-p sampling, number of steps, input prompt,
 * random seed, mode of operation, and an optional system prompt for chat mode.
 * It performs basic validation on the arguments and sets default values where necessary.
 */
int argparse(int argc, char* argv[], Args* args) {
  // default values
  args->temperature = 1.0f;      // 0.0 = greedy deterministic. 1.0 = original. don't set higher
  args->topp = 0.9f;             // top-p in nucleus sampling. 1.0 = off. 0.9 works well, but slower
  args->steps = 256;             // number of steps to run for
  args->prompt = NULL;           // prompt string
  args->rng_seed = 0;            // seed rng with time by default
  args->mode = "generate";       // generate|chat
  args->system_prompt = NULL;    // the (optional) system prompt to use in chat mode
  args->num_threads = 3;         // default number of matmul worker threads
  args->server_ip = SERVER_IP;   // weight server; -a overrides (see ftpclient.h)


  for (int i = 1; i < argc; i += 2) {
    // do some basic validation
    if (i + 1 >= argc) { return -1; } // must have arg after flag
    if (argv[i][0] != '-') { return -1; } // must start with dash
    if (strlen(argv[i]) != 2) { return -1; } // must be -x (one dash, one letter)
    // read in the args
    if (argv[i][1] == 't') { args->temperature = atof(argv[i + 1]); }
    else if (argv[i][1] == 'p') { args->topp = atof(argv[i + 1]); }
    else if (argv[i][1] == 's') { args->rng_seed = atoi(argv[i + 1]); }
    else if (argv[i][1] == 'n') { args->steps = atoi(argv[i + 1]); }
    else if (argv[i][1] == 'i') { args->prompt = argv[i + 1]; }
    else if (argv[i][1] == 'm') { args->mode = argv[i + 1]; }
    else if (argv[i][1] == 'y') { args->system_prompt = argv[i + 1]; }
    else if (argv[i][1] == 'x') { args->num_threads = atoi(argv[i + 1]); }
    else if (argv[i][1] == 'a') { args->server_ip = parse_server_ip(argv[i + 1]); }
    else { return -1; }
  }

  if (args->rng_seed <= 0) args->rng_seed = (unsigned long long)rdtime();
  if (args->temperature < 0.0f) args->temperature = 0.0f;
  if (args->topp < 0.0f || args->topp > 1.0f) args->topp = 0.9f;
  if (args->steps < 0) args->steps = 0;
  if (args->num_threads <= 0) args->num_threads = 1;
  // cap to reasonable upper bound to avoid excessive allocations in xv6
  if (args->num_threads > 16) args->num_threads = 16; 

  return 0;
}

int main(int argc, char* argv[]) {
  // Initialize profiling
  perf_init();
  perf_register_function("fetch_model_weights");
  perf_register_function("fetch_tokenizer");
  perf_register_function("build_transformer");
  perf_register_function("build_tokenizer");
  perf_register_function("build_sampler");
  perf_register_function("generate");
  perf_register_function("chat");
  perf_register_function("forward");
  perf_register_function("multihead_attention");
  perf_register_function("matmul");
  perf_register_function("rmsnorm");
  perf_register_function("sample");
  perf_register_function("encode");
  perf_register_function("decode");

  Args args;

  if (argparse(argc, argv, &args) != 0) error_usage();

  // apply user-configured thread count for matmul worker pool
  g_num_threads = args.num_threads;

  // point the LLM-RFTP client at the weight server before any fetch happens
  llm_set_server(args.server_ip, 0);

  // Initialize performance metrics
  perf_metrics.start_time_ms = perf_time_in_ms();
  perf_metrics.initial_ram_usage = getramused();
  perf_metrics.peak_ram_usage = perf_metrics.initial_ram_usage;

  Transformer transformer;
  Tokenizer tokenizer;

  perf_start_function("fetch_model_weights");
  GLOBAL_WEIGHTS_PTR = fetch_if_not_cached("llm_weights", WEIGHTS_SIZE, FILE_WEIGHTS);
  if (!GLOBAL_WEIGHTS_PTR) { eprintf("Could not load weights\n"); exit(1); }
  perf_end_function("fetch_model_weights");

  perf_start_function("fetch_tokenizer");
  GLOBAL_TOKENIZER_PTR = fetch_if_not_cached("llm_tokenizer", TOKENIZER_SIZE, FILE_TOKENIZER);
  if (!GLOBAL_TOKENIZER_PTR) {
    eprintf("Could not load tokenizer\n");
    shmdt(GLOBAL_WEIGHTS_PTR);
    exit(1);
  }
  perf_end_function("fetch_tokenizer");

  build_transformer(&transformer, GLOBAL_WEIGHTS_PTR);
  build_tokenizer(&tokenizer, GLOBAL_TOKENIZER_PTR, transformer.config.vocab_size);

  perf_update_peak_ram();

  if (args.steps == 0 || args.steps > transformer.config.seq_len)
    args.steps = transformer.config.seq_len; // override to ~max length

  // build the Sampler
  Sampler sampler;
  build_sampler(&sampler, transformer.config.vocab_size, args.temperature, args.topp, args.rng_seed);


  perf_update_peak_ram();

  init_thread_pool();

  // run!
  if (strcmp(args.mode, "generate") == 0) {
    generate(&transformer, &tokenizer, &sampler, args.prompt, args.steps);
  }
  else if (strcmp(args.mode, "chat") == 0) {
    chat(&transformer, &tokenizer, &sampler, args.prompt, args.system_prompt, args.steps);
  }
  else {
    eprintf("unknown mode: %s\n", args.mode);
    error_usage();
  }

  // memory and file handles cleanup
  free_sampler(&sampler);
  free_tokenizer(&tokenizer);
  free_transformer(&transformer);

  perf_metrics.end_time_ms = perf_time_in_ms();
  perf_update_peak_ram();
  perf_print_report();

  release_and_exit(EXIT_SUCCESS);

  // Should not reach here. 
  printf("Time to panic!\n");
  return -1;
}
#endif