/**
 * @file perf.h
 * @author Syed Taha
 * @date November 30, 2025
 *
 * @brief Performance profiling library header for xv6 user programs.
 *
 * @details
 * This library provides comprehensive performance profiling capabilities for xv6 user programs,
 * with special optimizations for LLM (Large Language Model) workloads. It supports accurate
 * measurement of function execution times, memory usage, and throughput metrics. The library
 * uses call stack-based profiling to distinguish between self (exclusive) time and inclusive
 * time, enabling detailed analysis of function performance in nested call hierarchies.
 *
 * Key features:
 * - Function-level profiling with self vs inclusive time measurement
 * - Memory usage tracking (initial, peak, final)
 * - Timing and throughput statistics
 * - Support for up to 100 profiled functions
 * - Call stack depth up to 64 frames
 *
 * @note This library is currently experimental and may be inefficient.
 *       It allocates memory dynamically and uses simple data structures that may not scale
 *       well for very large numbers of functions or deep call stacks.
 */

#ifndef PERF_H
#define PERF_H

#include "kernel/types.h"
#include "user/user.h"

#define PERF_MAX_FUNCTIONS 100
#define PERF_FUNCTION_NAME_MAX 64
#define PERF_SAMPLE_BUFFER_SIZE 10000

/**
 * @brief Function profiling entry structure
 *
 * This structure holds profiling data for a single function, including its name,
 * timing information, and call statistics. It tracks both inclusive (total) time
 * and exclusive (self) time to help identify performance bottlenecks.
 *
 * Members:
 * 
 * - `name`: The function name (up to PERF_FUNCTION_NAME_MAX characters)
 * 
 * - `total_time_ms`: Total inclusive time spent in the function across all calls
 * 
 * - `self_time_ms`: Exclusive time spent in the function (excluding time in child functions)
 * 
 * - `call_count`: Number of times the function has been called
 * 
 * - `start_time`: Timestamp when the current call started (used internally)
 * 
 * - `active`: Flag indicating if the function is currently being timed (1 = active, 0 = inactive)
 * 
 * - `hash`: Hash value computed from the function name for fast lookup
 */
typedef struct {
    char name[PERF_FUNCTION_NAME_MAX];
    long long total_time_ms;
    long long self_time_ms;
    int call_count;
    long long start_time;
    int active;
    uint32 hash;
} PerfFunction;

/**
 * @brief Call stack frame for tracking nested function calls
 *
 * This structure represents a single frame in the call stack, used to accurately
 * calculate self time by tracking time spent in child functions.
 *
 * Members:
 * 
 * - `entry`: Pointer to the PerfFunction entry for this frame
 * 
 * - `start_ticks`: Timestamp when this frame was pushed onto the stack
 * 
 * - `child_accum`: Accumulated time spent in all child function calls
 */
typedef struct {
    PerfFunction *entry;
    long long start_ticks;
    long long child_accum;
} PerfFrame;

/**
 * @brief Performance metrics structure
 *
 * This structure contains various performance metrics collected during program execution,
 * including memory usage, timing information, and throughput statistics. It's particularly
 * useful for LLM workloads where memory and inference time are critical metrics.
 *
 * Members:
 * 
 * - `peak_ram_usage`: Maximum RAM usage observed during execution (in bytes)
 * 
 * - `initial_ram_usage`: RAM usage at program start (in bytes)
 * 
 * - `final_ram_usage`: RAM usage at program end (in bytes)
 * 
 * - `start_time_ms`: Program start time in milliseconds
 * 
 * - `end_time_ms`: Program end time in milliseconds
 * 
 * - `total_inference_time_ms`: Total time spent on inference operations
 * 
 * - `total_tokens_generated`: Number of tokens generated (LLM-specific)
 * 
 * - `prompt_tokens`: Number of tokens in the input prompt (LLM-specific)
 * 
 * - `tokens_per_second`: Token generation rate (LLM-specific)
 */
typedef struct {
    // Memory and time metrics
    uint64 peak_ram_usage;
    uint64 initial_ram_usage;
    uint64 final_ram_usage;
    long long start_time_ms;
    long long end_time_ms;
    long long total_inference_time_ms;

    // Model statistics
    int total_tokens_generated;
    int prompt_tokens;
    float tokens_per_second;

    // New LLM-specific metrics
    long long time_to_first_token_ms;      // TTFT: cycles until first token output
} PerfMetrics;

extern PerfFunction *perf_functions;   /// @brief Array of profiled functions
extern int perf_num_functions;         /// @brief Number of registered profiled functions
extern PerfMetrics perf_metrics;       /// @brief Collected performance metrics
extern PerfFrame perf_call_stack[64];  /// @brief Call stack for nested function timing
extern int perf_call_depth;            /// @brief Current depth of the call stack

/**
 * @brief Initialize the profiling system
 *
 * Allocates memory for the function profiling table and resets all profiling state.
 * This function must be called before any other profiling functions. It sets up
 * the global data structures needed for function timing and call stack management.
 *
 * @note This function performs dynamic memory allocation which may fail if insufficient
 *       memory is available. Check for allocation errors in production code.
 */
void perf_init(void);

/**
 * @brief Register a function for profiling
 *
 * Adds a function to the profiling system so it can be timed. Functions must be
 * registered before they can be profiled. Duplicate registrations are ignored.
 *
 * @param name The name of the function to register (null-terminated string)
 */
void perf_register_function(const char *name);

/**
 * @brief Start timing a function
 *
 * Begins timing the specified function. This should be called at the start of
 * the function to be profiled. If the function is already being timed, this call
 * is ignored to prevent double-timing.
 *
 * @param name The name of the function to start timing
 */
void perf_start_function(const char *name);

/**
 * @brief End timing a function
 *
 * Stops timing the specified function and updates its profiling statistics.
 * This should be called at the end of the function to be profiled. It calculates
 * both inclusive and self time based on the call stack.
 *
 * @param name The name of the function to stop timing
 */
void perf_end_function(const char *name);

/**
 * @brief Print the performance report
 *
 * Generates and prints a comprehensive performance report to stdout, including
 * function timing statistics, memory usage, and throughput metrics. Functions
 * are sorted by inclusive time in descending order.
 */
void perf_print_report(void);

/**
 * @brief Update peak RAM usage
 *
 * Checks the current RAM usage and updates the peak usage metric if the current
 * usage is higher. Also updates the final RAM usage for end-of-program reporting.
 */
void perf_update_peak_ram(void);

/**
 * @brief Get current time in milliseconds
 *
 * Returns the current system time in milliseconds since some arbitrary start point.
 * This is used internally for timing measurements.
 *
 * @return Current time in milliseconds
 */
long long perf_time_in_ms(void);

/**
 * @brief Convert bytes to MB
 *
 * Utility function to convert a byte count to megabytes for display purposes.
 *
 * @param bytes Number of bytes to convert
 * @return Equivalent value in megabytes as a float
 */
float to_mb(uint64 bytes);

#endif // PERF_H