/**
 * @file perf.c
 * @author Syed Taha
 * @date November 30, 2025
 *
 * @brief Performance profiling library implementation for xv6 user programs.
 *
 * @details
 * This implementation provides call stack-based profiling to accurately measure
 * self (exclusive) vs inclusive time for functions in xv6 user programs. It supports
 * nested function calls and generates detailed performance reports including memory
 * usage, timing statistics, and throughput metrics. While designed with LLM workloads
 * in mind, it can be used for profiling any user program that requires detailed
 * function-level performance analysis.
 *
 * The library maintains a call stack to track nested function invocations, allowing
 * precise calculation of self time (time spent only in the function itself, excluding
 * time in called functions) versus inclusive time (total time including all callees).
 * This is crucial for identifying true performance bottlenecks in complex call graphs.
 *
 * Key implementation details:
 * - Uses a fixed-size call stack (64 frames) to avoid dynamic allocation overhead
 * - Employs hash-based function lookup for efficient registration and timing
 * - Supports up to 100 profiled functions with dynamic allocation
 * - Provides comprehensive reporting with sorting by inclusive time
 *
 * @note This library is currently experimental and may be inefficient.
 *       It performs dynamic memory allocation and uses simple linear searches that may
 *       not scale well for very large numbers of functions or frequent profiling calls.
 */

#include "perf.h"

PerfFunction *perf_functions = 0;
int perf_num_functions = 0;
PerfMetrics perf_metrics = {0};
PerfFrame perf_call_stack[64];
int perf_call_depth = 0;

/**
 * @brief Simple hash function for function names
 *
 * Computes a 32-bit hash value from a null-terminated string using the djb2 algorithm.
 * This hash is used for fast lookup of function entries in the profiling table.
 *
 * @param str The input string to hash (must be null-terminated)
 * @return A 32-bit unsigned integer hash value
 */
static uint32 hash_string(const char *str) {
    uint32 hash = 5381;
    int c;
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c; // hash * 33 + c
    }
    return hash;
}

void perf_init(void) {
    if (perf_functions == 0) {
        perf_functions = (PerfFunction*)malloc(PERF_MAX_FUNCTIONS * sizeof(PerfFunction));
        if (perf_functions == 0) {
            printf("perf: Failed to allocate function profiling buffer\n");
            return;
        }
        memset(perf_functions, 0, PERF_MAX_FUNCTIONS * sizeof(PerfFunction));
    }
    perf_num_functions = 0;
}

void perf_register_function(const char *name) {
    if (perf_num_functions >= PERF_MAX_FUNCTIONS) {
        printf("perf: Maximum number of profiled functions reached\n");
        return;
    }

    // Check if already registered
    uint32 hash = hash_string(name);
    for (int i = 0; i < perf_num_functions; i++) {
        if (perf_functions[i].hash == hash &&
            strcmp(perf_functions[i].name, name) == 0) {
            return; // Already registered
        }
    }

    // Add new function
    strcpy(perf_functions[perf_num_functions].name, name);
    perf_functions[perf_num_functions].hash = hash;
    perf_functions[perf_num_functions].total_time_ms = 0;
    perf_functions[perf_num_functions].self_time_ms = 0;
    perf_functions[perf_num_functions].call_count = 0;
    perf_functions[perf_num_functions].active = 0;
    perf_num_functions++;
}

void perf_start_function(const char *name) {
    uint32 hash = hash_string(name);

    for (int i = 0; i < perf_num_functions; i++) {
        if (perf_functions[i].hash == hash &&
            strcmp(perf_functions[i].name, name) == 0) {
            if (!perf_functions[i].active) {
                // Push to call stack
                if (perf_call_depth < 64) {
                    perf_call_stack[perf_call_depth].entry = &perf_functions[i];
                    perf_call_stack[perf_call_depth].start_ticks = perf_time_in_ms();
                    perf_call_stack[perf_call_depth].child_accum = 0;
                    perf_call_depth++;
                }
                perf_functions[i].start_time = perf_time_in_ms();
                perf_functions[i].active = 1;
            }
            break;
        }
    }
}

void perf_end_function(const char *name) {
    long long end_time = perf_time_in_ms();
    uint32 hash = hash_string(name);

    for (int i = 0; i < perf_num_functions; i++) {
        if (perf_functions[i].hash == hash &&
            strcmp(perf_functions[i].name, name) == 0) {
            if (perf_functions[i].active) {
                long long inclusive_time = end_time - perf_functions[i].start_time;
                perf_functions[i].total_time_ms += inclusive_time;
                perf_functions[i].call_count++;
                perf_functions[i].active = 0;

                // Pop from call stack and calculate self time
                if (perf_call_depth > 0) {
                    perf_call_depth--;
                    PerfFrame *frame = &perf_call_stack[perf_call_depth];
                    long long frame_inclusive = end_time - frame->start_ticks;
                    perf_functions[i].self_time_ms += (frame_inclusive - frame->child_accum);

                    // Add to parent's child accumulator if there's a parent
                    if (perf_call_depth > 0) {
                        perf_call_stack[perf_call_depth - 1].child_accum += frame_inclusive;
                    }
                }
            }
            break;
        }
    }
}

void perf_print_report(void) {
    long long total_time = perf_metrics.end_time_ms - perf_metrics.start_time_ms;
    if (total_time == 0) total_time = 1; // avoid division by zero

    // Calculate total self time
    long long total_self = 0;
    for (int i = 0; i < perf_num_functions; i++) {
        if (perf_functions[i].call_count > 0) {
            total_self += perf_functions[i].self_time_ms;
        }
    }
    if (total_self == 0) total_self = 1; // avoid division by zero

    // Sort functions by total time (descending)
    PerfFunction *sorted_functions = (PerfFunction*)malloc(perf_num_functions * sizeof(PerfFunction));
    if (!sorted_functions) {
        printf("perf: Failed to allocate sort buffer\n");
        return;
    }

    int sorted_count = 0;

    // Copy active profiles
    for (int i = 0; i < perf_num_functions; i++) {
        if (perf_functions[i].call_count > 0) {
            sorted_functions[sorted_count++] = perf_functions[i];
        }
    }

    // Bubble sort by total self time
    for (int i = 0; i < sorted_count - 1; i++) {
        for (int j = 0; j < sorted_count - i - 1; j++) {
            if (sorted_functions[j].self_time_ms < sorted_functions[j+1].self_time_ms) {
                PerfFunction temp = sorted_functions[j];
                sorted_functions[j] = sorted_functions[j+1];
                sorted_functions[j+1] = temp;
            }
        }
    }

    // Print function profiling table
    printf("\n==================================================================\n");
    printf("                       FUNCTION PROFILING\n");
    printf("==================================================================\n");
    printf("%20s %8s %8s %8s %8s %8s\n",
           "Function", "Calls", "Total(ms)", "Self(ms)", "Avg(ms)", "Time(%)");
    printf("------------------------------------------------------------------\n");

    for (int i = 0; i < sorted_count && i < 20; i++) {
        float time_pct = (sorted_functions[i].self_time_ms * 100.0f) / total_self;
        float avg_time = sorted_functions[i].call_count > 0 ?
                        (float)sorted_functions[i].total_time_ms / sorted_functions[i].call_count : 0;

        printf("%20s %8d %8lld %8lld %8.2f %7.2f%%\n",
               sorted_functions[i].name,
               sorted_functions[i].call_count,
               sorted_functions[i].total_time_ms,
               sorted_functions[i].self_time_ms,
               avg_time,
               time_pct);
    }
    printf("==================================================================\n");
    printf("Total Time: %lld ms\n\n", total_time);

    free(sorted_functions);

    // Print other performance metrics in a prettier format
    printf("==================================================================\n");
    printf("                     SYSTEM PERFORMANCE METRICS\n");
    printf("==================================================================\n");

    printf("\nMEMORY USAGE:\n");
    printf("  %15s %8.1f MB (%lu bytes)\n", "Initial",
           to_mb(perf_metrics.initial_ram_usage), perf_metrics.initial_ram_usage);
    printf("  %15s %8.1f MB (%lu bytes)\n", "Peak",
           to_mb(perf_metrics.peak_ram_usage), perf_metrics.peak_ram_usage);
    printf("  %15s %8.1f MB (%lu bytes)\n", "Final",
           to_mb(perf_metrics.final_ram_usage), perf_metrics.final_ram_usage);

    printf("\nTIMING:\n");
    printf("  %15s %8lld ms\n", "Total (E2EL)", total_time);
    printf("  %15s %8lld ms\n", "Inference", perf_metrics.total_inference_time_ms);

    printf("\nLLM METRICS:\n");
    printf("  %15s %8lld ms\n", "TTFT", perf_metrics.time_to_first_token_ms);

    printf("\nTHROUGHPUT:\n");
    printf("  %15s %8d tokens\n", "Generated", perf_metrics.total_tokens_generated);
    printf("  %15s %8.2f tokens/sec\n", "Rate", perf_metrics.tokens_per_second);

    printf("==================================================================\n\n");
}

void perf_update_peak_ram(void) {
    uint64 current = getramused();
    if (current > perf_metrics.peak_ram_usage) {
        perf_metrics.peak_ram_usage = current;
    }

    // Also update final RAM usage
    perf_metrics.final_ram_usage = current;
}

long long perf_time_in_ms(void) {
    // NOTE: Although some documentation claims a 100 MHz timebase,
    // xv6 on RISC-V (including QEMU) uses a 10 MHz timer for rdtime().
    //
    // rdtime() returns hardware timebase ticks:
    //     10,000,000 ticks per second
    //     10,000 ticks per millisecond
    //
    // Therefore, dividing by 10,000 converts raw ticks to milliseconds.
    return (long long)(rdtime() / 10000);
}

float to_mb(uint64 bytes) {
    return bytes / (1024.0f * 1024.0f);
}