/**
 * @file testperf.c
 * @author Syed Taha
 * @date November 30, 2025
 *
 * @brief Test harness for the performance profiling library.
 *
 * @details
 * This program demonstrates the functionality of the perf profiling library by
 * executing nested function calls with varying computational loads. It showcases
 * the library's ability to accurately measure self (exclusive) time versus
 * inclusive time in complex call graphs, which is essential for identifying
 * performance bottlenecks in nested function hierarchies.
 *
 * The test creates a call tree: top_function -> middle_function -> leaf_function,
 * with additional direct calls to demonstrate different profiling scenarios.
 * Each function performs CPU-intensive work to generate measurable timing data.
 */

#include "kernel/types.h"
#include "user/user.h"
#include "user/perf.h"

volatile int global_result = 0;

/**
 * @brief Leaf function in the call hierarchy
 *
 * Performs CPU-intensive computation to simulate work. This function represents
 * the bottom level of the call stack and has no child function calls.
 */
void leaf_function() {
    perf_start_function("leaf_function");
    volatile int sum = 0;
    for(volatile int i = 0; i < 100000; i++) {
        sum += i;
    }
    global_result += sum;
    perf_end_function("leaf_function");
}

/**
 * @brief Middle-level function that calls leaf functions
 *
 * Calls leaf_function twice and performs additional computation. This demonstrates
 * how the profiler tracks time spent in child functions versus self time.
 */
void middle_function() {
    perf_start_function("middle_function");
    // Call leaf twice
    leaf_function();
    leaf_function();
    // Some work
    volatile int sum = 0;
    for(volatile int i = 0; i < 50000; i++) {
        sum += i * 2;
    }
    global_result += sum;
    perf_end_function("middle_function");
}

/**
 * @brief Top-level function in the call hierarchy
 *
 * Calls middle_function twice, leaf_function once, and performs computation.
 * This creates a complex call graph to test the profiler's call stack handling.
 */
void top_function() {
    perf_start_function("top_function");
    // Call middle twice
    middle_function();
    middle_function();
    // Call leaf once more
    leaf_function();
    // Some work
    volatile int sum = 0;
    for(volatile int i = 0; i < 25000; i++) {
        sum += i * 3;
    }
    global_result += sum;
    perf_end_function("top_function");
}

/**
 * @brief High-workload function called independently
 *
 * Performs significant computation without calling other profiled functions.
 * Used to demonstrate profiling of functions with different execution times.
 */
void hot_function() {
    perf_start_function("hot_function");
    volatile int sum = 0;
    for(volatile int i = 0; i < 2000000; i++) {
        sum += i;
    }
    global_result += sum;
    perf_end_function("hot_function");
}

/**
 * @brief Main test harness entry point
 *
 * Initializes the profiler, registers functions, runs the test sequence,
 * and generates the performance report.
 *
 * @param argc Argument count (unused)
 * @param argv Argument vector (unused)
 * @return Always returns 0 (calls exit(0))
 */
int main(int argc, char *argv[]) {
    perf_init();

    // Register functions for profiling
    perf_register_function("top_function");
    perf_register_function("middle_function");
    perf_register_function("leaf_function");
    perf_register_function("hot_function");

    perf_metrics.start_time_ms = perf_time_in_ms();

    printf("Running performance test with nested function calls...\n");

    for(int i = 0; i < 3; i++) {
        top_function();
        hot_function();
    }

    perf_metrics.end_time_ms = perf_time_in_ms();
    perf_metrics.final_ram_usage = getramused();

    printf("Done! Result = %d\n", global_result);

    perf_print_report();

    exit(0);
}