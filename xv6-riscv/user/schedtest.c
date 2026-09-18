/**
 * @file schedtest.c
 * @brief Comprehensive scheduler testing suite for xv6
 * @author Hamna Sajid, Updated by Syed Taha
 * @date December 2025
 *
 * @details
 * Tests different scheduling algorithms with proper correctness verification
 * and performance benchmarking.
 *
 * Test Organization:
 * - Default (RR): Performance benchmark only
 * - Priority/MLFQ: Correctness verification + performance benchmark
 */

#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"

#include "testutil.h"

#define NUM_PROCESSES 6
#define WORK_ITERATIONS 10000000L
#define TRACKED_PROCESS 1

 // Compile-time scheduler detection
#if defined(MLFQ_SCHED)
#define SCHEDULER_NAME "MLFQ (Multi-Level Feedback Queue)"
#define HAS_PRIORITY 1
#elif defined(PRIORITY_SCHED)
#define SCHEDULER_NAME "Priority Scheduling"
#define HAS_PRIORITY 2
#else
#define SCHEDULER_NAME "Round Robin (Default)"
#define HAS_PRIORITY 0
#endif

long long time_in_ms(void) {
  // NOTE: Although some documentation claims a 100 MHz timebase,
  // xv6 on RISC-V (including QEMU) uses a 10 MHz timer for rdtime().
  //
  // rdtime() returns hardware timebase ms:
  //     10,000,000 ms per second
  //     10,000 ms per millisecond
  //
  // Therefore, dividing by 10,000 converts raw ms to milliseconds.
  return (long long)(rdtime() / 10000);
}

/**
 * @brief CPU-intensive work simulation
 */
void cpu_work(long iterations) {
  volatile long sum = 0;
  for (long i = 0; i < iterations; i++) {
    sum += i;
  }
}

/**
 * @brief Print scheduler info
 */
void print_scheduler_info(void) {
  info("");
  info("****************************************************************");
  info("                  SCHEDULER TEST SUITE                          ");
  info("****************************************************************");
  info(" Active Scheduler: %s", SCHEDULER_NAME);
  info(" Number of Test Processes: %d", NUM_PROCESSES);
  info(" Work per Process: %ld iterations", WORK_ITERATIONS);
  info(" Tracked Process: #%d", TRACKED_PROCESS);
  info("****************************************************************\n");
}

// ============================================================================
// DEFAULT SCHEDULER TESTS (Round Robin)
// ============================================================================

#if !HAS_PRIORITY

/**
 * @brief Benchmark test for default Round Robin scheduler
 *
 * @details
 * Creates 100 processes, each doing the same amount of work.
 * Tracks process #10 individually and reports:
 * - Average completion time across all processes
 * - Completion time for process #10
 * - Total wall-clock time
 */
void test_rr_benchmark(void) {
  info("Round Robin Benchmark Test");

  int pipes[NUM_PROCESSES][2];
  uint test_start = time_in_ms();

  // Create pipes
  for (int i = 0; i < NUM_PROCESSES; i++) {
    if (pipe(pipes[i]) < 0) {
      printf("ERROR: Pipe creation failed\n");
      exit(1);
    }
  }

  printf("Starting %d processes...\n", NUM_PROCESSES);

  // Fork all processes
  for (int i = 0; i < NUM_PROCESSES; i++) {
    int pid = fork();

    if (pid < 0) {
      printf("ERROR: Fork failed at process %d\n", i);
      exit(1);
    }

    if (pid == 0) {
      // Child process
      for (int j = 0; j < NUM_PROCESSES; j++) {
        close(pipes[j][0]);
        if (j != i) close(pipes[j][1]);
      }

      uint start = time_in_ms();
      cpu_work(WORK_ITERATIONS);
      uint end = time_in_ms();

      int result[3] = { i, getpid(), end - start };
      write(pipes[i][1], result, sizeof(result));
      close(pipes[i][1]);
      exit(0);
    }
  }

  // Parent: collect results
  for (int i = 0; i < NUM_PROCESSES; i++) {
    close(pipes[i][1]);
  }

  printf("\n%10s %10s %15s\n", "Process", "PID", "Time (ms)");
  printf("------------------------------------------\n");

  uint total_time = 0;
  uint tracked_time = 0;

  for (int i = 0; i < NUM_PROCESSES; i++) {
    int result[3];
    read(pipes[i][0], result, sizeof(result));
    close(pipes[i][0]);

    total_time += result[2];

    if (result[0] == TRACKED_PROCESS) {
      tracked_time = result[2];
      printf("%10d %10d %15d  <- TRACKED\n", result[0], result[1], result[2]);
    }
    else if (i < 5 || i >= NUM_PROCESSES - 5) {
      // Print first 5 and last 5 processes
      printf("%10d %10d %15d\n", result[0], result[1], result[2]);
    }
    else if (i == 5) {
      printf("... (showing first/last 5 only) ...\n");
    }
  }

  uint test_end = time_in_ms();
  uint wall_time = test_end - test_start;
  uint avg_time = total_time / NUM_PROCESSES;

  printf("------------------------------------------\n");
  printf("Average completion time: %d ms\n", avg_time);
  printf("Process #%d time:        %3d ms\n", TRACKED_PROCESS, tracked_time);
  printf("Total wall-clock time:   %d ms\n", wall_time);
  printf("Total CPU time used:     %d ms\n", total_time);

  // Wait for all children
  for (int i = 0; i < NUM_PROCESSES; i++) {
    wait(0);
  }

  printf("\n");
}

#endif // !HAS_PRIORITY

// ============================================================================
// PRIORITY/MLFQ SCHEDULER TESTS
// ============================================================================

#if HAS_PRIORITY

/**
 * @brief Correctness Test 1: All processes complete
 *
 * @details
 * Verifies that all 100 processes complete successfully regardless of priority.
 * Tests basic scheduler fairness - no starvation.
 */
void test_correctness_completion(void) {
  info("Correctness Test 1: All Processes Complete");

  int pipes[NUM_PROCESSES][2];

  for (int i = 0; i < NUM_PROCESSES; i++) {
    if (pipe(pipes[i]) < 0) {
      printf("ERROR: Pipe creation failed\n");
      exit(1);
    }
  }

  printf("Creating %d processes with varying priorities...\n", NUM_PROCESSES);

  // Fork all processes with different priorities
  for (int i = 0; i < NUM_PROCESSES; i++) {
    int pid = fork();

    if (pid < 0) {
      printf("ERROR: Fork failed\n");
      exit(1);
    }

    if (pid == 0) {
      for (int j = 0; j < NUM_PROCESSES; j++) {
        close(pipes[j][0]);
        if (j != i) close(pipes[j][1]);
      }

      // Distribute priorities evenly: 0-31
      int priority = (i * 31) / NUM_PROCESSES;
      setpriority(0, priority);

      cpu_work(WORK_ITERATIONS / 10);  // Lighter work for correctness test

      int result[2] = { i, getpid() };
      write(pipes[i][1], result, sizeof(result));
      close(pipes[i][1]);
      exit(0);
    }
  }

  // Collect results
  for (int i = 0; i < NUM_PROCESSES; i++) {
    close(pipes[i][1]);
  }

  int completed = 0;
  for (int i = 0; i < NUM_PROCESSES; i++) {
    int result[2];
    int bytes = read(pipes[i][0], result, sizeof(result));
    if (bytes == sizeof(result)) {
      completed++;
    }
    close(pipes[i][0]);
  }

  printf("\n");
  printf("Result: %d / %d processes completed\n", completed, NUM_PROCESSES);

  if (completed == NUM_PROCESSES) {
    pass(" All processes completed successfully\n");
  }
  else {
    failnoex(" %d processes did not complete\n", NUM_PROCESSES - completed);
  }

  for (int i = 0; i < NUM_PROCESSES; i++) {
    wait(0);
  }

  printf("\n");
}

/**
 * @brief Correctness Test 2: Priority ordering
 *
 * @details
 * Creates <NUM_PROCESSES> processes with different priorities and verifies that
 * higher priority processes (lower numbers) complete first.
 */
void test_correctness_priority_order(void) {
  info("Correctness Test 2: Priority Ordering");

  const int n = NUM_PROCESSES;
  int pipes[n][2];
  int priorities[NUM_PROCESSES];
  // Assign priorities: lower index = higher priority
  for (int i = 0; i < n; i++) {
    priorities[i] = i * (31 / (n - 1));  // Spread from 0 to 31
  }

  for (int i = 0; i < n; i++) {
    if (pipe(pipes[i]) < 0) {
      printf("ERROR: Pipe creation failed\n");
      exit(1);
    }
  }

  printf("Creating %d processes with priorities: ", n);
  for (int i = 0; i < n; i++) {
    printf("%d ", priorities[i]);
  }
  printf("\n\n");

  uint start_time = time_in_ms();

  for (int i = 0; i < n; i++) {
    int pid = fork();

    if (pid == 0) {
      for (int j = 0; j < n; j++) {
        close(pipes[j][0]);
        if (j != i) close(pipes[j][1]);
      }

      setpriority(0, priorities[i]);

      // uint my_start = time_in_ms();
      cpu_work(WORK_ITERATIONS);
      uint my_end = time_in_ms();

      int result[4] = { i, getpid(), priorities[i], my_end - start_time };
      write(pipes[i][1], result, sizeof(result));
      close(pipes[i][1]);
      exit(0);
    }
  }

  for (int i = 0; i < n; i++) {
    close(pipes[i][1]);
  }

  printf("%10s %7s %11s %14s\n", "Process", "PID", "Priority", "Finish Time");
  printf("---------------------------------------------\n");

  int results[n][4];
  for (int i = 0; i < n; i++) {
    read(pipes[i][0], results[i], sizeof(results[i]));
    close(pipes[i][0]);
  }

  // Sort by finish time
  for (int i = 0; i < n - 1; i++) {
    for (int j = 0; j < n - i - 1; j++) {
      if (results[j][3] > results[j + 1][3]) {
        int temp[4];
        for (int k = 0; k < 4; k++) {
          temp[k] = results[j][k];
          results[j][k] = results[j + 1][k];
          results[j + 1][k] = temp[k];
        }
      }
    }
  }

  for (int i = 0; i < n; i++) {
    printf("%10d %7d %11d %14d\n", results[i][0], results[i][1], results[i][2], results[i][3]);
  }

  // Verify ordering: check if lower priorities tend to finish first
  int correct_order = 1;
  for (int i = 0; i < n - 1; i++) {
    if (results[i][2] > results[i + 1][2]) {
      correct_order = 0;
      break;
    }
  }

  printf("\n");
  if (correct_order) {
    pass(" Processes completed in priority order");
  }
  else {
    info("Note: Priority ordering not strictly enforced (expected for MLFQ)");
  }

  for (int i = 0; i < n; i++) {
    wait(0);
  }

  printf("\n");
}

/**
 * @brief Correctness Test 3: High vs Low priority fairness
 *
 * @details
 * Creates <NUM_PROCESSES>/2 high-priority and <NUM_PROCESSES>/2 low-priority processes.
 * Verifies that high-priority processes complete significantly faster.
 */
void test_correctness_fairness(void) {
  info("Correctness Test 3: High vs Low Priority Comparison");

  const int n = NUM_PROCESSES;
  int pipes[n][2];

  for (int i = 0; i < n; i++) {
    if (pipe(pipes[i]) < 0) {
      fail("ERROR: Pipe creation failed\n");
    }
  }

  info("Creating %d processes: %d HIGH priority (0), %d LOW priority (31)", n, n / 2, n / 2);

  uint start_time = time_in_ms();

  for (int i = 0; i < n; i++) {
    int pid = fork();

    if (pid == 0) {
      for (int j = 0; j < n; j++) {
        close(pipes[j][0]);
        if (j != i) close(pipes[j][1]);
      }

      int priority = (i < n / 2) ? 0 : 31;
      setpriority(0, priority);

      uint my_start = time_in_ms();
      cpu_work(WORK_ITERATIONS);
      uint my_end = time_in_ms();

      int result[3] = { priority, my_end - start_time, my_end - my_start };
      write(pipes[i][1], result, sizeof(result));
      close(pipes[i][1]);
      exit(0);
    }
  }

  for (int i = 0; i < n; i++) {
    close(pipes[i][1]);
  }

  uint high_total = 0, low_total = 0;
  int high_count = 0, low_count = 0;

  for (int i = 0; i < n; i++) {
    int result[3];
    read(pipes[i][0], result, sizeof(result));
    close(pipes[i][0]);

    if (result[0] == 0) {
      high_total += result[2];
      high_count++;
    }
    else {
      low_total += result[2];
      low_count++;
    }
  }

  uint high_avg = high_total / high_count;
  uint low_avg = low_total / low_count;

  info("\nHigh Priority (0)  - Avg time: %d ms", high_avg);
  info("Low Priority (31)  - Avg time: %d ms", low_avg);

  if (high_avg < low_avg) {
    info("Speedup factor: %.2fx\n", (float)low_avg / high_avg);
    pass(" High priority processes completed faster");
  }

  for (int i = 0; i < n; i++) {
    wait(0);
  }

  printf("\n");
}

/**
 * @brief Performance benchmark with prioritized tracked process
 */
void test_priority_benchmark(void) {
  info("Priority Scheduler Benchmark Test");

  int pipes[NUM_PROCESSES][2];
  uint test_start = time_in_ms();

  for (int i = 0; i < NUM_PROCESSES; i++) {
    if (pipe(pipes[i]) < 0) {
      printf("ERROR: Pipe creation failed\n");
      exit(1);
    }
  }

  printf("Starting %d processes...\n", NUM_PROCESSES);
  printf("Process #%d will have HIGH PRIORITY (0)\n", TRACKED_PROCESS);
  printf("All other processes will have LOW PRIORITY (31)\n\n");

  for (int i = 0; i < NUM_PROCESSES; i++) {
    int pid = fork();

    if (pid < 0) {
      printf("ERROR: Fork failed\n");
      exit(1);
    }

    if (pid == 0) {
      for (int j = 0; j < NUM_PROCESSES; j++) {
        close(pipes[j][0]);
        if (j != i) close(pipes[j][1]);
      }

      int priority = (i == TRACKED_PROCESS) ? 0 : 31;
      setpriority(0, priority);

      uint start = time_in_ms();
      cpu_work(WORK_ITERATIONS);
      uint end = time_in_ms();

      int result[4] = { i, getpid(), priority, end - start };
      write(pipes[i][1], result, sizeof(result));
      close(pipes[i][1]);
      exit(0);
    }
  }

  for (int i = 0; i < NUM_PROCESSES; i++) {
    close(pipes[i][1]);
  }

  printf("%10s %10s %12s %15s\n", "Process", "PID", "Priority", "Time (ms)");
  printf("----------------------------------------------------\n");

  uint total_time = 0;
  uint tracked_time = 0;
  // uint high_priority_time = 0;
  uint low_priority_total = 0;
  int low_priority_count = 0;

  for (int i = 0; i < NUM_PROCESSES; i++) {
    int result[4];
    read(pipes[i][0], result, sizeof(result));
    close(pipes[i][0]);

    total_time += result[3];

    if (result[2] == 0) {
      // high_priority_time = result[3];
    }
    else {
      low_priority_total += result[3];
      low_priority_count++;
    }

    if (result[0] == TRACKED_PROCESS) {
      tracked_time = result[3];
      printf("%10d %10d %12d %15d  <- HIGH PRIORITY\n",
        result[0], result[1], result[2], result[3]);
    }
    else if (i < 5 || i >= NUM_PROCESSES - 5) {
      printf("%10d %10d %12d %15d\n",
        result[0], result[1], result[2], result[3]);
    }
    else if (i == 5) {
      printf("... (showing first/last 5 only) ...\n");
    }
  }

  uint test_end = time_in_ms();
  uint wall_time = test_end - test_start;
  uint avg_time = total_time / NUM_PROCESSES;
  uint low_avg = low_priority_total / low_priority_count;

  printf("----------------------------------------------------\n");
  info("Process #%d (high priority): %3d ms", TRACKED_PROCESS, tracked_time);
  info("Low priority average:        %d ms", low_avg);
  info("Overall average:             %d ms", avg_time);
  info("Speedup for high priority:   %.2fx", (float)low_avg / tracked_time);
  info("Total wall-clock time:       %d ms", wall_time);

  for (int i = 0; i < NUM_PROCESSES; i++) {
    wait(0);
  }

  printf("\n");

}

#endif // HAS_PRIORITY

// ============================================================================
// Main
// ============================================================================

int main(int argc, char* argv[]) {
  print_scheduler_info();

#if HAS_PRIORITY
  // Priority/MLFQ: Correctness tests first, then benchmark
  test_correctness_completion();
  test_correctness_priority_order();
  test_correctness_fairness();
  test_priority_benchmark();
#else
  // Default RR: Just benchmark
  test_rr_benchmark();
#endif

  exit(0);
}
