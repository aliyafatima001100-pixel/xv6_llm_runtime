/**
 * @file threadtest.c
 * 
 * @author Syed Taha
 * @date December 16, 2025
 *
 * @brief Test suite for XV6 threading primitives and performance measurements.
 *
 * @details
 * Exercises thread creation/join/exit, mutex semantics and contention,
 * and measures basic parallel computation speedup. Outputs human-readable
 * test results and timing statistics via the test util helpers.
 */

#include "kernel/types.h"
#include "user.h"
#include "user/perf.h"

#include "testutil.h"


/**
 * @struct timing_results
 * @brief Aggregated timing breakdown for thread operations.
 */
struct timing_results {
  long long create_time; /// @brief Total time in thread_create
  long long join_time;   /// @brief Total time in thread_join
  long long exit_time;   /// @brief Estimated total time in thread_exit
  long long total_time;  /// @brief Total lifecycle time
};

/**
 * @struct count_arg
 * @brief Arguments for worker threads that perform counting work.
 */
struct count_arg {
  int iters;          /// @brief Number of increments to perform
  long long* shared;  /// @brief Pointer to shared accumulator
  int* lock;          /// @brief Pointer to mutex protecting the accumulator
};

/**
 * @struct mutex_test_arg
 * @brief Arguments for mutex contention test threads.
 */
struct mutex_test_arg {
  int iters;      /// @brief Number of increments to perform
  int* counter;   /// @brief Pointer to shared counter
  int* lock;      /// @brief Pointer to mutex protecting the counter
};


/** Global state used by test threads (for coordination and synthetic work). */
volatile int dummy_work = 0;          /// @brief Dummy work counter to simulate load
volatile int thread_ready = 0;        /// @brief Flag indicating a thread is ready
volatile int thread_should_exit = 0;  /// @brief Flag indicating a thread should exit

/**
 * @brief Worker thread that increments the integer pointed to by arg.
 * Performs increment on the shared integer.
 *
 * @param arg Pointer to an integer counter to increment.
 */
void work_thread(void* arg) {
  int* work = (int*)arg;
  (*work)++;
  thread_exit();
}

/**
 * @brief Thread that performs local counting then atomically adds to shared sum.
 * Uses the provided lock to protect the shared accumulator.
 *
 * @param arg Pointer to a {@link count_arg} describing the work to perform.
 */
void count_thread(void* arg) {
  struct count_arg* a = (struct count_arg*)arg;
  volatile long long local = 0;
  for (int i = 0; i < a->iters; i++)
    local++;

  mutex_lock(a->lock);
  *a->shared += local;
  mutex_unlock(a->lock);
  thread_exit();
}

/**
 * @brief Thread that repeatedly acquires a mutex and increments a shared counter.
 * Used to exercise contention behavior of the mutex implementation.
 *
 * @param arg Pointer to a {@link mutex_test_arg} describing the work to perform.
 */
void mutex_contention_thread(void* arg) {
  struct mutex_test_arg* a = (struct mutex_test_arg*)arg;
  for (int i = 0; i < a->iters; i++) {
    mutex_lock(a->lock);
    (*a->counter)++;
    mutex_unlock(a->lock);
  }
  thread_exit();
}


/**
 * @brief Measure cost of thread operations.
 * Runs a short workload across multiple iterations and records timing
 * breakdowns for create, join, and estimated exit costs.
 *
 * @param iterations Number of measurement iterations to perform.
 * @param results Pointer to a {@link timing_results} to populate.
 * @return 1 on success, 0 on failure (e.g., unable to create thread).
 */
int measure_thread_operations(int iterations, struct timing_results* results) {
  long long total_create = 0, total_join = 0, total_lifecycle = 0;
  int work = 0;

  info(" Measuring thread operations (%d iterations)...", iterations);

  for (int i = 0; i < iterations; i++) {
    // Measure full lifecycle with timing breakdown
    long long t0 = perf_time_in_ms();
    int tid = thread_create(work_thread, &work);
    long long t1 = perf_time_in_ms();

    if (tid < 0) {
      fail(" ERROR: Failed to create thread");
      return 0;
    }

    thread_join(tid);
    long long t2 = perf_time_in_ms();

    total_create += (t1 - t0);
    total_join += (t2 - t1);
    total_lifecycle += (t2 - t0);
  }

  results->create_time = total_create;
  results->join_time = total_join;
  results->total_time = total_lifecycle;
  results->exit_time = total_lifecycle - total_create - total_join;

  info(" Work completed: %d (expected %d)", work, iterations);
  info("   thread_create: %lld ms total, %.3f ms avg", results->create_time, results->create_time / (float)iterations);
  info("   thread_join:   %lld ms total, %.3f ms avg", results->join_time, results->join_time / (float)iterations);
  info("   thread_exit:   %lld ms total, %.3f ms avg (est.)", results->exit_time, results->exit_time / (float)iterations);
  info("   full lifecycle: %lld ms total, %.3f ms avg\n", results->total_time, results->total_time / (float)iterations);

  return 1;
}


/**
 * @brief Verify mutex serializes access correctly under contention.
 *
 * Spawns `threads` threads, each incrementing a shared counter `iters_per_thread`
 * times under a mutex and validates the final counter value.
 *
 * @param threads Number of concurrent threads to spawn.
 * @param iters_per_thread Number of increments each thread performs.
 * @return 1 if counter matches expected value, 0 otherwise.
 */
int test_mutex_correctness(int threads, int iters_per_thread) {
  info(" Testing mutex correctness (%d threads, %d iters each)...", threads, iters_per_thread);

  int counter = 0;
  int lock = 0;
  mutex_init(&lock);

  struct mutex_test_arg* args = malloc(sizeof(*args) * threads);
  int* tids = malloc(sizeof(int) * threads);

  long long t0 = perf_time_in_ms();

  for (int i = 0; i < threads; i++) {
    args[i].iters = iters_per_thread;
    args[i].counter = &counter;
    args[i].lock = &lock;
    tids[i] = thread_create(mutex_contention_thread, &args[i]);
  }

  for (int i = 0; i < threads; i++) {
    if (tids[i] > 0) thread_join(tids[i]);
  }

  long long t1 = perf_time_in_ms();
  int expected = threads * iters_per_thread;

  info("   Counter: %d (expected %d) - %s", counter, expected, counter == expected ? "PASS" : "FAIL");
  info("   Time: %lld ms, %.3f ms per operation", t1 - t0, (t1 - t0) / (float)expected);
  info("   Contention: %d threads competing\n", threads);

  free(args);
  free(tids);
  return counter == expected;
}

/**
 * @brief Measure the cost of a mutex lock/unlock pair.
 *
 * Runs a tight loop performing lock, increment, unlock and reports aggregate
 * and per-iteration timings.
 *
 * @param iterations Number of lock/unlock iterations to run.
 * @return Always returns 1.
 */
int test_mutex_overhead(int iterations) {
  info(" Measuring mutex lock/unlock overhead (%d iterations)...", iterations);

  int lock = 0;
  mutex_init(&lock);
  volatile int dummy = 0;

  long long t0 = perf_time_in_ms();
  for (int i = 0; i < iterations; i++) {
    mutex_lock(&lock);
    dummy++;
    mutex_unlock(&lock);
  }
  long long t1 = perf_time_in_ms();

  info("   Total time: %lld ms", t1 - t0);
  info("   Average per lock/unlock: %.3f ms\n", (t1 - t0) / (float)iterations);
  return 1;
}


/**
 * @brief Single-threaded counting baseline.
 *
 * Increments a local counter `target` times and returns elapsed time in ms.
 *
 * @param target Number of increments to perform.
 * @return Elapsed time in milliseconds, or -1 on error.
 */
long long count_single(int target) {
  long long t0 = perf_time_in_ms();
  volatile long long local = 0;
  for (int i = 0; i < target; i++)
    local++;
  long long t1 = perf_time_in_ms();

  if (local != target) {
    fail(" ERROR: Count mismatch in single-threaded!");
    return -1;
  }
  return t1 - t0;
}

/**
 * @brief Parallel counting using multiple threads.
 *
 * Distributes `target` increments across `num_threads` threads and accumulates
 * the result under a mutex. Returns elapsed time and writes final sum to
 * `out_sum`.
 *
 * @param target Total number of increments to perform.
 * @param num_threads Number of threads to use.
 * @param out_sum Pointer to receive the aggregated sum.
 * @return Elapsed time in milliseconds, or -1 on error.
 */
long long count_parallel(int target, int num_threads, long long* out_sum) {
  struct count_arg* args = malloc(sizeof(*args) * num_threads);
  int* tids = malloc(sizeof(int) * num_threads);

  if (!args || !tids) {
    free(args);
    free(tids);
    return -1;
  }

  int base = target / num_threads;
  int rem = target % num_threads;
  long long shared = 0;
  int lock = 0;
  mutex_init(&lock);

  long long t0 = perf_time_in_ms();

  for (int i = 0; i < num_threads; i++) {
    args[i].iters = base + (i < rem ? 1 : 0);
    args[i].shared = &shared;
    args[i].lock = &lock;
    tids[i] = thread_create(count_thread, &args[i]);
  }

  for (int i = 0; i < num_threads; i++) {
    if (tids[i] > 0) thread_join(tids[i]);
  }

  long long t1 = perf_time_in_ms();
  *out_sum = shared;

  free(args);
  free(tids);
  return t1 - t0;
}

/**
 * @brief Benchmarks parallel counting across thread counts up to `max_threads`.
 *
 * Computes a single-threaded baseline and compares multi-threaded runs for
 * speedup and efficiency. Reports results via test util helpers.
 *
 * @param target Number of total increments to perform.
 * @param max_threads Maximum number of threads to test (inclusive).
 * @return Number of thread counts that achieved a speedup >= 1.0.
 */
int test_parallel_speedup(int target, int max_threads) {
  info(" === Parallel Computation Benchmark ===");
  info(" Target count: %d\n", target);

  info(" Single-threaded baseline...");
  long long t_single = count_single(target);
  info("   Time: %lld ms\n", t_single);

  int passes = 0;

  for (int threads = 2; threads <= max_threads; threads++) {
    long long sum = 0;
    long long t_multi = count_parallel(target, threads, &sum);

    if (sum != target) {
      fail(" ERROR: Sum mismatch with %d threads! Expected %d, got %lld", threads, target, sum);
    }

    float speedup = (float)t_single / t_multi;
    float efficiency = speedup / threads * 100.0;

    info("   %d threads: %lld ms (%.2fx speedup, %.1f%% efficiency) - %s", threads, t_multi, speedup, efficiency, speedup >= 1.0 ? "FASTER" : "SLOWER");
    if (speedup >= 1.0) passes++;
  }
  printf("\n");
  return passes;
}

/*
 * @brief Worker thread that tries to access and modify a shared memory integer.
 * The argument is expected to be the address returned by shmat().
 * 
 * @param arg Pointer to the shared memory integer.
 */
void thread_shm_worker(void* arg) {
  int *p = (int*)arg;
  if (p == 0) {
    failnoex("thread_shm_worker: received NULL arg\n");
    thread_exit();
  }

  // attempt to read and increment the integer in shared memory
  int before = *p;
  printf("  thread_shm_worker: read %d at %p\n", before, p);
  *p = before + 1;
  printf("  thread_shm_worker: wrote %d at %p\n", *p, p);

  thread_exit();
}


/*
 * Test if a thread can access shared memory mapped in the parent process.
 * This intentionally reproduces the failure mode where a thread's pagetable
 * does not include mappings created after the group's size (`main_proc->sz`)
 * and thus faults on access.
 * 
 * @return 1 if the test passed, 0 otherwise.
 */
int test_thread_shm_access() {
  const char *name = "threadtest_shm";
  int shmid = shmget(name, 4096, IPC_CREAT | SHM_PERSIST);
  if (shmid < 0) {
    failnoex(" shmget failed");
    return 0;
  }

  void *shmaddr = shmat(shmid, 0, SHM_RDWR);
  if (shmaddr == (void*)-1) {
    failnoex(" shmat failed");
    return 0;
  }

  int *shared = (int*)shmaddr;
  *shared = 1234;
  printf(" parent: wrote %d at %p (shmid=%d)\n", *shared, shared, shmid);

  int tid = thread_create(thread_shm_worker, shared);
  if (tid < 0) {
    failnoex(" thread_create failed");
    shmdt(shmaddr);
    shmctl(shmid, IPC_RMID, 0);
    return 0;
  }

  thread_join(tid);

  printf(" parent: read back %d at %p\n", *shared, shared);
  int ok = 0;
  if (*shared == 1235) {
    pass(" thread could access and modify shared memory");
    ok = 1;
  } else {
    failnoex(" thread could not access shared memory (val=%d)", *shared);
  }

  if (shmdt(shmaddr) < 0) failnoex(" shmdt failed");
  if (shmctl(shmid, IPC_RMID, 0) < 0) failnoex(" shmctl IPC_RMID failed");

  printf("\n");
  return ok;
}

/**
 * @brief Measure cost of thread operations using shared memory.
 * Runs a short workload across multiple iterations and records timing
 * breakdowns for create, join, and estimated exit costs.
 *
 * @param iterations Number of measurement iterations to perform.
 * @param results Pointer to a {@link timing_results} to populate.
 * @return 1 on success, 0 on failure (e.g., unable to create thread).
 */
int measure_shm_thread_operations(int iterations, struct timing_results* results) {
  long long total_create = 0, total_join = 0, total_lifecycle = 0;

  // allocate a SHM segment for the threads to use
  const char *name = "threadtest_shm_timing";
  int shmid = shmget(name, 4096, IPC_CREAT | SHM_PERSIST);
  if (shmid < 0) {
    failnoex(" shmget failed");
    return 0;
  }

  void *shmaddr = shmat(shmid, 0, SHM_RDWR);
  if (shmaddr == (void*)-1) {
    failnoex(" shmat failed");
    shmctl(shmid, IPC_RMID, 0);
    return 0;
  }

  int* shared = (int*)shmaddr;

  info(" Measuring thread operations (%d iterations)...", iterations);

  for (int i = 0; i < iterations; i++) {
    // Measure full lifecycle with timing breakdown
    long long t0 = perf_time_in_ms();
    int tid = thread_create(work_thread, shared);
    long long t1 = perf_time_in_ms();

    if (tid < 0) {
      fail(" ERROR: Failed to create thread");
      
      if (shmdt(shmaddr) < 0) failnoex(" shmdt failed");
      if (shmctl(shmid, IPC_RMID, 0) < 0) failnoex(" shmctl IPC_RMID failed");

      return 0;
    }

    thread_join(tid);
    long long t2 = perf_time_in_ms();

    total_create += (t1 - t0);
    total_join += (t2 - t1);
    total_lifecycle += (t2 - t0);
  }

  results->create_time = total_create;
  results->join_time = total_join;
  results->total_time = total_lifecycle;
  results->exit_time = total_lifecycle - total_create - total_join;

  info(" Work completed: %d (expected %d)", *shared, iterations);
  info("   thread_create: %lld ms total, %.3f ms avg", results->create_time, results->create_time / (float)iterations);
  info("   thread_join:   %lld ms total, %.3f ms avg", results->join_time, results->join_time / (float)iterations);
  info("   thread_exit:   %lld ms total, %.3f ms avg (est.)", results->exit_time, results->exit_time / (float)iterations);
  info("   full lifecycle: %lld ms total, %.3f ms avg\n", results->total_time, results->total_time / (float)iterations);

  // cleanup
  if (shmdt(shmaddr) < 0) failnoex(" shmdt failed");
  if (shmctl(shmid, IPC_RMID, 0) < 0) failnoex(" shmctl IPC_RMID failed");

  return 1;
}

/**
 * @brief Program entry point for the THREADTEST suite.
 *
 * Runs a collection of unit and micro-bench tests validating thread and mutex
 * behavior and reports a summary result.
 *
 * @return Returns the result from `summary` (calls exit internally in helpers).
 */
int main(void) {
  set_tag("THREADTEST");
  info("========================================");
  info("    XV6 Threading System Test Suite");
  info("========================================\n");

  int total_tests = 0;
  int passed_tests = 0;

  // 1. Basic functionality test
  info("=== Basic Functionality Test ===");
  int counter = 0, lock = 0;
  mutex_init(&lock);

  struct mutex_test_arg arg1 = { 10000, &counter, &lock };
  struct mutex_test_arg arg2 = { 10000, &counter, &lock };

  int t1 = thread_create(mutex_contention_thread, &arg1);
  int t2 = thread_create(mutex_contention_thread, &arg2);
  thread_join(t1);
  thread_join(t2);

  int test_pass = (counter == 20000);
  if (test_pass) {
    pass("Counter: %d (expected 20000)\n", counter);
    passed_tests++;
  }
  else
    failnoex("Counter: %d (expected 2000)\n", counter);
  total_tests++;

  // 2. Thread operation timing
  info("=== Thread Operation Timing ===");
  struct timing_results timing; total_tests++;
  passed_tests += measure_thread_operations(100, &timing);

  // 3. Mutex tests
  info("=== Mutex Tests ===");
  total_tests += 3;
  passed_tests += test_mutex_correctness(2, 100000);
  passed_tests += test_mutex_correctness(5, 50000);
  passed_tests += test_mutex_overhead(1000000);

  // 4. Parallel computation
  total_tests += 4; // 2, 3, 4, 5 threads
  passed_tests += test_parallel_speedup(500000000, 5);

  // 5. Thread access to shared memory (reproducer for thread mapping bug)
  info("=== Thread access to shared memory test ===");
  total_tests++;
  passed_tests += test_thread_shm_access();

  // 6. Thread operation timing
  info("=== Thread Operation Timing (on SHM) ===");
  total_tests++;
  passed_tests += measure_shm_thread_operations(100, &timing);

  return summary(passed_tests, total_tests);
}
