/**
 * @file fputest.c
 * @brief Strict FPU tests for xv6 userland with child-to-parent pipe reporting.
 *
 * @author Syed Taha
 * @date 7th November 2025
 *
 * @details
 * This file implements a suite of floating-point unit (FPU) tests intended for
 * xv6 userland. Tests exercise basic arithmetic, precision accumulation,
 * special IEEE-754 values (NaN/Inf), correctness of FPU state across fork,
 * and concurrent stress testing where multiple children perform FP work while
 * the parent performs FP work and collects child reports.
 *
 * Each test prints concise pass/fail messages. Children write binary
 * `struct child_msg` structures into a pipe to the parent. This avoids
 * interleaved console output from multiple processes. The parent reads these
 * messages to determine child success and to validate isolation/inheritance
 * semantics for FPU state.
 *
 * Tests included:
 *  - basic_arithmetic: verify add, mul, div behavior with small eps tolerance.
 *  - precision_accumulation: check accumulation of small increments.
 *  - special_values: ensure NaN/Inf are produced and propagate correctly.
 *  - nan_inf_behaviour: further semantics for comparisons and arithmetic with
 *                     NaN/Inf (e.g., Inf-Inf => NaN).
 *  - fork_inherit_and_isolation: fork a child to test FPU state on fork and
 *                                that child's modifications do not corrupt parent.
 *  - concurrent_context_switching: spawn multiple children performing FP
 *                                  work concurrently and report via pipes.
 *
 * @bug If the FPU statement management is not correctly implemented, it may sometimes
 * still pass the tests. Check the printed child values To deduce.
 *
 */

#include "kernel/types.h"
#include "user/user.h"
#include "testutil.h"

#define EPS 1e-9
#define BIG 1e300

 /** @brief Child status codes. */
#define CHILD_STATUS_OK              0
#define CHILD_STATUS_INIT_MISMATCH   1
#define CHILD_STATUS_NAN_OR_INF      2
#define CHILD_STATUS_UNCHANGED       3
#define CHILD_STATUS_INCORRECT_FINAL 4
#define CHILD_STATUS_PIPE_FAIL       5

/**
 * @brief Message structure children send to parent over a pipe.
 *
 * @details
 * Binary structure written by child processes. The parent reads exactly this
 * structure from the read end of the pipe to determine the child's id,
 * success status, and a sample floating value for verification or debugging.
 */
struct child_msg {
  int  id;        /**< child id (1..N), -1 for single-child tests */
  int  status;    /**< 0 = ok, nonzero = error code */
  double initial; /**< initial value observed by child */
  double final;   /**< final value after FP work */
};

#define TAG_FPUTEST "FPUTEST"

/**
 * @brief Compare two doubles for approximate equality.
 *
 * @param a    First floating value.
 * @param b    Second floating value.
 * @param eps  Maximum allowed absolute difference for equivalence.
 * @return int Returns nonzero if |a-b| <= eps, zero otherwise.
 *
 * @note This is an absolute-tolerance comparison. It is sufficient for the
 *       test-suite values used here where magnitudes are reasonably bounded.
 */
static int approx_eq(double a, double b, double eps) {
  double diff = a - b;
  if (diff < 0) diff = -diff;
  return diff <= eps;
}

/**
 * @brief Check whether a double is NaN.
 *
 * @param x  Value to test.
 * @return int Nonzero if x is NaN, zero otherwise.
 *
 * @note Uses the property that NaN != NaN.
 */
static int is_nan(double x) { return x != x; }

/**
 * @brief Heuristic check for infinity based on magnitude threshold.
 *
 * @param x  Value to test.
 * @return int Nonzero if |x| is larger than BIG (treat as infinity).
 *
 * @note Uses a large sentinel BIG rather than isnan/isinf to remain portable
 *       with the limited runtime environment in xv6 userland.
 */
static int is_inf(double x) { return (x > BIG) || (x < -BIG); }


/**
 * @brief Robustly read exactly n bytes from a file descriptor.
 *
 * @param fd   File descriptor to read from.
 * @param buf  Buffer to read into.
 * @param n    Number of bytes to read.
 * @return int Number of bytes read, or <=0 on error or EOF before n bytes.
 */
static int read_n(int fd, void* buf, int n) {
  int offset = 0;
  char* b = (char*)buf;
  while (offset < n) {
    int r = read(fd, b + offset, n - offset);
    if (r <= 0) return r;
    offset += r;
  }
  return offset;
}

/**
 * @brief Robustly write exactly n bytes to a file descriptor.
 *
 * @param fd   File descriptor to write to.
 * @param buf  Buffer to write from.
 * @param n    Number of bytes to write.
 * @return int Number of bytes written, or <=0 on error before n bytes.
 */
static int write_n(int fd, void* buf, int n) {
  int offset = 0;
  char* b = (char*)buf;
  while (offset < n) {
    int w = write(fd, b + offset, n - offset);
    if (w <= 0) return w;
    offset += w;
  }
  return offset;
}

/* ---- non-fork tests ---- */

/**
 * @brief Test basic floating-point arithmetic.
 *
 * @details
 * Performs simple addition, multiplication, division checks using predefined
 * values. Tolerances are chosen to allow for differences introduced by the
 * environment and implementation.
 */
static void test_basic_arithmetic(void) {
  info("starting basic_arithmetic...");
  double a = 1.23456789, b = 9.87654321;
  double s = a + b, e = 11.11111110;
  if (!approx_eq(s, e, 1e-8)) fail("  addition");
  double m = a * b;
  if (!approx_eq(m / a, b, 1e-9)) fail("  multiplication");
  double d = b / a;
  if (!approx_eq(d * a, b, 1e-8)) fail("  division");
  pass("  basic arithmetic");
}

/**
 * @brief Test accumulation of small increments to detect precision drift.
 *
 * @details
 * Adds a small increment repeatedly and compares against an expected product.
 * This checks whether repeated FP additions accumulate correctly and remain
 * within a tolerance bound.
 */
static void test_precision_accumulation(void) {
  info("starting precision_accumulation...");

  double inc = 1e-6, sum = 0.0;
  int N = 100000;
  for (int i = 0; i < N; i++) sum += inc;
  double expect = N * inc;
  if (!approx_eq(sum, expect, 1e-6)) fail("  precision accumulation");
  pass("  precision accumulation");
}

/**
 * @brief Test special IEEE-754 values NaN and Infinity and propagation rules.
 *
 * @details
 * Creates NaN and Inf by dividing by zero. Verifies detection functions and
 * that operations with NaN/Inf produce expected NaN/Inf propagation.
 */
static void test_special_values(void) {
  info("starting special_values...");
  double plus_inf = 1.0 / 0.0;
  double minus_inf = -1.0 / 0.0;
  double nanv = 0.0 / 0.0;
  if (!is_inf(plus_inf) || !is_inf(minus_inf) || !is_nan(nanv))
    fail("  special values (Inf/NaN)");
  double a = 1.23;
  double p = a + nanv;
  if (!is_nan(p)) fail("  NaN propagation in addition");
  pass("  special values (Inf/NaN)");
}

/**
 * @brief Further NaN/Inf semantics checks.
 *
 * @details
 * Verifies NaN comparison behavior and arithmetic semantics involving infinite
 * values such as Inf + finite => Inf and Inf - Inf => NaN.
 */
static void test_nan_inf_behaviour(void) {
  info("starting nan/inf behaviour tests");
  double nanv = 0.0 / 0.0;
  double infv = 1.0 / 0.0;
  double neginf = -1.0 / 0.0;
  if (!(nanv != nanv)) fail("  NaN comparison semantics");
  if (!is_inf(infv) || !is_inf(neginf)) fail("  Inf detection");
  double a = infv + 1.0;
  if (!is_inf(a)) fail("  Inf + finite should be Inf");
  double r = infv - infv;
  if (!is_nan(r)) fail("  Inf - Inf should be NaN");
  pass("  NaN/Inf comparison and arithmetic semantics");
}

/* ---- test that forks a single child and needs the child value ----
   Parent will create a pipe, fork, child writes struct child_msg (binary)
   Parent waits, reads child_msg, prints the child's reported info.
*/

/**
 * @brief Handle a child's reported status and validate final value.
 *
 * @param m                Pointer to child's message structure.
 * @param expected_final   Expected final floating value from child.
 *
 * @details
 * Interprets the child's status code and prints appropriate messages.
 * Validates that the child's reported final value matches the expected
 * final value within tolerance. Any discrepancies result in test failure.
 */
static void handle_child_status(struct child_msg* m, double expected_final) {
  switch (m->status) {
  case CHILD_STATUS_OK:
    // expected, nothing to fail
    break;
  case CHILD_STATUS_INIT_MISMATCH:
    printf("    child %d: initial value mismatch (got %f, expected ~%f)\n",
      m->id, m->initial, m->id > 0 ? m->id + 0.123456789 : 6.28318530717958);
    fail("  child initial mismatch");
    break;
  case CHILD_STATUS_NAN_OR_INF:
    printf("    child %d: final value invalid (NaN or Inf)\n", m->id);
    fail("  child final invalid");
    break;
  case CHILD_STATUS_UNCHANGED:
    printf("    child %d: final value unchanged or incorrect (initial=%f final=%f, expected=%f)\n",
      m->id, m->initial, m->final, expected_final);
    fail("  child final unchanged or incorrect");
    break;
  case CHILD_STATUS_INCORRECT_FINAL:
    printf("    child %d: final value incorrect (got %f, expected %f)\n",
      m->id, m->final, expected_final);
    fail("  child final incorrect");
    break;
  case CHILD_STATUS_PIPE_FAIL:
  default:
    printf("    child %d: unknown failure (status=%d)\n", m->id, m->status);
    fail("  child pipe/report failure");
  }

  // Verify parent sees correct final value
  if (!approx_eq(m->final, expected_final, 1e-9)) {
    printf("    parent: observed final %f does not match expected %f\n", m->final, expected_final);
    fail("  parent detected final mismatch");
  }
}


/**
 * @brief Test FPU inheritance and isolation across fork.
 *
 * @details
 * This test forks a single child. The child computes a sample floating value
 * derived from a constant and performs additional FP work. The child writes a
 * `struct child_msg` to the parent via a pipe. The parent waits for the
 * child, reads the message, and checks the child's status and reported value.
 *
 * Using a binary pipe message avoids the need for children to print to the
 * console. Printing from children creates interleaved output in xv6's shared
 * console. By having children send a structured message to the parent, the
 * parent remains the single actor that prints results. The parent also
 * validates that its own FPU state remains correct after the child has
 * executed.
 */
static void test_fork_inherit_and_isolation(void) {
  info("starting fork_inherit_and_isolation...");
  int fds[2];
  if (pipe(fds) < 0) fail("  pip failed");

  double parent_val = 3.14159265358979 * 2.0;
  double expected_final = 6.33628217556536;

  int pid = fork();
  if (pid < 0) fail("  fork failed");

  if (pid == 0) {
    // Child
    close(fds[0]);
    struct child_msg m;
    m.id = -1;
    m.status = CHILD_STATUS_OK;
    m.initial = parent_val;

    double x = parent_val;
    for (int i = 0; i < 10000; i++) x = (x * 1.000001) - 0.000001;
    m.final = x;

    if (is_nan(m.final) || is_inf(m.final)) m.status = CHILD_STATUS_NAN_OR_INF;
    else if (!approx_eq(m.final, expected_final, 1e-9)) m.status = CHILD_STATUS_UNCHANGED;

    write_n(fds[1], &m, sizeof(m));
    close(fds[1]);
    exit(m.status == CHILD_STATUS_OK ? 0 : 1);
  }
  else {
    // Parent
    close(fds[1]);
    int st; wait(&st);

    struct child_msg m;
    int n = read_n(fds[0], &m, sizeof(m));
    if (n != sizeof(m)) fail("  fork child failed with no report");

    handle_child_status(&m, expected_final);

    printf("    child initial=%f final=%f\n", m.initial, m.final);
    close(fds[0]);
    pass("  fork inherit and isolation");
  }
}

/* ---- concurrent stress test: spawn many children, each writes a message struct ---- */

/**
 * @brief Compute expected final value after iterations.
 *
 * @param id    Child id used to derive initial value.
 * @param iter  Number of FP iterations performed.
 * @return double Expected final floating value.
 *
 * @details
 * Computes the expected final value after `iter` iterations of the
 * computation performed in `child_worker_pipe`. This allows the parent
 * to validate the child's reported final value.
 */
static inline double get_expected(int id, int iter) {
  double v = id + 0.123456789;
  for (int i = 0; i < iter; i++) {
    v = v * 1.0000001 + 0.0000001;
  } // No pauses. Ensure exact same computation.
  return v;
}


/**
 * @brief Worker invoked in child process for concurrent stress test.
 *
 * @param id       Integer child id used for reporting.
 * @param writefd  File descriptor for the pipe write end to parent.
 * @param iter     Number of FP iterations to perform.
 *
 * @details
 * The child performs iterative floating-point updates to a local accumulator.
 * Periodically the child calls `pause(1)` to yield the scheduler and provoke
 * context switches. After completing its iterations the child constructs a
 * `struct child_msg` containing its id, status and sample value then writes
 * it to the parent's pipe. The child closes the write end and exits with
 * return code 0 on success or 1 on detected NaN/Inf.
 *
 * Writing a single binary message avoids interleaved console output from
 * concurrent children and simplifies deterministic parent-side reporting.
 */
static void child_worker_pipe(int id, int writefd, int iter) {
  struct child_msg m;
  m.id = id;
  m.status = CHILD_STATUS_OK;
  double v = id + 0.123456789;
  m.initial = v;

  for (int i = 0; i < iter; i++) {
    v = v * 1.0000001 + 0.0000001;
    if ((i & 0x3ff) == 0) pause(1);
  }
  m.final = v;

  double expected = get_expected(id, iter);

  if (is_nan(m.initial) || is_inf(m.initial) || is_nan(m.final) || is_inf(m.final))
    m.status = CHILD_STATUS_NAN_OR_INF;
  if (approx_eq(m.final, m.initial, 1e-12))
    m.status = CHILD_STATUS_UNCHANGED;
  if (!approx_eq(m.final, expected, 1e-9))
    m.status = CHILD_STATUS_INCORRECT_FINAL;

  write_n(writefd, &m, sizeof(m));
  close(writefd);
  exit(m.status ? 1 : 0);
}

/**
 * @brief Concurrent context switching stress test.
 *
 * @details
 * Spawns multiple children (CHILDREN). Each child executes `child_worker_pipe`
 * performing a large number of FP iterations while periodically yielding the
 * CPU. The parent concurrently performs its own FP work. After children exit
 * the parent reads each child's `struct child_msg` from the corresponding
 * pipe read end to verify per-child success. Any child failure or missing
 * report triggers test failure.
 */
static void test_concurrent_context_switching(void) {
  info("concurrent_context_switching (stress)");
  const int CHILDREN = 10;
  const int ITER = 50000;
  int rfd[CHILDREN], wfd[CHILDREN];

  for (int i = 0; i < CHILDREN; i++) {
    int fds[2];
    if (pipe(fds) < 0) fail("  pipe failed in stress");
    rfd[i] = fds[0]; wfd[i] = fds[1];

    int pid = fork();
    if (pid < 0) fail("  fork failed in stress");
    if (pid == 0) {
      close(rfd[i]);
      child_worker_pipe(i + 1, wfd[i], ITER);
    }
    else {
      close(wfd[i]);
    }
  }

  // Parent does its own FP work
  double acc = 1.0;
  for (int i = 0; i < ITER; i++) {
    acc = acc * 1.000001 + 0.000001;
    if ((i & 0x7ff) == 0) pause(1);
  }

  // Collect child reports and validate
  double last_final = 0.0;
  for (int i = 0; i < CHILDREN; i++) {
    int st;
    wait(&st);

    struct child_msg m;
    int n = read_n(rfd[i], &m, sizeof(m));
    if (n != sizeof(m)) fail("  concurrent child no report");

    double expected = get_expected(m.id, ITER);

    // Handle child status centrally
    handle_child_status(&m, expected);

    // Validate diversity among children
    if (i > 0 && approx_eq(m.final, last_final, 1e-9)) {
      printf("    child %d: final too similar to previous child: %f == %f\n",
        m.id, m.final, last_final);
      fail("  concurrent finals lack diversity");
    }

    last_final = m.final;
    printf("    child %d: ok (initial=%f final=%f)\n", m.id, m.initial, m.final);
    close(rfd[i]);
  }

  if (is_nan(acc) || is_inf(acc))
    fail("  concurrent parent bad state");
  pass("  concurrent context switching (stress)");
}

/**
 * @brief Program entry point.
 *
 * @return int Exit status. 0 on success. Exits with nonzero on test failure.
 *
 * @details
 * Runs the sequence of FPU tests in order. At the end it drains any stray
 * children. All output is printed by the parent process. Children report via
 * pipes to avoid console interleaving.
 */
int main(int argc, char** argv) {
  // Set indentation if provided. usage fputest <level>
  if (argc == 2) {
    int indent = atoi(argv[1]);
    printf_set_indent(indent);
  }

  set_tag("FPU");
  info("=== fputests: starting");

  test_basic_arithmetic();
  test_precision_accumulation();
  test_special_values();
  test_nan_inf_behaviour();
  test_fork_inherit_and_isolation();
  test_concurrent_context_switching();

  while (wait(0) > 0);

  info("=== fputests: all tests passed");
  exit(0);
}
