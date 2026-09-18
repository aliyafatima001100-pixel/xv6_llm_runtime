/**
 * @file runtests.c
 * @brief Sequential test runner for xv6 userland programs.
 *
 * @author Syed Taha
 * @date 10th November 2025
 *
 * @details
 * This program runs a list of xv6 userland test programs one by one,
 * collects their exit statuses, and prints pass/fail messages for each.
 * A summary of all tests run is displayed at the end.
 *
 * Tests are defined in a null-terminated array of program names. Each
 * test is executed, and success is determined by an exit code of 0.
 */

#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"

#include "testutil.h"

/** 
 * @brief Array of test program names to run.
 * @details Null-terminated list of executable names. Each program is run
 *          sequentially in its own child process.
 */
char *tests[] = {
  "fputest",
  "testxstdlib",
  "testxmath",
  "testxstrlib",
  "testsha",
  0   // null-terminated
};

/**
 * @brief Main entry point for the test runner.
 *
 * @details
 * Iterates through the `tests` array, forks a child for each test, executes
 * the test program via `exec`, waits for the child to finish, and prints a
 * pass/fail message using `testutil` helpers. Finally, prints a summary of all
 * tests run.
 *
 * @return Exit code 0 if all tests pass, 1 otherwise.
 */
int main(void) {
  int total = 0;
  int passed = 0;

  for (int i = 0; tests[i]; i++) {
    char* test = tests[i];
    total++;
    printf("==> Running test: %s\n", test);

    int pid = fork();
    if (pid < 0) {
      printf("fork failed for %s\n", test);
      continue;
    }

    if (pid == 0) {
      // Child: prepare argv for xv6 exec
      char* argv[2] = { test, 0 };
      exec(test, argv);

      // If exec fails
      printf("exec failed for %s\n", test);
      exit(127);
    }

    // Parent: wait for child
    int st;
    wait(&st);

    if (st == 0) {
      pass("  %s", test);
      passed++;
    } else {
      failnoex("  %s", test);
    }
  }

  printf("\n=== Summary: %d/%d tests passed ===\n\n", passed, total);
  exit(passed == total ? 0 : 1);
}
