/**
 * @file testshm.c
 * @brief Comprehensive shared memory tests for xv6 userland with persistence and lazy deletion.
 *
 * @author Syed Taha
 * @date 27th November 2025
 *
 * @details
 * This file implements a suite of shared memory tests for xv6 userland, focusing
 * on POSIX-compliant shared memory operations including shmget, shmat, shmdt,
 * and shmctl with IPC_RMID for lazy deletion. Tests verify persistence across
 * processes, proper cleanup, and large buffer handling.
 *
 * Tests exercise:
 * - Basic shared memory creation and persistence across processes
 * - Lazy deletion semantics with IPC_RMID
 * - Large buffer allocation and verification
 * - Proper cleanup and resource management
 *
 * Each test spawns child processes to verify shared memory behavior and uses
 * testutil.h for consistent colored output formatting.
 */

#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"
#include "testutil.h"

 /** @brief Test data string written to shared memory segments. */
#define TEST_DATA "Hello from persistent shared memory!"
/** @brief Name of the test segment for basic persistence tests. */
#define TEST_SEGMENT "persistent_test"
/** @brief Name of the test segment for large buffer tests. */
#define LARGE_SEGMENT "large_test"
/** @brief Size of large buffer test (~60MB for LLM weights). */
#define LARGE_SIZE (60816028)  // ~60MB (size of llm weights)

/**
 * @brief Helper function to get shared memory address with error handling.
 *
 * @param segment_name Name of the shared memory segment.
 * @param size Size of the segment in bytes.
 * @param flags Flags for shmget operation.
 * @param shmid Pointer to store the shared memory ID.
 * @return void* Mapped address on success, (void*)-1 on failure.
 *
 * @details
 * Convenience function that combines shmget and shmat operations with
 * consistent error handling and reporting.
 */
void* get_shmaddr(const char* segment_name, uint64 size, int flags, int* shmid) {
  *shmid = shmget(segment_name, size, flags);
  if (*shmid < 0) {
    failnoex("  shmget failed");
    return (void*)-1;
  }

  void* shmaddr = shmat(*shmid, 0, SHM_RDWR);
  if (shmaddr == (void*)-1) {
    failnoex("  shmat failed");
    return (void*)-1;
  }

  return shmaddr;
}

/**
 * @brief Test basic shared memory creation and persistence.
 *
 * @details
 * Spawns a child process that creates a persistent shared memory segment,
 * writes test data to it, and detaches. Verifies that the shared memory
 * persists after the child exits and can be accessed by other processes.
 *
 * @return int 0 on success, 1 on failure.
 */
int test_child_write() {
  info(" Starting child write test...");

  int pid, status;

  pid = fork();
  if (pid < 0) {
    failnoex(" fork failed");
    return 1;
  }

  if (pid == 0) {
    // Child process
    int shmid = -1;
    void* shmaddr;
    char* data;

    info("  Creating persistent shared memory segment in child process...");

    // Create shared memory segment with SHM_PERSIST
    shmaddr = get_shmaddr(TEST_SEGMENT, 4096, IPC_CREAT | SHM_PERSIST, &shmid);

    // Write test data
    data = (char*)shmaddr;
    strcpy(data, TEST_DATA);
    printf("  wrote \"%s\" to shmaddr %p with shmid %d\n", TEST_DATA, shmaddr, shmid);

    // Detach (but memory should persist due to SHM_PERSIST)
    if (shmdt(shmaddr) < 0) fail("  shmdt failed");
    info("  shmdt succeeded, memory should persist");

    exit(0);
  }

  // Parent waits for child to complete
  wait(&status);
  if (status != 0) {
    failnoex(" Child exited with error");
    return 1;
  }

  pass(" Child created persistent shared memory");
  return 0;
}

/**
 * @brief Test shared memory access and lazy deletion marking.
 *
 * @details
 * Spawns a child process that accesses the persistent shared memory created
 * by the previous test, verifies the data integrity, and marks the segment
 * for lazy deletion using IPC_RMID. The segment should remain accessible
 * until all processes detach.
 *
 * @return int 0 on success, 1 on failure.
 */
int test_child_read_and_mark_delete() {
  info(" Starting child read and mark for deletion test...");
  int pid, status;

  pid = fork();
  if (pid < 0) {
    failnoex(" fork failed");
    return 1;
  }

  if (pid == 0) {
    // Child process
    int shmid = 0;
    void* shmaddr;
    char* data;

    info("  Attempting to access persistent shared memory...");

    // Get the shared memory ID for the existing segment (no SHM_PERSIST flag)
    shmaddr = get_shmaddr(TEST_SEGMENT, 4096, 0, &shmid);

    // Read and verify the data
    data = (char*)shmaddr;
    printf("  read \"%s\" from shmaddr %p with shmid %d\n", data, shmaddr, shmid);

    if (strcmp(data, TEST_DATA) == 0) {
      pass("  Data matches! Persistent shared memory works!");
    }
    else {
      failnoex("  Data mismatch!");
    }

    // Mark the segment for deletion (IPC_RMID) - but don't detach yet
    if (shmctl(shmid, IPC_RMID, 0) < 0) fail("  shmctl IPC_RMID failed");
    info("  Marked segment for deletion with IPC_RMID");

    // Detach - this should trigger actual deletion since refcount becomes 0
    if (shmdt(shmaddr) < 0) fail("  shmdt failed");
    info("  shmdt succeeded - segment should now be deleted");

    exit(0);
  }

  // Parent waits for child to complete
  wait(&status);
  if (status != 0) {
    failnoex(" Child exited with error");
    return 1;
  }

  pass(" Child accessed persistent memory and marked for deletion");
  return 0;
}

/**
 * @brief Test lazy deletion verification.
 *
 * @details
 * Spawns a child process that attempts to access the shared memory segment
 * marked for deletion in the previous test. Verifies that the segment has
 * been properly deleted and is no longer accessible.
 *
 * @return int 0 on success, 1 on failure.
 */
int test_child_verify_deleted() {
  info(" Starting child verify deleted test...");
  int pid, status;


  pid = fork();
  if (pid < 0) {
    failnoex(" fork failed");
    return 1;
  }

  if (pid == 0) {
    // Child process
    int shmid = -1;

    info("  Testing if shared memory was properly deleted...");

    // Try to get the shared memory segment
    shmid = shmget(TEST_SEGMENT, 4096, 0);  // Don't create, just get existing
    if (shmid < 0) {
      pass("  shmget failed as expected (segment was deleted)");
      exit(0);  // This is the expected behavior
    }

    // If we get here, the segment still exists, which is bad
    fail("  shmget succeeded, segment was not deleted!");
  }

  // Parent waits for child to complete
  wait(&status);
  if (status != 0) {
    failnoex(" Child exited with error");
    return 1;
  }

  pass(" Lazy deletion verified");
  return 0;
}

/**
 * @brief Test large shared memory buffer creation.
 *
 * @details
 * Spawns a child process that creates a large (~60MB) shared memory segment
 * and fills it with a predictable sequence of bytes. Tests the ability to
 * allocate and initialize large buffers for LLM weight storage.
 *
 * @return int 0 on success, 1 on failure.
 */
int test_large_buffer_create() {
  int pid, status;

  info(" Starting large shared memory buffer creation test...");

  pid = fork();
  if (pid < 0) {
    failnoex(" fork failed");
    return 1;
  }

  if (pid == 0) {
    // Child process
    int shmid = -1;
    void* shmaddr;
    char* data;
    int i;

    printf("  Creating large shared memory segment of size %d bytes: ", LARGE_SIZE);
    shmaddr = get_shmaddr(LARGE_SEGMENT, LARGE_SIZE, IPC_CREAT | SHM_PERSIST, &shmid);
    info("OK");

    data = (char*)shmaddr;
    for (i = 0; i < LARGE_SIZE; i++) data[i] = (i % 256);  // Cycle through 0-255

    if (shmdt(shmaddr) < 0) fail("  shmdt failed");
    exit(0);
  }

  // Parent waits for child to complete
  wait(&status);
  if (status != 0) {
    failnoex(" Child exited with error");
    return 1;
  }

  pass(" Large buffer created successfully");
  return 0;
}

/**
 * @brief Test large shared memory buffer verification.
 *
 * @details
 * Spawns a child process that accesses the large shared memory buffer created
 * by the previous test, verifies all bytes match the expected sequence, and
 * properly cleans up the segment. Ensures data integrity for large buffers.
 *
 * @return int 0 on success, 1 on failure.
 */
int test_large_buffer_verify() {
  info(" Starting large shared memory buffer verification test...");
  int pid, status;

  pid = fork();
  if (pid < 0) {
    failnoex(" fork failed");
    return 1;
  }

  if (pid == 0) {
    // Child process
    int shmid = -1;
    void* shmaddr;
    char* data;
    int i;
    int errors = 0;

    info("  Accessing large shared memory segment");

    shmaddr = get_shmaddr(LARGE_SEGMENT, LARGE_SIZE, 0, &shmid);

    info("  Checking buffer sequence");
    data = (char*)shmaddr;
    for (i = 0; i < LARGE_SIZE; i++) {
      char expected = (i % 256);
      if (data[i] != expected) {
        errors++;
        if (errors >= 10) break;  // Stop after 10 errors
      }
    }

    if (errors == 0) pass("  all bytes correct!");
    else fail("  errors found");


    if (shmdt(shmaddr) < 0) fail("  shmdt failed");

    // Mark for deletion
    if (shmctl(shmid, IPC_RMID, 0) < 0) fail("  shmctl failed");

    exit(0);
  }

  // Parent waits for child to complete
  wait(&status);
  if (status != 0) {
    failnoex(" Child exited with error");
    return 1;
  }

  pass(" Large buffer verified successfully");
  return 0;
}

int (*tests[])() = {
  test_child_write,
  test_child_read_and_mark_delete,
  test_child_verify_deleted,
  test_large_buffer_create,
  test_large_buffer_verify
};


/**
 * @brief Program entry point for shared memory test suite.
 *
 * @param argc Number of command line arguments.
 * @param argv Array of command line argument strings.
 * @return int Exit status: 0 on success, nonzero on test failures.
 *
 * @details
 * Runs the complete suite of shared memory tests in sequence. Each test
 * is executed and results are accumulated. A summary is printed showing
 * total tests run, passed, and failed. Uses testutil.h for consistent
 * colored output formatting.
 */
int main(int argc, char* argv[]) {
  set_tag("SHMTEST");

  info("=== Comprehensive Shared Memory Test Suite ===");

  int num_tests = sizeof(tests) / sizeof(tests[0]);
  int failed_tests = 0;
  int passed_tests = 0;

  for (int i = 0; i < num_tests; i++) failed_tests += tests[i]();
  passed_tests = num_tests - failed_tests;

  return summary(passed_tests, num_tests);
}
