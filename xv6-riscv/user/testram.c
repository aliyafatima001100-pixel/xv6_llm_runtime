/**
 * @file testram.c
 * @brief Test program for RAM usage syscall.
 *
 * @author Syed Taha
 * @date 30th November 2025
 *
 * @details
 * This program tests the getramused syscall by performing various memory
 * allocation and deallocation operations, measuring RAM usage at each step.
 * It demonstrates the syscall's functionality and validates memory management.
 */

#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"

#define ALLOC_SIZE (1024 * 1024)  // 1MB allocations

/**
 * @brief Print current RAM usage.
 */
void print_ram_usage(const char *msg) {
  uint64 used = getramused();
  printf("%s: %lu bytes (%lu KB, %lu MB)\n", msg, used, used / 1024, used / (1024 * 1024));
}

/**
 * @brief Main test function.
 */
int main(int argc, char *argv[]) {
  printf("RAM Usage Test Program Starting...\n");

  // Initial RAM usage
  print_ram_usage("Initial RAM usage");

  // Allocate 1MB
  printf("Allocating 1MB...\n");
  uint64 old_brk = (uint64)sbrk(ALLOC_SIZE);
  if ((void*)old_brk == (void*)-1) {
    printf("ERROR: sbrk failed\n");
    exit(1);
  }
  print_ram_usage("After allocating 1MB");

  // Allocate another 1MB
  printf("Allocating another 1MB...\n");
  old_brk = (uint64)sbrk(ALLOC_SIZE);
  if ((void*)old_brk == (void*)-1) {
    printf("ERROR: sbrk failed\n");
    exit(1);
  }
  print_ram_usage("After allocating another 1MB");

  // Deallocate 1MB
  printf("Deallocating 1MB...\n");
  if (sbrk(-ALLOC_SIZE) == (void*)-1) {
    printf("ERROR: sbrk dealloc failed\n");
    exit(1);
  }
  print_ram_usage("After deallocating 1MB");

  // Fork a child and check RAM
  printf("Forking a child process...\n");
  int pid = fork();
  if (pid < 0) {
    printf("ERROR: fork failed\n");
    exit(1);
  }

  if (pid == 0) {
    // Child
    print_ram_usage("Child process RAM usage");
    // Child allocates 512KB
    printf("Child allocating 512KB...\n");
    uint64 child_brk = (uint64)sbrk(ALLOC_SIZE / 2);
    if ((void*)child_brk == (void*)-1) {
      printf("ERROR: child sbrk failed\n");
      exit(1);
    }
    print_ram_usage("Child after allocating 512KB");
    exit(0);
  } else {
    // Parent
    wait(0);
    print_ram_usage("Parent after child exited");
  }

  // Final RAM usage
  print_ram_usage("Final RAM usage");

  printf("RAM Usage Test Program Completed.\n");
  exit(0);
}