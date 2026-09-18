/**
 * @file mutex.c
 * @author Syed Taha
 * @date December 16, 2025
 * 
 * @brief User-level mutex implementation for XV6 threads.
 * @details
 * This file provides a simple mutex (mutual exclusion) primitive for
 * synchronizing access to shared resources among threads in the XV6
 * operating system. The mutex is implemented using atomic operations to
 * ensure correct behavior in a concurrent environment.
 */


#include "kernel/types.h"
#include "user.h"

/**
 * @brief Initialize a mutex.
 * 
 * @param mutex Pointer to the mutex variable to initialize.
 * @return int Returns 0 on success.
 */
int mutex_init(int *mutex)
{
  *mutex = 0;
  return 0;
}

/**
 * @brief Acquire a mutex, blocking if necessary.
 * 
 * @param mutex Pointer to the mutex variable to acquire.
 */
void mutex_lock(int *mutex)
{
  while (__sync_lock_test_and_set(mutex, 1)) {
    // Avoid busy-waiting by yielding the CPU so other threads can run.
    yield();
  }
  __sync_synchronize();
}

/**
 * @brief Release a mutex.
 * 
 * @param mutex Pointer to the mutex variable to release.
 */
void mutex_unlock(int *mutex)
{
  __sync_synchronize();
  __sync_lock_release(mutex);
}
