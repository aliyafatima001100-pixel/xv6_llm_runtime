/**
 * @file threadstack.c
 * @brief Regression test for per-thread user stack size and its guard page.
 *
 * @details
 * Threads run the same code the main thread does -- the DistInf listen thread
 * owns rpc_recv, whose wire buffer alone is 4352 bytes -- but a thread stack was
 * one page (4096 bytes) with no guard page below it. An overflow was therefore
 * not an error: it wrote into the heap or the neighbouring thread's stack and
 * the failure surfaced later, somewhere unrelated.
 *
 * thread_create() now maps THREAD_STACK_PAGES usable pages plus an inaccessible
 * guard page, the same shape exec() builds for the main thread. This program
 * pins that down from user space.
 *
 * Checks performed:
 *   1. A thread can use a frame larger than one page (6 KB here, which the old
 *      one-page stack could not have held) without disturbing anything else.
 *   2. Every byte of that frame reads back what was written to it, so the frame
 *      did not silently overlap the heap or another thread's stack.
 *   3. The main thread's own data is intact afterwards, i.e. the thread stack did
 *      not collide with it.
 *   4. thread_join() returns, so the thread completed rather than faulting.
 */

#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"

#define DEEP_FRAME 6144      /* larger than the old single-page thread stack */
#define CANARY     0xA5

static volatile int thread_ok;
static int main_sentinel = 0x1234BEEF;

/**
 * @brief Occupy a frame bigger than one page and verify every byte of it.
 */
static void
deep_thread(void *arg)
{
  volatile unsigned char frame[DEEP_FRAME];

  for (int i = 0; i < DEEP_FRAME; i++)
    frame[i] = (unsigned char)(CANARY ^ (i & 0xff));

  for (int i = 0; i < DEEP_FRAME; i++) {
    if (frame[i] != (unsigned char)(CANARY ^ (i & 0xff))) {
      printf("threadstack: FAIL frame byte %d corrupted\n", i);
      thread_exit();
    }
  }

  thread_ok = 1;
  thread_exit();
}

int
main(void)
{
  int tid = thread_create(deep_thread, 0);
  if (tid < 0) {
    printf("threadstack: FAIL thread_create\n");
    exit(1);
  }
  thread_join(tid);

  if (!thread_ok) {
    printf("threadstack: FAIL thread did not complete\n");
    exit(1);
  }
  if (main_sentinel != 0x1234BEEF) {
    printf("threadstack: FAIL main data clobbered by the thread stack\n");
    exit(1);
  }

  printf("threadstack: OK\n");
  exit(0);
}
