//
// randtest -- exercises the POSIX.1-2024 getentropy() syscall and the per-exec stack
// canary it seeds (kernel/random.c, kernel/sysproc.c, user/crt0.c).
//
//   randtest          getentropy(): exact-length fills with no buffer overrun, boundary
//                     and error-path rejection, and unpredictability (distinct, non-zero
//                     draws). Prints "rand OK" on success, "rand FAIL ..." otherwise.
//   randtest guard    print this exec's stack canary as "guard <hex>"; the harness runs
//                     it twice and checks the two values differ (per-exec randomization).
//
// Differential reference: getentropy() mirrors getentropy(3) on a POSIX.1-2024 host
// (0/-1 return, {GETENTROPY_MAX} = 256 cap).
//

#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"

extern unsigned long __stack_chk_guard; // the per-exec canary (user/stackguard.c)

#define FILLBYTE 0xAB   // sentinel: any byte getentropy must NOT touch stays this value

// getentropy() boundary, error-path and unpredictability coverage. Returns 0 on success.
static int
test_ent(void)
{
  unsigned char buf[GETENTROPY_MAX + 8];
  int lens[] = {0, 1, 7, 8, 13, 255, GETENTROPY_MAX};
  int nlens = sizeof(lens) / sizeof(lens[0]);

  // Exact-length fill, no overrun: for each length the call succeeds and the byte just
  // past the requested range is left untouched (catches a bad non-multiple-of-8 tail).
  for(int i = 0; i < nlens; i++){
    int len = lens[i];
    memset(buf, FILLBYTE, sizeof(buf));
    if(getentropy(buf, len) != 0){
      printf("rand FAIL (getentropy len %d refused)\n", len);
      return 1;
    }
    if(buf[len] != FILLBYTE){
      printf("rand FAIL (getentropy wrote past %d bytes)\n", len);
      return 1;
    }
  }

  // Over-long and negative requests are rejected (POSIX [EINVAL]).
  if(getentropy(buf, GETENTROPY_MAX + 1) != -1){
    printf("rand FAIL (over-long request accepted)\n");
    return 1;
  }
  if(getentropy(buf, -1) != -1){
    printf("rand FAIL (negative length accepted)\n");
    return 1;
  }

  // A bad user pointer is rejected ([EFAULT]), not a kernel crash.
  if(getentropy((void *)0xffffffffffff0000UL, 16) != -1){
    printf("rand FAIL (bad pointer accepted)\n");
    return 1;
  }

  // Unpredictability sanity: two draws are non-zero and differ from each other.
  unsigned char a[32], b[32];
  if(getentropy(a, sizeof(a)) != 0 || getentropy(b, sizeof(b)) != 0){
    printf("rand FAIL (draw)\n");
    return 1;
  }
  int allzero = 1, same = 1;
  for(int i = 0; i < (int)sizeof(a); i++){
    if(a[i] != 0)
      allzero = 0;
    if(a[i] != b[i])
      same = 0;
  }
  if(allzero){
    printf("rand FAIL (all-zero draw)\n");
    return 1;
  }
  if(same){
    printf("rand FAIL (two draws identical)\n");
    return 1;
  }

  printf("rand OK (getentropy bounds + no overrun + distinct draws)\n");
  return 0;
}

// Print the canary this exec was seeded with, so the harness can compare across execs.
static int
test_guard(void)
{
  // Trailing ';' lets the test harness wait for the full hex value before parsing.
  printf("canary=%lx;\n", __stack_chk_guard);
  return 0;
}

int
main(int argc, char *argv[])
{
  if(argc == 2 && strcmp(argv[1], "guard") == 0)
    return test_guard();
  return test_ent();
}
