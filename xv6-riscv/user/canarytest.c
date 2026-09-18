//
// canarytest -- proves the user-space stack-smashing protection (SSP) is active.
//
// Builds with -fstack-protector-strong (Makefile CFLAGS). smash() deliberately
// overruns a local buffer past the saved return address (CWE-121); the compiler-
// emitted epilogue notices the clobbered canary and calls __stack_chk_fail()
// (user/stackguard.c), which prints
//     *** stack smashing detected ***: terminated
// to standard error and exit(1)s. If SSP were OFF the overflow would silently corrupt
// the frame and smash() would return, so reaching the line after smash() is the
// failure case.
//
// This is the user-half analog of the differential test in the plan: with the flag the
// overflow is caught; without it, silent corruption.
//

#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"

// Opaque sink so the buffer is "used" (defeats -Wunused-but-set-variable) without the
// compiler being able to elide the stores.
volatile char g_sink;

// noinline: the overflow must be a real function-return event the SSP epilogue checks.
// The trip count is volatile so the compiler cannot prove the overflow at compile time
// (which would let -Warray-bounds reject the build); buf is volatile so the stores are
// not optimized away.
__attribute__((noinline))
static void
smash(void)
{
  volatile char buf[16];
  volatile int n = 64;            // > sizeof(buf): runs into the saved canary / ra
  for(int i = 0; i < n; i++)
    buf[i] = (char)i;
  g_sink = buf[0];                // read back so buf counts as used
}

int
main(void)
{
  smash();
  // Only reached if the canary did NOT trip -- i.e. SSP is broken/disabled.
  printf("canarytest: FAIL (no canary trip)\n");
  exit(1);
}
