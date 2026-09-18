//
// Stack-smashing protection (SSP) runtime support for user programs.
//
// Every user program is built with -fstack-protector-strong (see the Makefile CFLAGS)
// and links this file via ULIB, so the two symbols the compiler references for a
// protected frame -- __stack_chk_guard (the canary) and __stack_chk_fail() (the
// mismatch handler) -- are resolved. A contiguous overflow of a local buffer that
// reaches the saved return address (CWE-121) also clobbers the canary, and the
// compiler epilogue then calls __stack_chk_fail() before the poisoned "ret".
//
// Mechanism / standards: SSP / StackGuard (Cowan et al., USENIX Security '98); the
// symbols are defined by the RISC-V psABI (not by ISO/IEC 9899 -- the C standard does not
// specify stack protection).
//

#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"

// The per-program stack canary. It is re-seeded with unpredictable bytes on every exec
// by the crt0 stub (user/crt0.c, via getentropy()) before main() runs, so it is unique
// per run -- the user-space analog of the kernel's boot-seeded canary
// (kernel/stackguard.c). This static initialiser is only the pre-seed value used by the
// few programs without a crt0 entry (e.g. forktest, linked -e main): the classic
// terminator bytes (0x00 NUL, 0x0a LF, 0x0d CR, 0xff) that also halt naive string-copy
// overflows.
unsigned long __stack_chk_guard = 0xff0a0d0000aaff00UL;

// Called by the compiler-generated epilogue when a frame canary no longer matches
// __stack_chk_guard. Control-flow integrity is already lost, so we terminate
// abnormally rather than return.
//
// POSIX-conformant failure path: emit the canonical glibc diagnostic on standard
// error (fd 2) and exit with a non-zero (abnormal) status -- the xv6 stand-in for
// glibc's abort()/SIGABRT, since xv6 has no signals.
//
// Uses the raw write() syscall (usys.o) rather than fprintf (printf.o) so even the
// minimally-linked programs (e.g. forktest) resolve this handler without dragging in
// the whole stdio implementation.
void
__stack_chk_fail(void)
{
  static const char msg[] = "*** stack smashing detected ***: terminated\n";
  int n = 0;
  while(msg[n] != '\0')
    n++;
  write(2, msg, n);
  exit(1);
}
