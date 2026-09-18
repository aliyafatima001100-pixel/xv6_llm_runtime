//
// aslrtest -- prints the address of a stack local so the regression harness can confirm
// stack-base ASLR (kernel/exec.c): two execs of this program must land the stack at
// different addresses.
//
// The trailing ';' lets the harness wait for the full value before parsing. Each run's
// gap is page-granular, so the within-page bits are stable and the page bits vary.
//

#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"

int
main(void)
{
  int local;
  printf("sp=%p;\n", (void *)&local);
  exit(0);
}
