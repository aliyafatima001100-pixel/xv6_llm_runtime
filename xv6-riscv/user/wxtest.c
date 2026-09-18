//
// wxtest -- verifies the kernel's W^X enforcement (OpenBSD model; see kernel/exec.c).
//
// A child exec()s "wxbad", a binary with a writable+executable (OMAGIC) segment and NO
// PT_OPENBSD_WXNEEDED exemption tag. Under W^X exec must refuse it: exec() returns -1 and
// the child falls through to exit(99). Without W^X, wxbad would run and exit(0). The parent
// tells the two apart by the child's exit status. (forktest -- W+X but wxneeded-tagged --
// exercises the allowed/exempt path and is covered by usertests.)
//
// Prints "wx OK" on success, "wx FAIL ..." otherwise (the form the regression harness greps).
//
// CHECK CHAIN:
//   1. fork a child
//   2. child exec("wxbad"): must fail (W+X, not exempt) -> child reaches exit(99); a success
//      would have replaced the child with wxbad, which exit(0)s
//   3. parent wait(): status 99 -> exec refused (W^X enforced); status 0 -> exec allowed (FAIL)
//

#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"

int
main(void)
{
  int pid = fork();
  if(pid < 0){
    printf("wx FAIL (fork)\n");
    exit(1);
  }
  if(pid == 0){
    char *av[] = { "wxbad", 0 };
    exec("wxbad", av);
    exit(99);                 // reached only if exec was refused (the correct W^X behaviour)
  }

  int st = 0;
  wait(&st);
  if(st == 99){
    printf("wx OK (W+X binary refused by exec)\n");
    exit(0);
  }
  printf("wx FAIL (W+X binary was allowed to exec, status %d)\n", st);
  exit(1);
}
