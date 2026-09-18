//
// idtest -- exercises the POSIX.1-2017 user-identity model (getuid/geteuid/setuid/seteuid)
// and its integration with the capability privilege gate.
//
//   - by default a process is root (ruid = euid = suid = 0);
//   - while root, raising a resource hard limit is permitted (CAP_SYS_RESOURCE);
//   - setuid(1000) drops the real/effective/saved uid AND clears the capability set, so the
//     same raise is then refused ([EPERM]) and root cannot be regained;
//   - seteuid() drops only the effective uid and can be restored from the saved uid;
//   - fork() inherits the identity.
//
// Each irreversible drop runs in a forked child so the test process keeps its own identity.
// Prints "id OK" if every check passes, "id FAIL ..." otherwise (the form the harness greps).
//
// Differential reference: mirrors getuid(2)/setuid(2)/seteuid(2) on a POSIX host.
//

#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"

#define PGSIZE 4096

// As root: lowering then raising a hard limit is allowed; after setuid(1000) the raise is
// refused (privilege dropped with root) and root cannot be regained. Runs in a child; the
// child's exit status is the result (0 = pass, nonzero = the failing step's code).
static int
test_drop(void)
{
  int pid = fork();
  if(pid < 0)
    return -1;
  if(pid == 0){
    uint64 base = (uint64)sbrk(0);

    struct rlimit lo = { base + 8 * PGSIZE, base + 8 * PGSIZE };
    if(setrlimit(RLIMIT_AS, &lo) < 0)
      exit(11);                                   // lowering the hard limit always allowed
    struct rlimit hi = { base + 16 * PGSIZE, base + 16 * PGSIZE };
    if(setrlimit(RLIMIT_AS, &hi) < 0)
      exit(12);                                   // root: raising the hard limit allowed

    if(setuid(1000) < 0)
      exit(13);
    if(getuid() != 1000 || geteuid() != 1000)
      exit(14);                                   // real/effective uid both dropped

    struct rlimit hi2 = { base + 32 * PGSIZE, base + 32 * PGSIZE };
    if(setrlimit(RLIMIT_AS, &hi2) != -1)
      exit(15);                                   // non-root: raise must be refused
    if(setuid(0) != -1)
      exit(16);                                   // cannot regain root
    exit(0);
  }
  int st = 0;
  wait(&st);
  return st;
}

// seteuid() drops only the effective uid (real/saved stay 0), and the saved uid lets it be
// restored to 0 -- the classic privileged-program drop/restore.
static int
test_seteuid(void)
{
  int pid = fork();
  if(pid < 0)
    return -1;
  if(pid == 0){
    if(seteuid(1000) < 0)
      exit(21);
    if(geteuid() != 1000 || getuid() != 0)
      exit(22);                                   // only euid changed
    if(seteuid(0) < 0)
      exit(23);                                   // restore from saved/real uid 0
    if(geteuid() != 0)
      exit(24);
    exit(0);
  }
  int st = 0;
  wait(&st);
  return st;
}

// fork() inherits the user identity: a child that dropped to uid 1000 forks a grandchild
// that sees uid 1000.
static int
test_inherit(void)
{
  int pid = fork();
  if(pid < 0)
    return -1;
  if(pid == 0){
    if(setuid(1000) < 0)
      exit(31);
    int g = fork();
    if(g < 0)
      exit(32);
    if(g == 0){
      if(getuid() != 1000 || geteuid() != 1000)
        exit(33);                                 // identity inherited across fork
      exit(0);
    }
    int gst = 0;
    wait(&gst);
    exit(gst == 0 ? 0 : 34);
  }
  int st = 0;
  wait(&st);
  return st;
}

int
main(void)
{
  if(getuid() != 0 || geteuid() != 0){
    printf("id FAIL (not root at start)\n");
    exit(1);
  }

  int st;
  if((st = test_drop()) != 0){
    printf("id FAIL (drop, code %d)\n", st);
    exit(1);
  }
  if((st = test_seteuid()) != 0){
    printf("id FAIL (seteuid, code %d)\n", st);
    exit(1);
  }
  if((st = test_inherit()) != 0){
    printf("id FAIL (inherit, code %d)\n", st);
    exit(1);
  }

  printf("id OK (uid euid suid, drop clears privilege, saved-uid restore, fork inherits)\n");
  exit(0);
}
