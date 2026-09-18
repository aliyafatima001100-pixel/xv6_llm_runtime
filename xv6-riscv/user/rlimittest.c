//
// rlimittest -- exercises the POSIX.1-2017 setrlimit()/getrlimit() resource limits.
//
//   rlimittest mem   RLIMIT_AS:  cap the address space a few pages above the current
//                    break, then confirm both the eager (sbrk) and lazy (sbrklazy)
//                    growth paths are refused at the cap instead of consuming all RAM.
//   rlimittest cpu   RLIMIT_CPU: a child caps its own CPU time and spins; confirm it is
//                    killed at the limit (parent's wait() reaps it) instead of looping
//                    forever.
//   rlimittest cpusleep  RLIMIT_CPU charges consumed CPU, not wall time: a capped child
//                    that sleeps past its limit is not killed.
//   rlimittest exec  RLIMIT_AS also bounds exec(): a capped child cannot escape its limit
//                    by exec'ing a larger binary (regression for the exec bypass).
//   rlimittest fork  inheritance: a child confirms it inherited the parent's RLIMIT_AS.
//   rlimittest cap   CAP_SYS_RESOURCE: after capdrop() a process can no longer RAISE its
//                    hard limit (POSIX [EPERM]) -- the rlimit becomes real confinement.
//
// Each sub-test prints "<name> OK" on success and "<name> FAIL ..." on failure, then
// exits 0/1 -- the form the regression harness greps for.
//
// Differential reference: RLIMIT_AS mirrors `ulimit -v`, RLIMIT_CPU mirrors `ulimit -t`
// on a POSIX host.
//

#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"

#define PGSIZE 4096

// RLIMIT_AS: refuse address-space growth past the soft limit (POSIX [ENOMEM]).
static int
test_mem(void)
{
  uint64 base = (uint64)sbrk(0);     // current break = current address-space size
  uint64 cap  = base + 16 * PGSIZE;  // allow 16 more pages, then it must be refused

  struct rlimit rl;
  rl.rlim_cur = cap;
  rl.rlim_max = cap;
  if(setrlimit(RLIMIT_AS, &rl) < 0){
    printf("mem FAIL (setrlimit)\n");
    return 1;
  }

  // getrlimit must read back exactly what we set.
  struct rlimit got;
  if(getrlimit(RLIMIT_AS, &got) < 0 || got.rlim_cur != cap || got.rlim_max != cap){
    printf("mem FAIL (getrlimit mismatch)\n");
    return 1;
  }

  // Eager path (sbrk -> growproc): grow one page at a time until it is refused.
  int pages = 0;
  for(;;){
    char *p = sbrk(PGSIZE);
    if(p == SBRK_ERROR)
      break;                          // hit the cap -- correct
    if(++pages > 64){                 // never refused: the limit is not enforced
      printf("mem FAIL (eager grow not capped)\n");
      return 1;
    }
  }

  // Lazy path (sbrklazy): the break is already at the cap, so this must also be
  // refused -- proving the limit is enforced on the lazy chokepoint too.
  if(sbrklazy(PGSIZE) != SBRK_ERROR){
    printf("mem FAIL (lazy grow not capped)\n");
    return 1;
  }

  printf("mem OK (capped after %d pages, both paths refused)\n", pages);
  return 0;
}

// RLIMIT_CPU: a spinning process is killed at its CPU-time limit (POSIX SIGXCPU/KILL;
// here kill-on-exceed). The parent reaping the child is the success signal.
static int
test_cpu(void)
{
  int pid = fork();
  if(pid < 0){
    printf("cpu FAIL (fork)\n");
    return 1;
  }
  if(pid == 0){
    struct rlimit rl;
    rl.rlim_cur = 1;                  // 1 CPU second
    rl.rlim_max = 1;
    setrlimit(RLIMIT_CPU, &rl);
    volatile int x = 0;
    for(;;)                           // burn CPU; must be killed at ~1s
      x++;
  }

  int st = 0;
  int w = wait(&st);                  // blocks until the child is killed/exits
  if(w == pid){
    printf("cpu OK (child %d reaped, status %d)\n", w, st);
    return 0;
  }
  printf("cpu FAIL (wait returned %d)\n", w);
  return 1;
}

// RLIMIT_AS must also bound exec(): a process that lowers its cap then exec's a larger
// binary must be refused, not allowed to escape the cap by replacing its image. This is
// the regression for the exec() bypass (exec built the new image via uvmalloc without
// consulting rlimit_as_ok()).
static int
test_exec(void)
{
  int pid = fork();
  if(pid < 0){
    printf("exec FAIL (fork)\n");
    return 1;
  }
  if(pid == 0){
    // Cap the address space far below any real binary's image, then try to exec one.
    struct rlimit rl = { 2 * PGSIZE, 2 * PGSIZE };
    setrlimit(RLIMIT_AS, &rl);
    char *args[] = { "ls", 0 };
    exec("ls", args);
    // Control only returns here if exec was REFUSED (the correct, capped behaviour);
    // a successful exec would have replaced this image with ls and never come back.
    exit(42);
  }
  int st = 0;
  wait(&st);
  if(st != 42){
    printf("exec FAIL (exec not capped by RLIMIT_AS, child st %d)\n", st);
    return 1;
  }
  printf("exec OK (exec refused past RLIMIT_AS)\n");
  return 0;
}

// RLIMIT_CPU charges CPU time actually consumed, not wall-clock time: a sleeping process
// is not the running process on any tick, so it must NOT be charged or killed. A 1 CPU
// second cap with a ~2 s sleep must survive.
static int
test_cpusleep(void)
{
  int pid = fork();
  if(pid < 0){
    printf("cpusleep FAIL (fork)\n");
    return 1;
  }
  if(pid == 0){
    struct rlimit rl = { 1, 1 };       // 1 CPU second
    setrlimit(RLIMIT_CPU, &rl);
    pause(20);                         // ~2 s wall, ~0 CPU -- must not trip the cap
    exit(0);
  }
  int st = 0;
  wait(&st);
  if(st != 0){
    printf("cpusleep FAIL (killed while sleeping, st %d)\n", st);
    return 1;
  }
  printf("cpusleep OK (sleep not charged as CPU time)\n");
  return 0;
}

// RLIMIT_AS inheritance across fork() (POSIX: limits are inherited).
static int
test_fork(void)
{
  uint64 base = (uint64)sbrk(0);
  uint64 cap  = base + 8 * PGSIZE;
  struct rlimit rl = { cap, cap };
  if(setrlimit(RLIMIT_AS, &rl) < 0){
    printf("fork FAIL (setrlimit)\n");
    return 1;
  }

  int pid = fork();
  if(pid == 0){
    struct rlimit got;
    if(getrlimit(RLIMIT_AS, &got) < 0 || got.rlim_cur != cap)
      exit(1);                        // limit was not inherited
    exit(0);
  }
  int st = 0;
  wait(&st);
  if(st != 0){
    printf("fork FAIL (child did not inherit limit)\n");
    return 1;
  }
  printf("fork OK (child inherited RLIMIT_AS)\n");
  return 0;
}

// CAP_SYS_RESOURCE: raising a hard limit needs the capability (POSIX [EPERM]); after a
// one-way capdrop() the rlimit is a real confinement boundary -- raises are refused while
// lowering still works. Mirrors `setrlimit` on a POSIX host with / without CAP_SYS_RESOURCE.
static int
test_cap(void)
{
  uint64 base = (uint64)sbrk(0);

  // Lower the hard limit from the unlimited default -- always allowed.
  struct rlimit rl = { base + 8 * PGSIZE, base + 8 * PGSIZE };
  if(setrlimit(RLIMIT_AS, &rl) < 0){
    printf("cap FAIL (initial setrlimit)\n");
    return 1;
  }

  // Still capable (CAP_ALL by default): raising the hard limit must succeed.
  struct rlimit hi = { base + 16 * PGSIZE, base + 16 * PGSIZE };
  if(setrlimit(RLIMIT_AS, &hi) < 0){
    printf("cap FAIL (privileged raise refused)\n");
    return 1;
  }

  // Drop CAP_SYS_RESOURCE (one-way); now raising the hard limit must be refused ([EPERM]).
  if(capdrop(CAP_SYS_RESOURCE) < 0){
    printf("cap FAIL (capdrop)\n");
    return 1;
  }
  struct rlimit higher = { base + 32 * PGSIZE, base + 32 * PGSIZE };
  if(setrlimit(RLIMIT_AS, &higher) != -1){
    printf("cap FAIL (raise allowed after capdrop)\n");
    return 1;
  }

  // Lowering the hard limit stays allowed without the capability (POSIX).
  struct rlimit lo = { base + 4 * PGSIZE, base + 4 * PGSIZE };
  if(setrlimit(RLIMIT_AS, &lo) < 0){
    printf("cap FAIL (lower refused after capdrop)\n");
    return 1;
  }

  printf("cap OK (hard-limit raise blocked after capdrop)\n");
  return 0;
}

int
main(int argc, char *argv[])
{
  if(argc != 2){
    printf("usage: rlimittest mem|cpu|cpusleep|exec|fork|cap\n");
    exit(1);
  }
  if(strcmp(argv[1], "mem") == 0)
    exit(test_mem());
  if(strcmp(argv[1], "cpu") == 0)
    exit(test_cpu());
  if(strcmp(argv[1], "cpusleep") == 0)
    exit(test_cpusleep());
  if(strcmp(argv[1], "exec") == 0)
    exit(test_exec());
  if(strcmp(argv[1], "fork") == 0)
    exit(test_fork());
  if(strcmp(argv[1], "cap") == 0)
    exit(test_cap());
  printf("usage: rlimittest mem|cpu|cpusleep|exec|fork|cap\n");
  exit(1);
}
