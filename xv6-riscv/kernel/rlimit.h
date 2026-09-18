#ifndef _RLIMIT_H_
#define _RLIMIT_H_

//
// Per-process resource limits -- the xv6 analog of POSIX <sys/resource.h>.
//
// Models IEEE Std 1003.1-2017 (POSIX.1-2017) getrlimit()/setrlimit(): each limited
// resource has a soft current limit (rlim_cur, enforced) and a hard ceiling
// (rlim_max, the most rlim_cur may be raised to). A limit of RLIM_INFINITY means
// "no limit". This header is shared by the kernel and by user programs (via
// user/user.h), so both sides agree on the layout and the resource numbers.
//
// Requires uint64 (kernel/types.h), which both the kernel .c files and the user
// programs include before this header.
//

typedef uint64 rlim_t;

struct rlimit {
  rlim_t rlim_cur;   // soft limit: the value the kernel enforces
  rlim_t rlim_max;   // hard limit: the ceiling rlim_cur may be raised to
};

// "no limit" sentinel (POSIX RLIM_INFINITY). All-ones, NOT zero -- a zero limit would
// mean "forbid everything".
#define RLIM_INFINITY (~(rlim_t)0)

// Resource identifiers (POSIX RLIMIT_*). Used both as the syscall argument and as the
// index into struct proc's rlim[] array, so the numbering must stay dense from 0.
#define RLIMIT_AS    0   // max process address space, in bytes  (POSIX RLIMIT_AS)
#define RLIMIT_CPU   1   // max CPU time consumed, in seconds     (POSIX RLIMIT_CPU)
#define RLIM_NLIMITS 2   // number of limits defined (array size)

#endif // _RLIMIT_H_
