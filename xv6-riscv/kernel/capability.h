#ifndef _CAPABILITY_H_
#define _CAPABILITY_H_

//
// Per-process capabilities -- the xv6 analog of the POSIX.1e / Linux capability model.
//
// IEEE Std 1003.1-2017 says only a process with "appropriate privileges" may raise a
// resource hard limit (setrlimit, RLIMIT_*). xv6 has no uid/superuser yet, so that
// "appropriate privilege" is modeled here as a single capability bit, CAP_SYS_RESOURCE,
// held in struct proc's `caps` bitmask. Every privilege decision goes through capable()
// (kernel/proc.c), so this stays one chokepoint.
//
// UPGRADE PATH (kept additive on purpose):
//   - add more capabilities below (e.g. CAP_KILL 1, CAP_SETUID 2), densely numbered;
//   - when uids land, fold the POSIX superuser rule into capable():
//       return p->euid == 0 || (p->caps & CAP_MASK(cap));
//   - generalise capget/capdrop into a full POSIX.1e capset (permitted / effective /
//     inheritable sets) without touching any call site.
//
// This header is shared by the kernel and by user programs (via user/user.h), so both
// sides agree on the capability numbers. Preprocessor defines only -- no type deps.
//

// Capability identifiers (bit indices into struct proc's `caps`). Keep dense from 0.
#define CAP_SYS_RESOURCE 0   // raise resource hard limits (POSIX setrlimit rlim_max)
#define CAP_NET_ADMIN    1   // change network admission policy (declare a bulk UDP flow)

// Bit mask for capability c, and the "all capabilities held" set.
#define CAP_MASK(c) (1UL << (c))
#define CAP_ALL     (~0UL)

#endif // _CAPABILITY_H_
