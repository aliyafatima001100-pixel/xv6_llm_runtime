#ifndef _RANDOM_H_
#define _RANDOM_H_

//
// Shared constants for the kernel randomness source (kernel/random.c) and its
// user-facing primitive getentropy() (kernel/sysproc.c). This header is included by
// both the kernel and user programs (via user/user.h), so both sides agree on the
// limit. Preprocessor defines only -- no type dependencies.
//

// Maximum number of bytes a single getentropy() call may request, the xv6 analog of
// {GETENTROPY_MAX} (IEEE Std 1003.1-2024, <limits.h>). A request larger than this is
// rejected with the POSIX [EINVAL] analog (-1). 256 matches the value mandated by
// POSIX and used by OpenBSD/glibc getentropy(3).
#define GETENTROPY_MAX 256

#endif // _RANDOM_H_
