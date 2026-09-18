typedef unsigned int   uint;
typedef unsigned short ushort;
typedef unsigned char  uchar;

typedef unsigned char uint8;
typedef unsigned short uint16;
typedef unsigned int  uint32;
typedef unsigned long uint64;

typedef uint64 pde_t;

// POSIX user identifier (IEEE Std 1003.1-2017 <sys/types.h>). Shared by the kernel and
// user programs (via user/user.h) so both agree on the uid layout.
typedef uint uid_t;
