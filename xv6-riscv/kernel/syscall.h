// System call numbers
#define SYS_fork 1
#define SYS_exit 2
#define SYS_wait 3
#define SYS_pipe 4
#define SYS_read 5
#define SYS_kill 6
#define SYS_exec 7
#define SYS_fstat 8
#define SYS_chdir 9
#define SYS_dup 10
#define SYS_getpid 11
#define SYS_sbrk 12
#define SYS_pause 13
#define SYS_uptime 14
#define SYS_open 15
#define SYS_write 16
#define SYS_mknod 17
#define SYS_unlink 18
#define SYS_link 19
#define SYS_mkdir 20
#define SYS_close 21

// System calls for labs
#define SYS_trace 22
#define SYS_interpose 23
#define SYS_sigalarm 24
#define SYS_sigreturn 25
#define SYS_symlink 26
#define SYS_mmap 27
#define SYS_munmap 28
#define SYS_bind 29
#define SYS_unbind 30
#define SYS_send 31
#define SYS_recv 32
#define SYS_pgpte 33
#define SYS_kpgtbl 34

// Shared memory syscalls
#define SYS_shmget 35
#define SYS_shmat 36
#define SYS_shmdt 37
#define SYS_shmctl 38

// Syscalls for reading cycle, time, and instret CSRs
#define SYS_rdcycle 39
#define SYS_rdtime 40
#define SYS_rdinstret 41

// RAM usage syscall
#define SYS_getramused 42

// POSIX.1-2017 per-process resource limits
#define SYS_setrlimit 43
#define SYS_getrlimit 44

// POSIX.1e-style capabilities (appropriate privileges for setrlimit)
#define SYS_capget 45
#define SYS_capdrop 46

// POSIX.1-2024 entropy source (unpredictable bytes for canaries, ASLR, keys)
#define SYS_getentropy 47

// POSIX.1-2017 user identity (real/effective/saved uid)
#define SYS_getuid  48
#define SYS_geteuid 49
#define SYS_setuid  50
#define SYS_seteuid 51
#define SYS_recvtimeo 52
#define SYS_ip 53

// Thread syscalls
//
// These were numbered 43-47 on the branch that introduced them, colliding with
// the POSIX block above (setrlimit/getrlimit/capget/capdrop/getentropy). Because
// syscalls[] is an array of designated initializers, a duplicate index is not a
// compile error -- the later initializer silently wins -- so every one of those
// five POSIX syscalls was dispatching to a thread/scheduler handler instead.
// The POSIX numbers are documented in README.md (setrlimit/getrlimit = 43/44),
// so the thread block moves here rather than the other way round.
#define SYS_thread_create 54
#define SYS_thread_join   55
#define SYS_thread_exit   56
#define SYS_yield         57

// Scheduler syscall
#define SYS_setpriority   58

// Declare a bulk UDP flow (exempt a bound port + declared peer from the
// per-source token bucket). Privileged: CAP_NET_ADMIN.
#define SYS_udp_bulk      59