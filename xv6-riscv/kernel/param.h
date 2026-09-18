#define NPROC        64  // maximum number of processes
#define NCPU          8  // maximum number of CPUs
#define NOFILE       16  // open files per process
#define NFILE       100  // open files per system
#define NINODE       50  // maximum number of active i-nodes
#define NDEV         10  // maximum major device number
#define ROOTDEV       1  // device number of file system root disk
#define MAXARG       32  // max exec arguments
#define MAXOPBLOCKS  10  // max # of blocks any FS op writes
#define LOGBLOCKS    (MAXOPBLOCKS*3)  // max data blocks in on-disk log
#define NBUF         (MAXOPBLOCKS*3)  // size of disk block cache
#define FSSIZE       8000  // size of file system in blocks (increased for more user binaries)
#define MAXPATH      128   // maximum file path name
#define USERSTACK    4     // user stack pages (main thread, built by exec)

// Per-thread user stack, in pages, plus one inaccessible guard page below it.
// Threads run the same RPC and inference code the main thread does, so they get
// the same budget as USERSTACK. This was one unguarded page: a 4352-byte RPC
// wire buffer did not fit in it at all, and with no guard page an overflow
// silently corrupted whatever was mapped below instead of trapping.
#define THREAD_STACK_PAGES 4

/** @brief Maximum number of shared memory segments in the system. */
#define NSHM         16