/**
 * @file shm.h
 * @brief Shared memory subsystem header for xv6 with persistence and lazy deletion.
 *
 * @author Syed Taha
 * @date 27th November 2025
 *
 * @details
 * This header defines the shared memory API for xv6, providing POSIX-compliant
 * shared memory operations with persistence across processes and lazy deletion
 * semantics. The implementation supports large memory segments suitable for
 * LLM weight storage and includes proper synchronization for concurrent access.
 *
 * Key features:
 * - Persistent shared memory segments that survive process termination
 * - Lazy deletion with IPC_RMID for safe cleanup when last process detaches
 * - Large buffer support (up to 96MB per segment with 4KB pages)
 * - Thread-safe operations with spinlock protection
 * - Memory-mapped access with configurable permissions
 */

#ifndef _SHM_H_
#define _SHM_H_

#include "types.h"

// Shared memory constants
/** @brief Maximum length of shared memory segment names. */
#define SHM_NAME_LEN 32
/**
 * @brief Maximum pages per shared memory segment (96 MiB with 4KB pages).
 *
 * Raised from 17825 (~70 MB) to hold the 110M model's word table -- the
 * embedding/classifier tensor is 32000 x 768 x 4 B = ~94 MB and must live in one
 * segment so the numeric kernels address it as a contiguous block (band-splitting
 * it would push per-row indexing into the bit-exact matmul path).
 *
 * Cost: phys_pages[] is embedded in every struct shm_segment and there are NSHM
 * of them, so this array is the dominant term in the static shm_table. At 24576
 * that table is ~3.0 MB of kernel BSS (was ~2.18 MB) -- +0.86 MB, ~0.3% of a
 * 256 MB node, reserved on every node including workers. The ceiling stops here
 * because a materially larger table would exceed the node's total RAM anyway, so
 * beyond ~96 MB the binding constraint is PHYSTOP, not this cap.
 */
#define MAX_PAGES_PER_SEG 24576 // 96 MiB with 4KB pages (see note above)
/** @brief Flag to create persistent shared memory segments. */
#define SHM_PERSIST 0x01
/** @brief Flag for read-only shared memory access. */
#define SHM_RDONLY 0x01
/** @brief Flag for read-write shared memory access. */
#define SHM_RDWR 0x02

// IPC flags
/** @brief Flag to create shared memory segment if it doesn't exist. */
#define IPC_CREAT 0x1000
/** @brief Flag to fail if shared memory segment already exists. */
#define IPC_EXCL 0x2000
/** @brief Command to mark shared memory segment for removal. */
#define IPC_RMID 0  // Remove shared memory segment

/**
 * @brief Shared memory segment structure.
 *
 * @details
 * Represents a single shared memory segment in the system. Contains metadata
 * for identification, physical page mappings, reference counting, and
 * synchronization primitives.
 */
struct shm_segment {
  int id;  /**< Shared memory ID */
  char name[SHM_NAME_LEN];  /**< Name of the shared memory segment */
  uint64 phys_pages[MAX_PAGES_PER_SEG];  /**< Physical addresses of allocated pages */
  uint64 size;  /**< Total size of the segment in bytes */
  uint64 npages;  /**< Number of pages allocated */
  int refcount;  /**< Number of processes currently attached */
  int persistent;  /**< Whether segment persists after creator exits */
  struct spinlock lock;  /**< Lock for thread-safe access to segment */
};

/**
 * @brief Global shared memory table structure.
 *
 * @details
 * Contains the global table of all shared memory segments and provides
 * synchronization for table-wide operations.
 */
struct shm_table {
  struct spinlock lock;  /**< Lock for thread-safe access to table */
  struct shm_segment segs[NSHM];  /**< Array of shared memory segments */
};

// Global shared memory table
extern struct shm_table shm_table;

#endif // _SHM_H_