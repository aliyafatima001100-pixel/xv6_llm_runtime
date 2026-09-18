#ifndef _DISCOVERY_H_
#define _DISCOVERY_H_

#include "rpc.h"
#include "distinf.h"

/* -----------------------------------------------------------------------
 * Worker registry constants
 * ----------------------------------------------------------------------- */
#define MAX_WORKERS       16

/* Worker states */
#define WORKER_PENDING    0    /* registered, not yet probed   */
#define WORKER_ACTIVE     1    /* probed, accepting work       */
#define WORKER_SUSPECTED  2    /* missed heartbeats            */
#define WORKER_EXPIRED    3    /* missed heartbeats            */

#define HEARTBEAT_INTERVAL_TICKS   200   // worker sends every 200 ticks
#define HEARTBEAT_MISS_SUSPECTED     2   // missed heartbeats before SUSPECTED
#define HEARTBEAT_MISS_EXPIRED       4   // missed heartbeats before EXPIRED

//TODO: Add time for exceeding capability claim

#define SUSPECTED_TIMEOUT  (HEARTBEAT_INTERVAL_TICKS * HEARTBEAT_MISS_SUSPECTED)
#define EXPIRED_TIMEOUT    (HEARTBEAT_INTERVAL_TICKS * HEARTBEAT_MISS_EXPIRED)

/*
 * How long the master's receive loop blocks before looking at the clock again.
 * Expiry is driven by this poll, so it must be well under SUSPECTED_TIMEOUT
 * (40 s at the current settings) for a silent worker to be noticed on time;
 * 5 s gives eight checks per suspect window without busy-polling.
 */
#define MASTER_POLL_MS     5000

/* Capability bitmasks (carried in worker_info_t.capabilities) */
#define CAP_INFER         (1 << 0)
#define CAP_ATTEST        (1 << 1)

/* -----------------------------------------------------------------------
 * Payload struct for PROC_AUTH_HELLO
 * Serialised into rpc_msg_t.payload as raw bytes.
 * ----------------------------------------------------------------------- */
typedef struct {
    uint32 worker_id;
    uint32 ip;
    uint16 port;
    uint32 RAM;
    uint8  psk_hash[32];   /* SHA-256(psk) — verified by master    */
    uint32 next_ip;                  /* IP of next worker default=master     */
    uint32 prev_ip;                  /* IP of prev worker default=master     */
} worker_info_t;

typedef struct {
    uint32 probe_nonce;   /* liveness: the issued nonce, echoed back            */
    uint32 checksum;      /* RAM probe: page-strided seeded checksum (below)    */
    uint8  identity[32];  /* HMAC-SHA256(PSK, nonce): proof of PSK possession   */
} cap_ack_t;

/*
 * Node identity (RFC 2104 HMAC-SHA256, FIPS 198-1).
 *
 * worker_info_t.psk_hash carries SHA-256(PSK) as an identity *commitment* at
 * AUTH_HELLO, and cap_ack_t.identity carries HMAC(PSK, nonce) as the *proof*:
 * only a holder of the pre-shared key can produce a valid MAC over the master's
 * fresh nonce, so a peer that merely replayed a captured psk_hash or nonce
 * cannot register. The master knows the PSK, recomputes both, and rejects a
 * mismatch. Reuses the in-tree user/sha256.c.
 *
 * Minor deviations, documented in README.md (the standards guidance permits the
 * smallest sufficient approach): a single fixed PSK stands in for per-node
 * provisioning / a key-exchange (RFC 5403 RPCSEC_GSS is out of scope on xv6),
 * and identity is authenticated once at registration rather than signing every
 * datagram -- the ring's session_id + strictly-increasing seq already bind each
 * hop to the authenticated epoch (anti-spoof/anti-replay, RFC 4303 model).
 */
#define DISTINF_PSK     "distinf-shared-psk-v1"
#define DISTINF_PSK_LEN 21   /* strlen(DISTINF_PSK), no NUL */

/*
 * Capability (RAM) sized-probe.
 *
 * A worker advertises worker_info_t.RAM. To keep that from being a bare unchecked
 * claim, the master answers AUTH_HELLO with a probe: a random seed and a page
 * count derived from the claim (bounded to CAP_PROBE_CEILING_BYTES). The worker
 * must malloc that many pages, touch one seeded word per page -- malloc here is
 * eager (SBRK_EAGER -> growproc -> uvmalloc kallocs every page), so the
 * allocation itself fails if the node cannot back the claim, whether by physical
 * exhaustion or by the worker's own RLIMIT_AS (IEEE Std 1003.1-2017) -- and
 * return a checksum over the seeded words. The master recomputes the checksum
 * independently (no buffer needed, the pattern is deterministic in the seed) and
 * rejects a mismatch.
 *
 * The touch is per-page, not per-word, so the probe is O(pages) and completes far
 * inside RPC_TIMEOUT_MS even at the ceiling. The ceiling bounds probe time and
 * memory; a claim above it is validated only up to the ceiling ("has at least
 * this much"), a deliberate deviation noted in README.md. A worker running a
 * byte-faithful binary that is genuinely short of memory is caught; a modified
 * binary that fabricates the checksum without allocating is out of scope without
 * attestation (that is what the PSK/HMAC identity below starts to address).
 */
#define CAP_PROBE_CEILING_BYTES (32 * 1024 * 1024)   /* probe at most 32 MB */

typedef struct {
    uint32 prev_ip;
    uint16 prev_port;
    uint32 next_ip;
    uint16 next_port;
} set_neighbor_t;

/* -----------------------------------------------------------------------
 * Master-side registry entry
 * ----------------------------------------------------------------------- */
typedef struct {
    worker_info_t info;                     /* as received in PROC_AUTH_HELLO       */
    uint32        probe_expected;           /* filled in PROC_AUTH_HELLO            */
    uint32        last_seen_ms;             /* updated on each PROC_HEARTBEAT       */
    uint8         state;                    /* WORKER_PENDING / ACTIVE / EXPIRED    */
    cap_ack_t     cap_ack_expected;         /* what the worker should answer        */
    uint32        probe_seed;               /* RAM sized-probe seed (AUTH_HELLO)    */
    uint32        probe_pages;              /* RAM sized-probe page count           */
    uint32        next_ip;                  /* IP of next worker default=master     */
    uint16        next_port;                /* port of next worker default=master   */
    uint32        prev_ip;                  /* IP of prev worker default=master     */
    uint16        prev_port;                /* port of prev worker default=master   */
} worker_entry_t;

extern worker_entry_t registry[MAX_WORKERS];

/* Print the master's per-reason RPC drop counters (malformed / rate-limited /
 * bad-program / unknown-proc) — malformed & abusive traffic made observable. */
void discovery_stats(void);

typedef struct {
    uint32 status;      /* PENDING                                            */
    uint32 probe_data;  /* liveness nonce for the worker to echo              */
    uint32 probe_seed;  /* RAM sized-probe: pattern seed                      */
    uint32 probe_pages; /* RAM sized-probe: pages to allocate + checksum      */
} auth_hello_reply_t;

typedef struct {
    rpc_addr_t     master;
    uint32         worker_id;
    worker_info_t *self;             /* our identity, replayed on re-register */
    uint32        *self_next_ip;     /* shared ring state, updated after re-register */
    uint16        *self_next_port;
    uint32        *self_prev_ip;
    uint16        *self_prev_port;
    volatile int  *needs_reregister; /* set by listen thread on PROC_EVICT   */
    volatile int  *reregistering;    /* we→listen: yield the socket to me     */
    volatile int  *listen_suspended; /* listen→us: I have parked rpc_recv     */
} heartbeat_args_t;

/* -----------------------------------------------------------------------
 * Worker API
 * ----------------------------------------------------------------------- */

/*
 * discovery_register — send PROC_AUTH_HELLO to master and wait for reply.
 * Returns RPC_OK on success.
 */
int discovery_register(const rpc_addr_t *master, worker_info_t *self,
                       set_neighbor_t *out_neighbors);

/*
 * discovery_heartbeat — send PROC_HEARTBEAT to master (fire and forget).
 * Call periodically to stay ACTIVE in the registry.
 */
int discovery_heartbeat(const rpc_addr_t *master, uint32 worker_id);

/*
 * discovery_listen_thread — worker-side thread that receives master→worker RPCs.
 * Pass a pointer to a listen_args_t (defined in discovery.h).
 */
typedef struct {
    rpc_addr_t  master;
    uint32      worker_id;
    uint32     *self_next_ip;   /* pointer into worker's local state */
    uint16     *self_next_port;
    uint32     *self_prev_ip;
    uint16     *self_prev_port;
    volatile int *needs_reregister;
    volatile int *reregistering;    /* heartbeat→us: park rpc_recv while it re-registers */
    volatile int *listen_suspended; /* us→heartbeat: rpc_recv is parked                   */
} listen_args_t;

void discovery_listen_thread(void *arg);

/*
 * discovery_inference_hook — where the listen thread sends inference-related
 * calls (PROC_ASSIGN_LAYERS, PROC_INFER_REQ). Set by the application; when it
 * is null those procedures are answered SYSTEM_ERR.
 */
extern void (*discovery_inference_hook)(const rpc_msg_t *msg, const rpc_addr_t *src);

/* -----------------------------------------------------------------------
 * Master API
 * ----------------------------------------------------------------------- */

/*
 * discovery_handle_call — dispatch an incoming CALL to the right handler.
 * Call this from your master recv loop for any INFERENCE_PROG message.
 * Returns RPC_OK or negative error; sends reply internally.
 */
int discovery_handle_call(const rpc_msg_t *msg, const rpc_addr_t *src, uint32 now_ms);


/*
* discovery_expire_workers — mark any workers that haven't sent a heartbeat
* in a while as EXPIRED. Call this periodically from your master loop.
*/
void discovery_expire_workers(uint32 now);

/*
 * discovery_notify_neighbor — master sends PROC_SET_NEIGHBOR to a worker.
 * Tells `dst` worker that its prev/next neighbors are now prev/next.
 */
int discovery_notify_neighbor(const rpc_addr_t *dst,
                              uint32 prev_ip, uint16 prev_port,
                              uint32 next_ip, uint16 next_port);

/*
 * discovery_assign_layers — split a model's layers over the ACTIVE workers and
 * send each one its PROC_ASSIGN_LAYERS.
 *
 * The split is even, with the remainder going to the lowest-indexed workers, so
 * the ranges are contiguous, non-overlapping and cover [0, n_layers) exactly.
 * It is deliberately NOT weighted by worker_info_t.RAM: that figure is
 * self-reported and unvalidated (threat-model item 1, "capability lying"), so
 * weighting by it would hand the largest shard to whichever node lies hardest.
 * No standard governs the split itself -- this is an implementation decision.
 *
 * Returns the number of workers assigned, or negative on error.
 */
int discovery_assign_layers(const assign_layers_t *tmpl, uint32 *out_ring_ids,
                            int max_ids);

/*
 * discovery_assign_one — assign layers to the k-th active worker only, so the
 * master can wait for each worker's shard to load before assigning the next
 * (keeping the assignment RPC out of the previous worker's fetch flood). Same
 * even split as discovery_assign_layers. Returns RPC_OK or a negative error.
 */
int discovery_assign_one(const assign_layers_t *tmpl, int k);

/*
 * discovery_ring_order — fill `out` with the ACTIVE workers in ring order.
 * Returns how many were written.
 */
int discovery_ring_order(int *out, int max);

/*
 * discovery_restitch_ring — recompute every survivor's prev/next over the
 * currently ACTIVE workers, closing the ring back to the master at both ends.
 * Returns the active count.
 *
 * Registration stitches the ring incrementally (handle_cap_ack links the new
 * worker in behind the old tail), but expiry only changes a worker's *state* --
 * it never re-links its neighbours. So after a loss the survivors' pointers
 * still name a node that is gone: the predecessor forwards its hop into the
 * hole, and if the tail was lost no worker's next is the master any more, so
 * master_ring_tail() cannot resolve and every returning activation is dropped.
 * Recomputing from the registry before a session is (re)formed makes the
 * registry the single authority on ring shape (RFC 2205 soft state: the
 * refreshed view, not the stale one, is what gets installed).
 *
 * Checks performed (by construction over the ACTIVE set, not at runtime):
 *   1. Membership is exactly what discovery_ring_order reports, so a SUSPECTED
 *      or EXPIRED worker cannot appear in the ring it produces.
 *   2. Both ends close on the master, and the sentinel is rpc_local_port() --
 *      whatever rpc_init actually bound -- not a fixed number, so the tail's
 *      next reaches us and master_ring_tail() can recognise it.
 *   3. The order matches registration's incremental stitch, since both derive
 *      their pointers from the same ordered ACTIVE list; the two paths agree
 *      without needing to be kept in sync by hand.
 */
int discovery_restitch_ring(void);
#endif /* _DISCOVERY_H_ */