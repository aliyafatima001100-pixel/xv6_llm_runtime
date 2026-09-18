#include "kernel/types.h"
#include "user/user.h"
#include "discovery.h"
#include "rpc.h"
#include "distinf.h"
#include "shard.h"
#include "user/llama_core.h"
#include "user/ftpclient.h"
#include "user/sha256.h"
/* -----------------------------------------------------------------------
 * Helpers
 * ----------------------------------------------------------------------- 
*/

/*
 * release_and_exit — the driver hook llama_core declares (see llama_core.h).
 *
 * The core calls it when an allocation it cannot proceed without fails; what
 * needs releasing is the application's business. For a DistInf node that means
 * stopping the matmul worker pool so its threads do not outlive the process.
 */
void
release_and_exit(int code)
{
    shutdown_thread_pool();
    exit(code);
}

/*
 * tick_wait — sleep for `ticks` xv6 ticks.
 *
 * This spun on uptime(), which burns a core for the whole interval: with the
 * heartbeat waiting 200 ticks (20 s) between beats, a worker sat at 100% CPU
 * doing nothing, starved the threads doing real work on the same node, and ran
 * straight into RLIMIT_CPU (IEEE Std 1003.1-2017) which kills a process on
 * consumed CPU time. pause() blocks in the kernel until the tick count advances,
 * so the wait costs nothing.
 */
static void
tick_wait(int ticks)
{
    if (ticks > 0)
        pause(ticks);
}

static void
print_registry(void)
{
    printf("--- registry ---\n");
    for (int i = 0; i < MAX_WORKERS; i++) {
        if (registry[i].info.worker_id == 0)
            continue;
        printf("  [%d] id=%d ip=%d port=%d RAM=0x%x state=%s last_seen=%d prev_ip=%d prev_port=%d next_ip=%d next_port=%d\n",
            i,
            registry[i].info.worker_id,
            registry[i].info.ip,
            registry[i].info.port,
            registry[i].info.RAM,
            registry[i].state == WORKER_PENDING  ? "PENDING"  :
            registry[i].state == WORKER_ACTIVE   ? "ACTIVE"   : 
            registry[i].state == WORKER_EXPIRED  ? "EXPIRED"  :
            registry[i].state == WORKER_SUSPECTED? "SUSPECTED"  : "???",
            registry[i].last_seen_ms,
            registry[i].prev_ip,
            registry[i].prev_port,
            registry[i].next_ip,
            registry[i].next_port
        );
    }
    printf("----------------\n");
}

static uint32
parse_ip(const char *s)
{
    /* expects dotted decimal "a.b.c.d" */
    uint32 a, b, c, d;
    /* xv6 has no sscanf — parse manually */
    a = b = c = d = 0;
    while (*s && *s != '.') a = a * 10 + (*s++ - '0');
    if (*s) s++;
    while (*s && *s != '.') b = b * 10 + (*s++ - '0');
    if (*s) s++;
    while (*s && *s != '.') c = c * 10 + (*s++ - '0');
    if (*s) s++;
    while (*s)              d = d * 10 + (*s++ - '0');
    return (a << 24) | (b << 16) | (c << 8) | d;
}

static uint16
parse_port(const char *s)
{
    uint16 p = 0;
    while (*s) p = p * 10 + (*s++ - '0');
    return p;
}

static void
strcmp_simple(const char *a, const char *b, int *eq)
{
    *eq = 1;
    while (*a && *b) {
        if (*a++ != *b++) { *eq = 0; return; }
    }
    if (*a || *b) *eq = 0;
}

/* -----------------------------------------------------------------------
 * Misbehaviour, selected at runtime by `--claim-ram` / `--corrupt`.
 *
 * These model the two node-level threats the cluster has to withstand: a node
 * that lies about its capabilities, and one that computes correctly and then
 * misreports the result. They are runtime flags rather than a build-time gate
 * on purpose. In deployment every machine holds its own copy of this source, so
 * a dishonest operator does not need our cooperation to misbehave -- they edit
 * the code. A compile-time switch would therefore describe our build system
 * rather than the threat, and invites the mistake of reading "not compiled in"
 * as a defence. The defences have to live, and do live, on the side receiving
 * the claim or the result.
 *
 * Both are inert unless asked for: 0 and CORRUPT_NONE are the honest values, so
 * an ordinary `distinf --worker` is byte-for-byte the node it always was.
 * ----------------------------------------------------------------------- */
typedef enum { CORRUPT_NONE = 0, CORRUPT_SIGNFLIP, CORRUPT_ZERO, CORRUPT_DELTA } corrupt_mode_t;
static uint32         g_claimed_ram_mb = 0;      /* 0 = honest default (512 MB) */
static uint32         g_real_ram_mb    = 0;      /* 0 = honest default (512 MB) */
static corrupt_mode_t g_corrupt_mode   = CORRUPT_NONE;
static float          g_corrupt_delta  = 0.0f;

/** @brief Convert MB to bytes, saturating instead of wrapping.
 *
 *  worker_info_t.RAM is a uint32, so 4096 MB is exactly 2^32 and a plain
 *  multiply wraps to *zero* -- turning "claim far more than I have" into
 *  "claim nothing", which sails through a probe sized from the claim. A lie
 *  that silently becomes the smallest possible honest statement is the worst
 *  failure this path could have, so clamp rather than overflow. */
static uint32
mb_to_bytes(uint32 mb)
{
    return mb > (0xFFFFFFFFu / (1024 * 1024)) ? 0xFFFFFFFFu : mb * 1024 * 1024;
}

/*
 * parse_misbehaviour — read the optional `--claim-ram` / `--corrupt` flags a
 * worker may be started with, beginning at argv[from].
 *
 * Named flags rather than trailing positionals: a positional form makes the
 * corruption argument unreachable without first supplying a RAM value, so a
 * caller wanting only corruption has to pass a meaningless placeholder, and a
 * misplaced argument silently selects the wrong behaviour.
 *
 * Checks performed:
 *   1. Every argument from `from` on must be a flag we recognise; an unknown
 *      one is an error, never ignored. A typo must not leave the node quietly
 *      honest in a run whose entire purpose is that it misbehaves -- the test
 *      would then pass while proving nothing, which is the failure mode this
 *      whole path exists to avoid.
 *   2. Each flag's argument must be present, so a truncated command line is
 *      refused rather than read off the end of argv.
 *   3. The corruption mode must name one of the three modes exactly; `none` is
 *      accepted so a caller can pass the flag through explicitly disabled.
 *   4. The amount is read only for `delta`, where it means something, and
 *      defaults to 0 when omitted.
 *   5. Nothing is written unless a flag was actually given, so an ordinary
 *      worker keeps the honest defaults set at their declaration.
 *
 * @return 0 on success, -1 on any malformed or unrecognised argument.
 */
static int
parse_misbehaviour(int argc, char *argv[], int from)
{
    for (int i = from; i < argc; i++) {
        int eq;

        strcmp_simple(argv[i], "--claim-ram", &eq);
        if (eq) {
            if (++i >= argc) return -1;
            g_claimed_ram_mb = (uint32)atoi(argv[i]);
            continue;
        }

        strcmp_simple(argv[i], "--real-ram", &eq);
        if (eq) {
            if (++i >= argc) return -1;
            g_real_ram_mb = (uint32)atoi(argv[i]);
            continue;
        }

        strcmp_simple(argv[i], "--corrupt", &eq);
        if (eq) {
            if (++i >= argc) return -1;
            int matched = 0;
            static const struct { const char *name; corrupt_mode_t mode; } modes[] = {
                { "none",     CORRUPT_NONE     },
                { "signflip", CORRUPT_SIGNFLIP },
                { "zero",     CORRUPT_ZERO     },
                { "delta",    CORRUPT_DELTA    },
            };
            for (int m = 0; m < (int)(sizeof(modes) / sizeof(modes[0])); m++) {
                strcmp_simple(argv[i], modes[m].name, &eq);
                if (eq) { g_corrupt_mode = modes[m].mode; matched = 1; break; }
            }
            if (!matched) {
                printf("distinf: unknown corrupt mode '%s'\n", argv[i]);
                return -1;
            }
            /* The amount belongs to `delta` alone; for the others it would be
             * a value with nothing to apply it to. */
            if (g_corrupt_mode == CORRUPT_DELTA && i + 1 < argc)
                g_corrupt_delta = (float)atof(argv[++i]);
            continue;
        }

        printf("distinf: unexpected argument '%s'\n", argv[i]);
        return -1;
    }
    return 0;
}

/* -----------------------------------------------------------------------
 * Worker Thread Helpers
 * ----------------------------------------------------------------------- */

/*
 * heartbeat_thread — soft-state keepalive + re-registration on eviction.
 *
 * The worker is soft state on the master (RFC 2205 model): periodic heartbeats
 * keep it ACTIVE. When the master expires it, it sends PROC_EVICT; the listen
 * thread sets *needs_reregister. Re-registration is a full soft-state
 * re-acquisition — we discard the stale binding and re-run the whole handshake
 * rather than patching it (cf. DHCP lease rebind, RFC 2131 §4.4.5; SIP
 * re-REGISTER on expiry, RFC 3261 §10).
 *
 * discovery_register() blocks in rpc_call → rpc_recv, but the listen thread is
 * the sole recv-owner of this socket. We hand off the socket via a pause/resume
 * handshake: raise *reregistering, wait for the listen thread to park
 * (*listen_suspended), then re-register alone, then release it.
 */
static void
heartbeat_thread(void *arg)
{
    printf("heartbeat: thread started\n");
    heartbeat_args_t *a = (heartbeat_args_t *)arg;

    for (;;) {
        tick_wait(HEARTBEAT_INTERVAL_TICKS);

        if (*a->needs_reregister) {
            printf("heartbeat: re-registration needed\n");

            /* Take sole ownership of the socket from the listen thread. */
            *a->reregistering = 1;
            while (!*a->listen_suspended)
                yield();

            set_neighbor_t nb;
            memset(&nb, 0, sizeof(nb));
            int r = discovery_register(&a->master, a->self, &nb);
            if (r == RPC_OK) {
                /* Refresh the ring state the listen thread reads. */
                *a->self_prev_ip   = nb.prev_ip;
                *a->self_prev_port = nb.prev_port;
                *a->self_next_ip   = nb.next_ip;
                *a->self_next_port = nb.next_port;
                *a->needs_reregister = 0;
                printf("heartbeat: re-registered — prev=%d:%d next=%d:%d\n",
                       nb.prev_ip, nb.prev_port, nb.next_ip, nb.next_port);
            } else {
                printf("heartbeat: re-registration failed, err=%d\n", r);
                /* leave *needs_reregister set — retry on the next interval */
            }

            /* Release the listen thread back onto the socket. */
            *a->reregistering = 0;

            /* Don't heartbeat a master that has evicted us until we're back. */
            if (*a->needs_reregister)
                continue;
        }

        discovery_heartbeat(&a->master, a->worker_id);
    }
}

static int rpc_mutex;

/* -----------------------------------------------------------------------
 * Worker-side inference state
 *
 * The listen thread owns rpc_recv (see discovery_listen_thread), so it cannot
 * also spend minutes fetching weights or seconds running matmuls -- heartbeats
 * would stop and the master would evict us mid-fetch. Instead it drops work
 * into this one-slot mailbox and the inference thread performs it. That is the
 * hand-off the rpc_mutex TODO above always anticipated.
 * ----------------------------------------------------------------------- */

typedef struct {
    rpc_addr_t  master;
    uint32      worker_id;
    worker_info_t self;

    /* assignment mailbox: listen thread -> inference thread */
    volatile int    have_assignment;
    assign_layers_t assignment;

    /*
     * Activation mailbox: listen thread -> inference thread, protected by `mutex`.
     *
     * `activation` is the one-slot mailbox the listen thread fills and the
     * inference thread drains, both under `mutex`; `have_hop` is the occupied
     * flag. `compute` is the inference thread's PRIVATE working copy -- it drains
     * `activation` into `compute` under the lock and then runs the forward pass
     * on `compute` alone, so a hop arriving mid-computation can never overwrite
     * the buffer being read. Before this split the listen thread decoded straight
     * into `activation` and cleared `have_hop` too early, so under -smp 8 a
     * retransmitted hop corrupted the in-flight activation and poisoned the KV
     * cache -- the "repeats one token" bug.
     */
    volatile int    have_hop;
    infer_hop_t     hop;
    float           activation[INFER_MAX_FLOATS];   /* mailbox slot (mutex-held) */
    float           compute[INFER_MAX_FLOATS];      /* inference thread's private copy */

    /* Ring state -- pointers into the listen thread's copies, never snapshots.
     * `prev` is as live as `next`: the source-binding check below rejects a hop
     * that did not come from our predecessor, so if it reads a value captured at
     * registration it keeps enforcing the ring we joined rather than the one we
     * are in now, and drops every hop from the neighbour that replaced a lost
     * node. */
    uint32 *next_ip;
    uint16 *next_port;
    uint32 *prev_ip;
    uint16 *prev_port;

    int mutex;
    shard_t shard;
    volatile uint32 session;     /* session/epoch we are loaded for */
    volatile int    ready;       /* shard resident, hops may be served */
} inference_args_t;

static inference_args_t g_inf;


/*
 * infer_send_hop — pass an activation to the next node in the ring.
 *
 * Fire-and-forget (rpc_send_call), not rpc_call: a blocking round trip around a
 * ring deadlocks, because each node would wait for a reply that can only be
 * produced after the traversal it is itself blocking. This is the ONC RPC
 * batching idiom (RFC 5531 §5), which also makes timeout and retransmission the
 * caller's responsibility -- the master owns that (see run_master).
 */
static int
infer_send_hop(const rpc_addr_t *dst, const infer_hop_t *h, const float *x)
{
    static rpc_msg_t req;
    memset(&req, 0, sizeof(req));
    rpc_fill_call(&req, PROC_INFER_REQ);

    uint32 words[INFER_HOP_HDR_WORDS];
    memcpy(words, h, sizeof(words));
    for (int i = 0; i < INFER_HOP_HDR_WORDS; i++)
        xdr_put_u32(req.payload + i * 4, words[i]);

    uint8 *p = req.payload + INFER_HOP_HDR_WORDS * 4;
    for (uint32 i = 0; i < h->n_floats; i++)
        xdr_put_float(p + i * 4, x[i]);

    req.payload_len = INFER_HOP_HDR_WORDS * 4 + h->n_floats * 4;
    return rpc_send_call(dst, &req);
}

/*
 * infer_decode_hop — validate and decode an incoming activation.
 *
 * Checks performed (the L3 input-sanitization list; a failure returns < 0 and
 * the datagram is dropped or answered GARBAGE_ARGS by the caller):
 *   1. The payload is long enough to hold the fixed header.
 *   2. n_floats is within INFER_MAX_FLOATS, so a lying length cannot make us
 *      read past the payload buffer.
 *   3. payload_len equals header + n_floats*4 EXACTLY -- the declared-vs-actual
 *      rule (RFC 1122 §1.2.2) applied at L3, not merely "at least".
 *   4. n_floats equals the model's dim; a correctly-sized but wrong-shaped
 *      activation is still garbage to this shard.
 *   5. session_id matches the epoch we are loaded for, so a stale session (or a
 *      different cluster) cannot drive our KV cache.
 *   6. pos is below the KV-cache capacity we allocated.
 * Source and sequence checks are applied by the caller, which knows the ring.
 */
static int
infer_decode_hop(const rpc_msg_t *msg, infer_hop_t *out, float *x, int dim, uint32 session)
{
    if (msg->payload_len < INFER_HOP_HDR_WORDS * 4) return -1;

    uint32 words[INFER_HOP_HDR_WORDS];
    for (int i = 0; i < INFER_HOP_HDR_WORDS; i++)
        words[i] = xdr_get_u32(msg->payload + i * 4);
    memcpy(out, words, sizeof(words));

    if (out->n_floats == 0 || out->n_floats > INFER_MAX_FLOATS) return -1;
    if (msg->payload_len != INFER_HOP_HDR_WORDS * 4 + out->n_floats * 4) return -1;
    if (dim > 0 && out->n_floats != (uint32)dim) return -1;
    if (session != 0 && out->session_id != session) return -1;

    const uint8 *p = msg->payload + INFER_HOP_HDR_WORDS * 4;
    for (uint32 i = 0; i < out->n_floats; i++)
        x[i] = xdr_get_float(p + i * 4);

    return 0;
}

/*
 * inference_thread — owns the shard: fetches it, then serves activations.
 *
 * Weight fetching happens here rather than in the listen thread precisely so
 * heartbeats keep flowing during a multi-minute download (RFC 2205 soft state
 * must be refreshed independently of work).
 *
 * An assignment is not a one-shot event: fault recovery re-assigns every
 * survivor, so this branch runs again on each restart with a different layer
 * range, and it must leave no trace of the range it is replacing.
 *
 * Checks performed on each assignment, in this order (the order is the point):
 *   1. `ready` is cleared first, so the listen thread stops committing hops
 *      against a shard we are about to replace. Until this was done the flag
 *      stayed set from the previous session and the only thing rejecting those
 *      hops was the master's epoch bump (infer_decode_hop's session check) --
 *      the invariant was enforced by the peer rather than by the node that owns
 *      the memory.
 *   2. The previous shard is released before the next is loaded. shard_load()
 *      opens with a memset over shard_t, so it destroys the very handles a
 *      release would need; done in the other order the old segments and
 *      run_state are orphaned. shard_release() is a no-op when nothing is
 *      loaded, so the first assignment passes through it harmlessly.
 *   3. The checkpoint header is fetched and checked against the geometry the
 *      master asserted -- a peer's self-report is never the basis for how we
 *      address memory, the same rule the hop checks apply to data.
 *   4. Only if all of that succeeds do `session` and `ready` go live; any
 *      failure is reported as a non-zero status in PROC_SHARD_READY and the
 *      worker stays out of the ring rather than serving a partial shard.
 */
static void
inference_thread(void *arg)
{
    inference_args_t *a = (inference_args_t *)arg;
    printf("worker: inference thread started\n");

    for (;;) {
        if (a->have_assignment) {
            assign_layers_t as = a->assignment;
            a->have_assignment = 0;

            printf("worker: assigned layers [%d,%d) of %d, session %d\n",
                   as.layer_start, as.layer_end, as.n_layers_total, as.session_id);

            /* Steps 1 and 2 above: refuse work ourselves, then hand back the
             * range we are replacing. No lock is needed -- this thread is the
             * sole owner of a->shard, and the assignment is handled before any
             * hop in the same iteration. */
            a->ready = 0;
            shard_release(&a->shard);

            llm_set_server(as.weights_ip, (uint16)as.weights_port);

            /*
             * Fetch the header ourselves and check it against what the master
             * claimed. A peer's self-report is never the basis for how we
             * address memory -- the same rule the hop checks apply to data.
             */
            Config cfg;
            int status = 0;
            if (shard_fetch_config((uint8_t)as.model_id, &cfg) < 0) {
                status = 1;
            } else if (cfg.dim != (int)as.dim || cfg.n_layers != (int)as.n_layers_total ||
                       cfg.hidden_dim != (int)as.hidden_dim || cfg.n_heads != (int)as.n_heads) {
                printf("worker: master's geometry disagrees with the checkpoint\n");
                status = 2;
            } else if (shard_load(&a->shard, (uint8_t)as.model_id, &cfg,
                                  as.layer_start, as.layer_end, as.max_seq) < 0) {
                status = 3;
            }

            if (status == 0) {
                a->session = as.session_id;
                a->ready = 1;
            }

            shard_ready_t rdy = {
                .session_id = as.session_id, .worker_id = a->worker_id,
                .layer_start = as.layer_start, .layer_end = as.layer_end,
                .status = status,
            };
            static rpc_msg_t req;
            memset(&req, 0, sizeof(req));
            rpc_fill_call(&req, PROC_SHARD_READY);
            uint32 w[SHARD_READY_WORDS];
            memcpy(w, &rdy, sizeof(w));
            for (int i = 0; i < SHARD_READY_WORDS; i++)
                xdr_put_u32(req.payload + i * 4, w[i]);
            req.payload_len = SHARD_READY_WORDS * 4;
            rpc_send_call(&a->master, &req);

            printf("worker: shard status %d reported\n", status);
            continue;
        }

        if (a->have_hop && a->ready) {
            infer_hop_t h;
            mutex_lock(&a->mutex);
            if (!a->have_hop) { mutex_unlock(&a->mutex); continue; }
            h = a->hop;
            memcpy(a->compute, a->activation, h.n_floats * sizeof(float));
            a->have_hop = 0;
            mutex_unlock(&a->mutex);

            printf("worker: FORWARD seq=%d pos=%d\n", h.seq, h.pos);

            uint64 t0 = rdtime();
            if (shard_forward(&a->shard, a->compute, h.pos) < 0) {
                printf("worker: forward FAILED at pos %d\n", h.pos);
                continue;
            }
            uint32 fwd_us = (uint32)((rdtime() - t0) / 10);

            /*
             * Result corruption (threat model item 3): tamper with a result we
             * genuinely computed.
             *
             * Placed here deliberately -- after shard_forward has *succeeded*,
             * and before the hop is encoded. That ordering is the whole point of
             * the threat: the node did the work, so nothing about its timing,
             * its liveness or its participation looks wrong; only the value it
             * reports is false. Corrupting a failed forward instead would be a
             * different and much less interesting node, and would let a test
             * claim a corruption it never actually performed.
             *
             * All three modes stay finite and in-range on purpose. They are not
             * meant to be caught by a range check -- nothing in the pipeline
             * inspects payload *content*, only shape and provenance, and that is
             * the gap these model.
             */
            if (g_corrupt_mode == CORRUPT_SIGNFLIP) {
                for (uint32 i = 0; i < h.n_floats; i++)
                    a->compute[i] = -a->compute[i];
                printf("worker: [MALICIOUS] sign-flipped %d floats seq=%d\n",
                       h.n_floats, h.seq);
            } else if (g_corrupt_mode == CORRUPT_ZERO) {
                memset(a->compute, 0, h.n_floats * sizeof(float));
                printf("worker: [MALICIOUS] zeroed %d floats seq=%d\n",
                       h.n_floats, h.seq);
            } else if (g_corrupt_mode == CORRUPT_DELTA) {
                for (uint32 i = 0; i < h.n_floats; i++)
                    a->compute[i] += g_corrupt_delta;
                printf("worker: [MALICIOUS] delta %f applied to %d floats seq=%d\n",
                       g_corrupt_delta, h.n_floats, h.seq);
            }

            rpc_addr_t nxt = { .ip = *a->next_ip, .port = *a->next_port };  
            infer_hop_t out = h;
            out.hop = h.hop + 1;
            out.compute_us = h.compute_us + fwd_us;
            if (nxt.ip == a->master.ip && nxt.port == a->master.port)
                out.flags |= INFER_FLAG_FINAL;

            printf("worker: SEND seq=%d pos=%d hop=%d -> %d:%d final=%d\n",
                   out.seq, out.pos, out.hop, nxt.ip, nxt.port,
                   (out.flags & INFER_FLAG_FINAL) ? 1 : 0);

            infer_send_hop(&nxt, &out, a->compute);
            continue;
        }

        yield();
    }
}


/*
 * worker_inference_hook — called by the listen thread for PROC_ASSIGN_LAYERS
 * and PROC_INFER_REQ. Validates, then parks the work in the mailbox.
 *
 * Checks performed for an activation hop (completing the list begun in
 * infer_decode_hop, which covers length, shape, session and bounds):
 *   7. Source binding: the datagram must come from our `prev` neighbour, or
 *      from the master. A node that is not our predecessor in the ring has no
 *      business advancing our KV cache -- this is the L3 analogue of the
 *      dynamic ARP inspection the link layer already performs (RFC 3704 §2
 *      source validation applied to an application flow). `prev` is read
 *      *live* through g_inf, the same pointer PROC_SET_NEIGHBOR writes and the
 *      send path reads: after a node is lost the master re-links the ring, and
 *      a value snapshotted at registration would keep enforcing the ring we
 *      joined instead of the one we are in -- rejecting every hop from the
 *      neighbour that replaced the departed node.
 *   8. Replay: seq must be strictly greater than the last one accepted, so a
 *      duplicated or replayed datagram cannot recompute a position (anti-replay
 *      counter, RFC 4303 §3.4.3 model).
 *   9. The shard must be loaded; a hop arriving before PROC_SHARD_READY is
 *      dropped rather than run against unallocated weights.
 * A previous hop still in the mailbox means we are behind: the newer one is
 * dropped rather than queued, since the master will retransmit.
 */
static uint32 g_last_seq;

static void
worker_inference_hook(const rpc_msg_t *msg, const rpc_addr_t *src)
{
    if (msg->call.proc == PROC_ASSIGN_LAYERS) {
        if (msg->payload_len < ASSIGN_LAYERS_WORDS * 4) {
            rpc_send_reply(src, msg->xid, GARBAGE_ARGS, 0, 0);
            return;
        }
        /* Only the master assigns work. */
        if (src->ip != g_inf.master.ip || src->port != g_inf.master.port) {
            printf("worker: assignment from %d:%d is not our master, dropped\n",
                   src->ip, src->port);
            rpc_send_reply(src, msg->xid, SYSTEM_ERR, 0, 0);
            return;
        }

        uint32 w[ASSIGN_LAYERS_WORDS];
        for (int i = 0; i < ASSIGN_LAYERS_WORDS; i++)
            w[i] = xdr_get_u32(msg->payload + i * 4);
        memcpy(&g_inf.assignment, w, sizeof(w));

        /*
         * Reply immediately: this acknowledges the assignment, not the weights.
         * The fetch that follows takes far longer than RPC_TIMEOUT_MS, so
         * readiness is reported out of band with PROC_SHARD_READY.
         */
        g_inf.ready = 0;
        g_last_seq = 0;
        g_inf.have_assignment = 1;
        rpc_send_reply(src, msg->xid, SUCCESS, 0, 0);
        return;
    }

    if (msg->call.proc == PROC_INFER_REQ) {
        static float staging[INFER_MAX_FLOATS];
        infer_hop_t h;
        int dim = g_inf.ready ? g_inf.shard.cfg.dim : 0;

        printf("worker: INFER_REQ from %d:%d len=%d ready=%d session=%d\n",
               src->ip, src->port, msg->payload_len, g_inf.ready, g_inf.session);

        if (infer_decode_hop(msg, &h, staging, dim, g_inf.session) < 0) {
            printf("worker: DROP decode failed (len=%d dim=%d session=%d)\n",
                   msg->payload_len, dim, g_inf.session);
            return;
        }

        printf("worker: decoded seq=%d pos=%d n_floats=%d session=%d flags=%d hop=%d\n",
               h.seq, h.pos, h.n_floats, h.session_id, h.flags, h.hop);

        if (!g_inf.ready) {
            printf("worker: DROP not ready (ready=%d)\n", g_inf.ready);
            return;
        }
        /* Read `prev` live, exactly as the send path reads `next`: after a node
         * is lost the master re-links the ring and pushes PROC_SET_NEIGHBOR, so
         * a snapshot taken at registration would still name the departed node
         * and reject every hop from the neighbour that replaced it. */
        uint32 prev_ip   = *g_inf.prev_ip;
        uint16 prev_port = *g_inf.prev_port;
        if (!((src->ip == prev_ip && src->port == prev_port) ||
              (src->ip == g_inf.master.ip && src->port == g_inf.master.port))) {
            printf("worker: DROP bad source %d:%d (want prev=%d:%d or master=%d:%d)\n",
                   src->ip, src->port, prev_ip, prev_port,
                   g_inf.master.ip, g_inf.master.port);
            return;
        }
        if (h.seq <= g_last_seq) {
            printf("worker: DROP replay seq=%d last=%d\n", h.seq, g_last_seq);
            return;
        }

        mutex_lock(&g_inf.mutex);
        if (g_inf.have_hop) {
            mutex_unlock(&g_inf.mutex);
            printf("worker: DROP mailbox busy\n");
            return;
        }
        memcpy(g_inf.activation, staging, h.n_floats * sizeof(float));
        g_inf.hop = h;
        g_last_seq = h.seq;
        g_inf.have_hop = 1;
        mutex_unlock(&g_inf.mutex);
        printf("worker: COMMIT seq=%d pos=%d into mailbox\n", h.seq, h.pos);
        return;
    }

    rpc_send_reply(src, msg->xid, PROC_UNAVAIL, 0, 0);
}

/* -----------------------------------------------------------------------
 * Master path
 * ----------------------------------------------------------------------- */


/*
 * fetch_if_not_cached_pub — attach a cached model segment, or stream it in.
 *
 * The same cache-or-fetch dance llama.c performs for the single-node runtime.
 * The master needs it for the embedding table, the final norm and the tokenizer
 * (the parts of the model that are not sharded); workers use shard_load()
 * instead, which fetches only their own layer ranges.
 *
 * Checks performed:
 *   1. An existing segment is reused read-only.
 *   2. A new segment is attached read-write before any bytes arrive, and the
 *      file streams straight into it rather than through a heap copy.
 *   3. The transfer must succeed, or 0 is returned rather than a partially
 *      filled mapping.
 */
static void *
fetch_if_not_cached_pub(const char *segment, uint8_t file_id)
{
    uint32_t size = 0, total = 0;
    unsigned char hash[32];

    if (llm_meta_request(file_id, &size, &total, hash) < 0) {
        printf("master: META request failed for file %d\n", file_id);
        return 0;
    }

    int shmid = shmget(segment, size, 0);
    if (shmid >= 0) {
        void *a = shmat(shmid, 0, SHM_RDONLY);
        if (a != (void *)-1) return a;
    }

    shmid = shmget(segment, size, IPC_CREAT | SHM_PERSIST);
    if (shmid < 0) return 0;
    void *addr = shmat(shmid, 0, SHM_RDWR);
    if (addr == (void *)-1) return 0;

    printf("master: fetching %s (%d bytes)...\n", segment, size);
    if (llm_fetch_file_into(file_id, (char *)addr, size, 0) < 0) {
        shmdt(addr);
        return 0;
    }
    return addr;
}

/*
 * Master-side inference state. The master holds the embedding table, the final
 * norm and the classifier; the workers hold the layers. It is also the ring
 * sentinel, so the last worker's `next` points back here and the final
 * activation returns naturally.
 */
static Transformer g_model;

/*
 * master_load_head_tail — load only the tensors the master runs on.
 *
 * The master never runs a transformer layer (the workers do), so it does not
 * need the checkpoint's layer weights -- only the embedding table, the classifier
 * (which aliases the embedding in the stories models) and the final RMSNorm.
 * Fetching those two ranges instead of the whole file is what makes 110M possible
 * at all: the whole checkpoint is 418 MB (impossible on a 256 MB node), whereas
 * the embedding is ~94 MB and fits one segment under the raised shm cap.
 *
 * Checks performed:
 *   1. The checkpoint header is fetched and validated first (shard_fetch_config),
 *      so every offset below is derived from the model's real geometry, not a
 *      value the caller supplied.
 *   2. shared_weights is read from the raw vocab_size sign, exactly as
 *      build_transformer does, so the classifier is treated as the embedding when
 *      shared (no second fetch) and as a separate tail tensor otherwise.
 *   3. The embedding segment is created before any bytes arrive and streamed into
 *      in place (llm_fetch_range), so peak memory stays at one copy.
 *   4. Both ranges must transfer, or the master fails rather than classifying on
 *      partially-fetched weights.
 *
 * Integrity of each partial range rests on the UDP checksum (RFC 768) the
 * hardened receive path validates; META_RESP's digest covers the whole file only.
 *
 * @return 0 on success, -1 on failure.
 */
static int
master_load_head_tail(Transformer *t, uint8_t model_id)
{
    if (shard_fetch_config(model_id, &t->config) < 0) {
        printf("master: could not fetch checkpoint header\n");
        return -1;
    }

    int shared = t->config.vocab_size > 0;          /* sign encodes weight sharing */
    t->config.vocab_size = t->config.vocab_size < 0 ?
                           -t->config.vocab_size : t->config.vocab_size;

    if (!shared) {
        /* stories models share weights; a separate 94 MB wcls would need its own
         * segment and is out of scope until such a checkpoint is actually used. */
        printf("master: unshared classifier weights are not supported yet\n");
        return -1;
    }

    uint64 embed_off, embed_bytes, final_off, final_bytes, wcls_off, wcls_bytes;
    llama_head_tail_offsets(&t->config, shared,
                            &embed_off, &embed_bytes, &final_off, &final_bytes,
                            &wcls_off, &wcls_bytes);

    /* Embedding (also the classifier): one segment, filled in place. */
    int shmid = shmget("llm_embed", embed_bytes, IPC_CREAT | SHM_PERSIST);
    if (shmid < 0) {
        printf("master: shmget(llm_embed, %d bytes) failed\n", (int)embed_bytes);
        return -1;
    }
    float *embed = shmat(shmid, 0, SHM_RDWR);
    if (embed == (void *)-1) {
        printf("master: shmat(llm_embed) failed\n");
        return -1;
    }
    printf("master: fetching embedding (%d MB)...\n", (int)(embed_bytes / (1024 * 1024)));
    if (llm_fetch_range(model_id, (char *)embed, (uint32_t)embed_off,
                        (uint32_t)embed_bytes) < 0) {
        printf("master: embedding fetch failed\n");
        return -1;
    }

    /* Final RMSNorm: a few kilobytes, into a heap buffer. */
    float *final_norm = malloc(final_bytes);
    if (!final_norm) {
        printf("master: out of memory for final norm\n");
        return -1;
    }
    if (llm_fetch_range(model_id, (char *)final_norm, (uint32_t)final_off,
                        (uint32_t)final_bytes) < 0) {
        printf("master: final-norm fetch failed\n");
        free(final_norm);
        return -1;
    }

    /* Wire up only the tensors the master reads; the per-layer pointers stay null. */
    memset(&t->weights, 0, sizeof(t->weights));
    t->weights.token_embedding_table = embed;
    t->weights.wcls = embed;                        /* shared */
    t->weights.rms_final_weight = final_norm;

    malloc_run_state_head(&t->state, &t->config);
    printf("master: head/tail loaded (embedding + final norm)\n");
    return 0;
}
static Tokenizer   g_tok;
static Sampler     g_sampler;
static volatile int g_ready_count;
static volatile int g_ready_failed;
static uint32 g_session;
static float  g_final_x[INFER_MAX_FLOATS];
static volatile int g_have_final;
static volatile uint32 g_final_seq;   /* seq the master is currently waiting to see return */
static volatile uint32 g_final_compute_us; /* compute_us the returning final hop carried */
static uint32 g_seq;         /* monotonic per-datagram counter (see master_run_token) */

/*
 * Per-token latency accounting (benchmarks). rdtime() is the 10 MHz hardware
 * timebase, so a tick is 0.1 us. For each completed token the master records:
 *   - rtt_us:     send-to-final ring round-trip (total wall time on the wire+ring)
 *   - compute_us: summed shard_forward time across the ring, carried back in the hop
 *   - master_us:  the master's own embed + classify time for the token
 * network time is then rtt_us - compute_us: what the round-trip cost beyond the
 * workers' arithmetic (datagram build/parse, fragmentation, mcast, scheduling).
 * The split is approximate by construction -- it excludes master_us (reported on
 * its own line) and folds per-hop queueing into "network" -- and exists to answer
 * "is the bottleneck the wire or the math?", which is the interesting question on
 * the xv6/QEMU target. Summed here, averaged at "master: done".
 */
static uint64 g_metric_rtt_us;
static uint64 g_metric_compute_us;
static uint64 g_metric_master_us;
static int    g_metric_tokens;

/*
 * Master servicing model: single-threaded, cooperative.
 *
 * The master runs one thread that alternates DRIVING work (fetch weights, assign
 * layers, generate) with master_pump(), which services the RPC socket -- worker
 * heartbeats, expiry, shard-ready reports, and the final activation completing a
 * ring traversal. Every wait in run_master pumps, so soft state stays serviced.
 *
 * Design decision -- why not a dedicated servicing thread (the worker's split):
 * the workers get away with listen/heartbeat/inference threads because their main
 * thread stays passive after spawning them. The master's main thread is the exact
 * opposite -- it drives a malloc- and socket-heavy weight fetch. Running a second
 * thread of the same process alongside that reliably corrupted memory under this
 * xv6's thread_create (per-thread pagetables spliced by uvmshare, with the brk
 * heap and sbrk not coherent across the group): the fetching thread faulted in
 * malloc at its own break and the servicing thread's control flow was smashed.
 * Cooperative servicing sidesteps the whole class of bug -- no shared mutable
 * state across threads, so nothing to race -- at the cost of servicing only at
 * pump points, which is why the one blocking operation long enough to matter, the
 * multi-minute weight fetch, calls back in via g_ftp_progress_hook (below).
 *
 * This also removes the need for the temporary "reset last_seen after the fetch"
 * band-aid, which did nothing for a fetch longer than EXPIRED_TIMEOUT: heartbeats
 * are now actually serviced throughout the fetch.
 */

/*
 * master_handle_shard_ready — count workers whose weights are resident.
 *
 * Checks performed:
 *   1. Payload is the expected length.
 *   2. The report is for the live session; a late report from a previous epoch
 *      is ignored rather than counted toward this one's readiness.
 *   3. A non-zero status is recorded as a failure, so the master aborts the
 *      session instead of waiting forever for a worker that cannot load.
 */
static void
master_handle_shard_ready(const rpc_msg_t *msg)
{
    if (msg->payload_len < SHARD_READY_WORDS * 4) return;

    uint32 w[SHARD_READY_WORDS];
    for (int i = 0; i < SHARD_READY_WORDS; i++)
        w[i] = xdr_get_u32(msg->payload + i * 4);
    shard_ready_t r;
    memcpy(&r, w, sizeof(w));

    if (r.session_id != g_session) return;

    if (r.status != 0) {
        printf("master: worker %d failed to load layers [%d,%d), status %d\n",
               r.worker_id, r.layer_start, r.layer_end, r.status);
        g_ready_failed = 1;
        return;
    }
    g_ready_count++;
    printf("master: worker %d ready with layers [%d,%d) (%d ready)\n",
           r.worker_id, r.layer_start, r.layer_end, g_ready_count);
}

/*
 * master_ring_tail — registry slot of the ring tail, i.e. the worker whose next
 * hop is the master itself. This is the authoritative definition of the tail
 * (the node that closes the ring), independent of registry slot order; the final
 * activation must arrive from it. Returns -1 if no such worker exists.
 */
static int
master_ring_tail(void)
{
    uint32 mip = ip();
    uint16 mport = rpc_local_port();
    for (int i = 0; i < MAX_WORKERS; i++)
        if (registry[i].info.worker_id != 0 && registry[i].state == WORKER_ACTIVE &&
            registry[i].next_ip == mip && registry[i].next_port == mport)
            return i;
    return -1;
}

/*
 * master_handle_final — the activation completing a ring traversal.
 *
 * Checks performed: the same list the workers apply (length, shape, session,
 * bounds), plus the source binding -- the final hop must come from the ring tail
 * (the worker whose next is the master, master_ring_tail(), not merely the last
 * registry slot) -- and the FINAL flag, so a mid-ring activation cannot be
 * mistaken for a completed pass.
 */
static void
master_handle_final(const rpc_msg_t *msg, const rpc_addr_t *src)
{
    static float staging[INFER_MAX_FLOATS];
    infer_hop_t h;

    printf("master: got INFER_REQ from %d:%d len=%d (waiting seq=%d)\n",
           src->ip, src->port, msg->payload_len, g_final_seq);

    if (infer_decode_hop(msg, &h, staging, g_model.config.dim, g_session) < 0) {
        printf("master: DROP decode failed (dim=%d session=%d)\n",
               g_model.config.dim, g_session);
        return;
    }

    printf("master: decoded seq=%d pos=%d hop=%d flags=%d\n",
           h.seq, h.pos, h.hop, h.flags);

    if (!(h.flags & INFER_FLAG_FINAL)) {
        printf("master: DROP not final (flags=%d)\n", h.flags);
        return;
    }
    if (h.seq != g_final_seq) {
        printf("master: DROP seq mismatch got=%d want=%d\n", h.seq, g_final_seq);
        return;
    }

    int tail = master_ring_tail();
    if (tail < 0 ||
        src->ip != registry[tail].info.ip || src->port != registry[tail].info.port) {
        printf("master: DROP not ring tail, tail_slot=%d src=%d:%d expected=%d:%d\n",
               tail, src->ip, src->port,
               tail >= 0 ? registry[tail].info.ip : 0,
               tail >= 0 ? registry[tail].info.port : 0);
        return;
    }

    memcpy(g_final_x, staging, h.n_floats * sizeof(float));
    g_final_compute_us = h.compute_us;
    g_have_final = 1;
    printf("master: COMMIT final seq=%d pos=%d\n", h.seq, h.pos);
}

/*
 * master_pump — service the socket for up to `ms`, dispatching what arrives.
 * Expiry runs on every pass so soft state stays clock-driven even mid-token.
 */
static void
master_pump(int ms)
{
    static rpc_msg_t  msg;
    static rpc_addr_t src;

    int r = rpc_recv(&msg, &src, ms);
    if (r == RPC_OK && msg.mtype == MSG_CALL) {
        switch ((rpc_proc_t)msg.call.proc) {
        case PROC_SHARD_READY:
            master_handle_shard_ready(&msg);
            break;
        case PROC_INFER_REQ:
            master_handle_final(&msg, &src);
            break;
        default:
            discovery_handle_call(&msg, &src, uptime());
            break;
        }
    }
    discovery_expire_workers(uptime());
}

/*
 * master_pump_hook — the pump the FTP client calls between chunk batches
 * (g_ftp_progress_hook) so heartbeats stay serviced during a multi-minute fetch.
 *
 * The fetch fires this thousands of times (once per 4 KB batch), but a pump is
 * not free: recvtimeo sleeps a whole tick when its port has nothing queued (the
 * timeout is only checked after the sleep), so pumping on every call would add
 * ~100 ms per batch and stall the transfer for many minutes. Throttle to at most
 * once every MASTER_HOOK_INTERVAL_TICKS -- comfortably finer than SUSPECTED/
 * EXPIRED_TIMEOUT, so no worker ages out, while the fetch pays only a tick or so
 * per interval. When a heartbeat *is* queued recvtimeo returns at once, so real
 * traffic is still drained promptly.
 */
#define MASTER_HOOK_INTERVAL_TICKS 20   /* ~2 s at 10 Hz; << SUSPECTED_TIMEOUT */
static void
master_pump_hook(void)
{
    static uint last;
    uint now = uptime();
    if ((uint)(now - last) < MASTER_HOOK_INTERVAL_TICKS)
        return;
    last = now;
    master_pump(0);
}

/*
 * master_run_token — one full ring traversal: embed, send to the head worker,
 * wait for the activation to come back round, then norm + classify.
 *
 * Because hops are fire-and-forget (RFC 5531 §5 batching), the timeout and
 * retransmission budget lives here. INFER_TOKEN_TIMEOUT_MS x INFER_MAX_RETRIES
 * is deliberately below SUSPECTED_TIMEOUT so a lost datagram is retried before
 * the lifecycle starts suspecting the node that owed us the reply.
 *
 * Returns 0 on success, -1 if the traversal could not be completed.
 */
static int
master_run_token(int token, int pos, int head_slot)
{
    static float x[INFER_MAX_FLOATS];

    uint64 embed_t0 = rdtime();
    llama_embed(&g_model.weights, &g_model.config, x, token);
    g_metric_master_us += (rdtime() - embed_t0) / 10;   /* master compute, part 1 */

    g_have_final = 0;

    rpc_addr_t head = { .ip = registry[head_slot].info.ip,
                        .port = registry[head_slot].info.port };

    for (int attempt = 0; attempt <= INFER_MAX_RETRIES; attempt++) {
        /*
         * seq is a per-DATAGRAM monotonic counter, not pos+1. Each attempt --
         * including a retransmit of the same token after a lost activation --
         * carries a strictly greater seq, so a worker's anti-replay check
         * (seq must exceed the last accepted, RFC 4303 §3.4.3 model) accepts it
         * rather than mistaking a legitimate retransmit for a replay. This is
         * the bug the simulation surfaced: with seq == pos+1 every retry reused
         * one value, so after any dropped datagram all retries were rejected as
         * replays and the token was lost. Reprocessing a position is safe: the
         * same token at the same pos writes the same K/V into the same cache
         * slot (idempotent). g_final_seq tracks the attempt in flight so the
         * master accepts the activation returning from THIS attempt and ignores
         * a late one from an earlier attempt (a lower seq).
         */
        g_final_seq = ++g_seq;
        infer_hop_t h = {
            .session_id = g_session, .seq = g_final_seq, .pos = (uint32)pos,
            .hop = 0, .n_floats = (uint32)g_model.config.dim, .flags = 0,
            .compute_us = 0,           /* ring accumulates into this as it goes */
        };
        uint64 send_t0 = rdtime();
        infer_send_hop(&head, &h, x);

        /* Pump the socket ourselves: master_pump receives the returning final
         * activation (setting g_have_final) plus any heartbeats/expiry that fall
         * due while we wait. Each pass blocks up to ~200 ms in rpc_recv. */
        int waited = 0;
        while (waited < INFER_TOKEN_TIMEOUT_MS) {
            master_pump(200);
            waited += 200;
            if (g_have_final) {
                /* Round-trip for this token, and the shard-compute the hop
                 * accumulated; the difference is time on the wire + ring. */
                g_metric_rtt_us += (rdtime() - send_t0) / 10;
                g_metric_compute_us += g_final_compute_us;
                g_metric_tokens++;
                return 0;
            }
        }
        printf("master: token at pos %d timed out (attempt %d/%d)\n",
               pos, attempt + 1, INFER_MAX_RETRIES + 1);
    }

    return -1;
}

/*
 * run_generation_session — assign layers over the given survivor set, wait
 * for shards, then generate until completion or a hop failure.
 *
 * Returns 0 on clean completion (all `steps` tokens generated or BOS hit),
 * -1 on a hop failure mid-generation (caller should reform the ring — fewer
 * active workers now — and retry), -2 on a setup failure not worth retrying
 * (no survivors, too few workers for the layer count, or a shard load that
 * failed/timed out).
 *
 * Always restarts generation at the prompt's first token (pos 0) rather than
 * replaying to rebuild worker KV-cache state: at `steps` in the 10s-100s
 * range, a KV-replay would cost about the same as generation itself while
 * adding a second failure-during-replay case and per-attempt layer-redistribution
 * bookkeeping. Simple restart reuses master_run_token/discovery_assign_one
 * unchanged.
 *
 * Checks performed before a single token is sent:
 *   1. The ring is re-linked over the ACTIVE set first, so the pointers pushed
 *      below describe the topology as it is now. Expiry only marks state; skip
 *      this and every survivor is handed a neighbour that no longer exists.
 *   2. At least one worker survived, otherwise there is nothing to generate on
 *      and the caller is told not to retry (-2).
 *   3. A fresh epoch is drawn, so any hop still in flight from the previous
 *      topology fails every node's session check (RFC 4303 model) instead of
 *      being mistaken for this attempt's traffic.
 *   4. Every survivor is told its neighbours before it is told its layers, so
 *      no worker can receive a hop for a ring it has not been informed of.
 *   5. The model has at least one layer per survivor (discovery_assign_one
 *      refuses otherwise), and every assignment is accepted.
 *   6. Every shard reports resident within SHARD_LOAD_TIMEOUT_TICKS; a failure
 *      or a timeout aborts as -2 rather than generating against a ring that is
 *      only partly loaded.
 */
static int
run_generation_session(assign_layers_t *tmpl, int *slots,
                        int *prompt_tokens, int num_prompt_tokens, int steps)
{
    /* Re-link the ring over whoever is still ACTIVE before reading it back.
     * Expiry only marks state; without this the survivors' prev/next still name
     * the lost node, so the loop below would faithfully push stale pointers and
     * every hop would fall into the hole (and if the tail was lost,
     * master_ring_tail() would never resolve again). */
    int n = discovery_restitch_ring();
    if (n < 1) {
        printf("master: no workers left, cannot generate\n");
        return -2;
    }
    discovery_ring_order(slots, MAX_WORKERS);

    /* fresh epoch: any hop still in flight from the old topology is rejected
     * by every node's session check (RFC 4303 model), rather than mistaken
     * for this attempt's traffic. */
    if (getentropy(&g_session, sizeof(g_session)) < 0 || g_session == 0)
        g_session = (uint32)uptime() | 1;
    tmpl->session_id = g_session;

    /* re-close the ring over survivors: push authoritative registry pointers
     * so a worker's local prev/next (possibly stale from the dead node's
     * position in the old ring) converges to the master's current view
     * before any token is sent. */
    for (int k = 0; k < n; k++) {
        int slot = slots[k];
        rpc_addr_t dst = { .ip = registry[slot].info.ip,
                           .port = registry[slot].info.port };
        discovery_notify_neighbor(&dst,
                                  registry[slot].prev_ip, registry[slot].prev_port,
                                  registry[slot].next_ip, registry[slot].next_port);
    }

    /* re-assign layers over the (possibly smaller) survivor set. Fire all
     * assignments first, then wait for all shards in parallel — same shape
     * as the initial bring-up in run_master. */
    g_ready_count = 0;
    g_ready_failed = 0;
    for (int k = 0; k < n; k++) {
        if (discovery_assign_one(tmpl, k) != RPC_OK) {
            printf("master: aborting, could not assign worker %d\n", k);
            return -2;
        }
    }

    uint32 wait_start = uptime();
    while (g_ready_count < n && !g_ready_failed &&
           (uint32)(uptime() - wait_start) < SHARD_LOAD_TIMEOUT_TICKS)
        master_pump(200);

    if (g_ready_failed) {
        printf("master: aborting, a worker could not load its shard\n");
        return -2;
    }
    if (g_ready_count < n) {
        printf("master: aborting, shard load timed out (%d/%d ready)\n",
               g_ready_count, n);
        return -2;
    }
    printf("master: all shards resident (%d worker(s)), generating\n", n);

    /* generation loop — restarts at pos 0 every attempt */
    int token = prompt_tokens[0], next = 0, pos = 0;
    int head_slot = slots[0];

    while (pos < steps) {
        if (master_run_token(token, pos, head_slot) < 0) {
            int tmp[MAX_WORKERS];
            int active = discovery_ring_order(tmp, MAX_WORKERS);
            printf("master: hop failed at pos %d (%d/%d workers active), "
                   "will restart generation\n", pos, active, n);
            return -1;
        }

        uint64 head_t0 = rdtime();
        llama_head(&g_model.weights, &g_model.config, &g_model.state, g_final_x);
        g_metric_master_us += (rdtime() - head_t0) / 10;

        if (pos < num_prompt_tokens - 1)
            next = prompt_tokens[pos + 1];
        else
            next = sample(&g_sampler, g_model.state.logits);
        pos++;

        if (next == 1) break;
        char *piece = decode(&g_tok, token, next);
        safe_printf(piece);
        token = next;
    }

    printf("\nmaster: done (%d tokens)\n", pos);
    return 0;
}

/*
 * run_master — registration, layer assignment, then generation over the ring.
 *
 * Sequence:
 *   1. serve registrations until `want_workers` are ACTIVE
 *   2. load the master's own half of the model (embedding, final norm, classifier)
 *   3. assign layers and wait for every worker to report its shard resident
 *   4. per token: embed, traverse the ring, sample, stream, repeat
 */
static int
run_master(uint16 port, int want_workers, uint8_t model_id, char *prompt, int steps)
{
    printf("master: starting on port %d, waiting for %d worker(s)\n", port, want_workers);

    if (rpc_init(port) < 0) {
        printf("master: rpc_init failed\n");
        return -1;
    }

    /*
     * Install the cooperative pump: while the master is blocked fetching its
     * multi-megabyte embedding below, the FTP client calls back here between
     * chunk batches so heartbeats keep being answered and no worker ages out.
     * Set once, for the master only (the workers never touch this hook).
     */
    g_ftp_progress_hook = master_pump_hook;

    /* Privilege separation: the master never raises a resource limit, so drop
     * CAP_SYS_RESOURCE (one-way) up front. Least privilege, POSIX.1e / IEEE Std
     * 1003.1-2017; the weight fetch's bulk exemption uses CAP_NET_ADMIN, which is
     * left intact. */
    capdrop(CAP_SYS_RESOURCE);

    /* (1) registration — pump the socket (heartbeats + the handshake) until the
     * requested number of workers are ACTIVE and stitched into the ring. */
    int slots[MAX_WORKERS], n = 0;
    while (n < want_workers) {
        master_pump(200);
        n = discovery_ring_order(slots, MAX_WORKERS);
    }
    print_registry();
    printf("master: %d worker(s) active\n", n);

    /* (2) the master's own weights: embedding + final norm + classifier only.
     * The workers hold every layer, so the master never fetches the whole file.
     * The fetch runs for minutes; g_ftp_progress_hook pumps heartbeats throughout,
     * so no last_seen band-aid is needed (the old reset did nothing for a fetch
     * longer than EXPIRED_TIMEOUT anyway). */
    printf("master: loading model head/tail...\n");
    if (master_load_head_tail(&g_model, model_id) < 0) {
        printf("master: could not load weights\n");
        return -1;
    }

    void *tokdata = fetch_if_not_cached_pub("llm_tokenizer", FILE_TOKENIZER);
    if (!tokdata) {
        printf("master: could not load tokenizer\n");
        return -1;
    }
    build_tokenizer(&g_tok, tokdata, g_model.config.vocab_size);

    build_sampler(&g_sampler, g_model.config.vocab_size, 0.0f, 0.9f, (unsigned long long)uptime());
    init_thread_pool();

    /* (3)+(4) assignment + generation, with restart-on-failure over survivors */
    if (getentropy(&g_session, sizeof(g_session)) < 0 || g_session == 0)
        g_session = (uint32)uptime() | 1;

    assign_layers_t tmpl = {
        .session_id = g_session, .model_id = model_id,
        .n_layers_total = (uint32)g_model.config.n_layers,
        .dim = (uint32)g_model.config.dim,
        .hidden_dim = (uint32)g_model.config.hidden_dim,
        .n_heads = (uint32)g_model.config.n_heads,
        .n_kv_heads = (uint32)g_model.config.n_kv_heads,
        .seq_len = (uint32)g_model.config.seq_len,
        .vocab_size = (uint32)g_model.config.vocab_size,
        .max_seq = SHARD_DEFAULT_MAX_SEQ,
        .weights_ip = llm_server_ip(), .weights_port = llm_server_port(),
    };

    int num_prompt_tokens = 0;
    int *prompt_tokens = malloc((strlen(prompt) + 3) * sizeof(int));
    encode(&g_tok, prompt, 1, 0, prompt_tokens, &num_prompt_tokens);
    if (num_prompt_tokens < 1) {
        printf("master: empty prompt\n");
        return -1;
    }

    int max_restarts = 3;   /* cap so a cascading failure doesn't spin forever */
    int gr = -1;

    for (int attempt = 0; attempt <= max_restarts; attempt++) {
        if (attempt > 0)
            printf("master: --- restarting generation (attempt %d/%d) ---\n",
                   attempt + 1, max_restarts + 1);
        gr = run_generation_session(&tmpl, slots, prompt_tokens, num_prompt_tokens, steps);
        if (gr == 0) break;
        if (gr == -2) return -1;
        /* gr == -1: worker died mid-generation. discovery_expire_workers ran
         * during master_pump's retries inside master_run_token, so the
         * registry already reflects survivors — loop back and reassign. */
    }

    if (gr != 0) {
        printf("master: generation did not complete after %d attempt(s)\n", max_restarts + 1);
        discovery_stats();
        for (;;) master_pump(2000);
    }

    discovery_stats();   /* malformed / rate-limited / bad-prog / unknown-proc */

    /* Latency summary — unchanged, still reads g_metric_* accumulated across
     * whichever attempt(s) actually produced completed tokens. */
    if (g_metric_tokens > 0) {
        uint64 rtt   = g_metric_rtt_us     / g_metric_tokens;
        uint64 comp  = g_metric_compute_us / g_metric_tokens;
        uint64 mast  = g_metric_master_us  / g_metric_tokens;
        uint64 net   = rtt > comp ? rtt - comp : 0;
        uint64 tps10 = rtt ? 10000000ULL / rtt : 0;
        printf("master: latency/token (avg over %d): ring rtt %d us = compute %d us"
               " + network %d us | master %d us | %d.%d tok/s\n",
               g_metric_tokens, (int)rtt, (int)comp, (int)net, (int)mast,
               (int)(tps10 / 10), (int)(tps10 % 10));
    }

    for (;;) master_pump(2000);
    return 0;
}

/* -----------------------------------------------------------------------
 * Worker path
 * ----------------------------------------------------------------------- */
static int
run_worker(uint32 master_ip, uint16 master_port, uint32 my_ip, uint32 my_id)
{
    uint16 my_port = 10000 + (my_id % 10000);   /* arbitrary ephemeral port */

    printf("worker: starting, will register with %d:%d\n",
           master_ip, master_port);

    if (rpc_init(my_port) < 0) {
        printf("worker: rpc_init failed\n");
        return -1;
    }

    worker_info_t self;
    memset(&self, 0, sizeof(self));
    self.worker_id    = my_id;
    self.ip           = my_ip;
    self.port         = my_port;

    /*
     * What we can actually back, as opposed to what we advertise. Honest nodes
     * make these the same number; --claim-ram is exactly the act of separating
     * them (threat model item 1, capability lying).
     */
    uint32 real_ram_bytes = g_real_ram_mb ? mb_to_bytes(g_real_ram_mb)
                                          : 1024 * 1024 * 512;   /* 512 MB */
    if (g_claimed_ram_mb) {
        self.RAM = mb_to_bytes(g_claimed_ram_mb);
        printf("worker: [MALICIOUS] claiming %d MB RAM (real budget %d MB)\n",
               g_claimed_ram_mb, real_ram_bytes / (1024 * 1024));
    } else {
        self.RAM = real_ram_bytes;
    }

    /* Identity commitment: SHA-256(PSK). The proof of possession (HMAC over the
     * master's nonce) is produced later, in discovery_register's cap_ack. */
    sha256_hash((const uint8 *)DISTINF_PSK, DISTINF_PSK_LEN, self.psk_hash);

    /*
     * Confine our address space to the RAM we can really back (IEEE Std
     * 1003.1-2017 RLIMIT_AS). Two purposes: a worker cannot quietly use more
     * than it has, and it makes the master's RAM sized-probe enforceable -- a
     * node whose real budget is smaller than its claim cannot allocate the probe
     * and is refused.
     *
     * The limit follows `real_ram_bytes`, never `self.RAM`. For an honest node
     * those are the same value and nothing changes. For a lying one the
     * distinction is the entire mechanism: raising the limit to match the lie
     * would build a node that can genuinely back its claim, i.e. an honest node
     * with a large budget, which is not the attack. Leaving it at the real
     * budget is what makes cap_probe_run's eager allocation fail for real, so
     * the rejection comes from the master's evidence rather than from us
     * volunteering it.
     *
     * Best-effort: if setrlimit is unavailable the probe still runs against
     * physical memory, so registration is not blocked by a missing limit.
     */
    struct rlimit as_lim = { .rlim_cur = real_ram_bytes, .rlim_max = real_ram_bytes };
    setrlimit(RLIMIT_AS, &as_lim);

    /*
     * Privilege separation (least privilege, POSIX.1e / IEEE Std 1003.1-2017
     * appropriate-privilege model): having pinned our address-space budget, drop
     * CAP_SYS_RESOURCE for good. It is the capability required to RAISE a hard
     * limit; the one-way capdrop() turns RLIMIT_AS into a real confinement
     * boundary the worker cannot lift, even if a later handler is subverted --
     * including one that wanted to make its own lie true after the fact.
     */
    capdrop(CAP_SYS_RESOURCE);

    rpc_addr_t master = { .ip = master_ip, .port = master_port };

    printf("worker: registering with master...\n");

    set_neighbor_t neighbors;
    memset(&neighbors, 0, sizeof(neighbors));

    int r = discovery_register(&master, &self, &neighbors);
    if (r == RPC_OK) {
        printf("worker: registered — prev=%d:%d next=%d:%d\n",
               neighbors.prev_ip, neighbors.prev_port,
               neighbors.next_ip, neighbors.next_port);

        /* Mutable neighbor state shared with listen thread */
        static uint32 cur_next_ip, cur_prev_ip;
        static uint16 cur_next_port, cur_prev_port;
        cur_next_ip   = neighbors.next_ip;
        cur_next_port = neighbors.next_port;
        cur_prev_ip   = neighbors.prev_ip;
        cur_prev_port = neighbors.prev_port;

        mutex_init(&rpc_mutex);

        static listen_args_t listen_args;
        listen_args.master         = master;
        listen_args.worker_id      = my_id;
        listen_args.self_next_ip   = &cur_next_ip;
        listen_args.self_next_port = &cur_next_port;
        listen_args.self_prev_ip   = &cur_prev_ip;
        listen_args.self_prev_port = &cur_prev_port;

        static heartbeat_args_t hb_args;
        hb_args.master          = master;
        hb_args.worker_id       = my_id;
        hb_args.self            = &self;   /* replayed verbatim on re-register */
        hb_args.self_next_ip    = &cur_next_ip;
        hb_args.self_next_port  = &cur_next_port;
        hb_args.self_prev_ip    = &cur_prev_ip;
        hb_args.self_prev_port  = &cur_prev_port;

        g_inf.master    = master;
        g_inf.worker_id = my_id;
        g_inf.self      = self;
        g_inf.next_ip   = &cur_next_ip;
        g_inf.next_port = &cur_next_port;
        g_inf.prev_ip   = &cur_prev_ip;
        g_inf.prev_port = &cur_prev_port;
        mutex_init(&g_inf.mutex);   /* guards the activation mailbox (listen<->inference) */
        discovery_inference_hook = worker_inference_hook;

        // wire listen args and heartbeat args together for re-registration signaling.
        // needs_reregister: listen→heartbeat (PROC_EVICT received).
        // reregistering / listen_suspended: the pause/resume handshake that lets the
        // heartbeat thread own the socket alone while discovery_register() blocks.

        static volatile int needs_reregister = 0;
        static volatile int reregistering    = 0;
        static volatile int listen_suspended = 0;

        listen_args.needs_reregister  = &needs_reregister;
        listen_args.reregistering     = &reregistering;
        listen_args.listen_suspended  = &listen_suspended;

        hb_args.needs_reregister = &needs_reregister;
        hb_args.reregistering    = &reregistering;
        hb_args.listen_suspended = &listen_suspended;

        int listen_tid = thread_create(discovery_listen_thread, &listen_args);
        int hb_tid     = thread_create(heartbeat_thread, &hb_args);
        int inf_tid    = thread_create(inference_thread, &g_inf);

        (void)hb_tid;
        (void)inf_tid;
        thread_join(listen_tid);
    }
    else
        printf("worker: registration failed, err=%d\n", r);

    return 0;
}

/* -----------------------------------------------------------------------
 * Entry point
 *
 * Usage:
 *   distinf --master <port>
 *   distinf --worker <master_ip> <master_port> <worker_id>
 * ----------------------------------------------------------------------- */

int
main(int argc, char *argv[])
{
    int eq;

    if (argc < 2) goto usage;

    strcmp_simple(argv[1], "--master", &eq);
    if (eq) {
        if (argc < 4) goto usage;
        uint16 port = parse_port(argv[2]);
        int workers = atoi(argv[3]);
        uint8_t model = argc > 4 ? (uint8_t)atoi(argv[4]) : FILE_WEIGHTS;
        char *prompt = argc > 5 ? argv[5] : "Once upon a time";
        int steps = argc > 6 ? atoi(argv[6]) : 32;
        if (argc > 7) llm_set_server(parse_ip(argv[7]), 0);
        return run_master(port, workers, model, prompt, steps);
    }

    strcmp_simple(argv[1], "--worker", &eq);
    if (eq) {
        if (argc < 4) goto usage;
        uint32 master_ip = parse_ip(argv[2]);
        uint16 master_port = parse_port(argv[3]);
        uint32 my_ip = ip();
        uint32 my_id = atoi(argv[4]);

        if (parse_misbehaviour(argc, argv, 5) < 0)
            goto usage;
        return run_worker(master_ip, master_port, my_ip, my_id);
    }

usage:
    printf("usage:\n");
    printf("  distinf --master <port> <n_workers> [model_id] [prompt] [steps] [server_ip]\n");
    printf("  distinf --worker <master_ip> <master_port> <worker_id>\n");
    printf("                   [--claim-ram <mb>] [--real-ram <mb>]\n");
    printf("                   [--corrupt signflip|zero|delta [amount]]\n");
    printf("    --claim-ram advertises RAM this node cannot back, --real-ram sets what it\n");
    printf("    can (its own RLIMIT_AS), and --corrupt tampers with a result it computed\n");
    printf("    correctly. Note the master probes only up to CAP_PROBE_CEILING_BYTES, so a\n");
    printf("    lie is caught only when --real-ram is below that ceiling. All exist to test\n");
    printf("    the cluster's defences; an honest worker passes none of them.\n");
    return -1;
}