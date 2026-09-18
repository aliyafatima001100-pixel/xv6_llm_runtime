#include "discovery.h"
#include "rpc.h"
#include "kernel/types.h"
#include "user/user.h"
#include "user/sha256.h"

/*
 * hmac_sha256 — RFC 2104 / FIPS 198-1 keyed MAC over user/sha256.c.
 *
 * HMAC(K,m) = H((K' ^ opad) || H((K' ^ ipad) || m)), K' the key zero-padded to
 * the 64-byte block (hashed first if longer). Used to prove PSK possession at
 * registration (cap_ack_t.identity = HMAC(PSK, nonce)); see discovery.h.
 */
static void
hmac_sha256(const uint8 *key, int keylen,
            const uint8 *msg, int msglen, uint8 out[32])
{
    uint8 k[64], pad[64], inner[32];
    SHA256_CTX c;

    memset(k, 0, sizeof(k));
    if (keylen > 64)
        sha256_hash(key, keylen, k);          /* k[0..31] = H(key), rest zero */
    else
        memmove(k, key, keylen);

    for (int i = 0; i < 64; i++) pad[i] = k[i] ^ 0x36;   /* ipad */
    sha256_init(&c);
    sha256_update(&c, pad, 64);
    sha256_update(&c, msg, msglen);
    sha256_final(&c, inner);

    for (int i = 0; i < 64; i++) pad[i] = k[i] ^ 0x5c;   /* opad */
    sha256_init(&c);
    sha256_update(&c, pad, 64);
    sha256_update(&c, inner, 32);
    sha256_final(&c, out);
}

/* HMAC(PSK, nonce) as 4 little-endian nonce bytes — the identity proof both the
 * worker and the master compute over the master's fresh registration nonce. */
static void
cap_identity(uint32 nonce, uint8 out[32])
{
    uint8 m[4] = { (uint8)nonce, (uint8)(nonce >> 8),
                   (uint8)(nonce >> 16), (uint8)(nonce >> 24) };
    hmac_sha256((const uint8 *)DISTINF_PSK, DISTINF_PSK_LEN, m, 4, out);
}

/* -----------------------------------------------------------------------
 * Master-side registry
 * ----------------------------------------------------------------------- */
worker_entry_t registry[MAX_WORKERS];

/*
 * Installed by distinf.c so the listen thread can hand PROC_ASSIGN_LAYERS and
 * PROC_INFER_REQ to the inference thread without discovery.c having to know
 * anything about shards or activations.
 */
void (*discovery_inference_hook)(const rpc_msg_t *msg, const rpc_addr_t *src) = 0;

/* -----------------------------------------------------------------------
 * Application-layer RPC admission control (RFC 1812 §4.3.2.8) + observability
 *
 * The kernel already meters datagrams per source IP at L2 (net.c udp_rl), but
 * that is protocol-blind and per-IP. This is a per-RPC-peer (ip:port) token
 * bucket sized for the control plane's low, steady call rate, so one peer
 * flooding CALLs is throttled without starving the ring or the other peers.
 * Same shape as the L2 bucket: BURST tokens, one refilled per REFILL_TICKS, and
 * when every slot is taken the fullest (least active) bucket is evicted.
 *
 * The per-reason drop counters make malformed / abusive traffic observable
 * (mirrors the hop counters); discovery_stats() prints them.
 * ----------------------------------------------------------------------- */
#define DISCOVERY_RL_SLOTS         8
#define DISCOVERY_RL_BURST         32   /* headroom for a registration burst   */
#define DISCOVERY_RL_REFILL_TICKS  1    /* ~10 calls/s sustained per peer       */

struct disc_bucket { uint32 ip; uint16 port; int tokens; uint32 last; int used; };
static struct disc_bucket disc_rl[DISCOVERY_RL_SLOTS];

static struct {
    uint32 malformed;    /* short / ill-shaped payload rejected by a handler   */
    uint32 rate;         /* dropped by the per-peer token bucket               */
    uint32 badprog;      /* wrong program / version                            */
    uint32 unknownproc;  /* call for an unexported procedure                   */
} disc_drops;

/*
 * disc_rl_allow — spend a token for (ip:port), refilling first. Returns 1 to
 * admit the call, 0 to drop it.
 *
 * Checks performed:
 *   1. locate this peer's bucket, or claim a slot (evicting the fullest, i.e.
 *      least active, when all are in use — bounded state, no unbounded table);
 *   2. refill one token per REFILL_TICKS elapsed, capped at BURST;
 *   3. admit iff a token is available, and spend it.
 */
static int
disc_rl_allow(uint32 ip, uint16 port, uint32 now)
{
    struct disc_bucket *b = 0, *lru = &disc_rl[0];
    for (int i = 0; i < DISCOVERY_RL_SLOTS; i++) {
        if (disc_rl[i].used && disc_rl[i].ip == ip && disc_rl[i].port == port) {
            b = &disc_rl[i];
            break;
        }
        if (!disc_rl[i].used || disc_rl[i].tokens > lru->tokens)
            lru = &disc_rl[i];
    }
    if (!b) {
        b = lru;
        b->ip = ip; b->port = port; b->used = 1;
        b->tokens = DISCOVERY_RL_BURST; b->last = now;
    }
    uint32 add = (now - b->last) / DISCOVERY_RL_REFILL_TICKS;
    if (add) {
        b->tokens += (int)add;
        if (b->tokens > DISCOVERY_RL_BURST) b->tokens = DISCOVERY_RL_BURST;
        b->last = now;
    }
    if (b->tokens <= 0)
        return 0;
    b->tokens--;
    return 1;
}

/* Print the drop counters (malformed / rate-limited / bad program / unknown
 * proc). Called by the master at shutdown/idle so abusive traffic is visible. */
void
discovery_stats(void)
{
    printf("master: rpc drops -- malformed %d, rate-limited %d, bad-prog %d, unknown-proc %d\n",
           disc_drops.malformed, disc_drops.rate, disc_drops.badprog, disc_drops.unknownproc);
}

/* -----------------------------------------------------------------------
 * Internal helpers
 * ----------------------------------------------------------------------- */

/* Shared with distinf.c; the implementation lives in rpc.c (RFC 5531 §9). */
static void
fill_call(rpc_msg_t *msg, uint32 proc)
{
    rpc_fill_call(msg, proc);
}

static int
registry_find(uint32 worker_id)
{
    for (int i = 0; i < MAX_WORKERS; i++)
        if (registry[i].info.worker_id == worker_id)
            return i;
    return -1;
}

static uint32
registry_find_ip_port(uint32 worker_ip, uint16 worker_port) {
    for (int i = 0; i < MAX_WORKERS; i++)
        if (registry[i].info.ip == worker_ip && registry[i].info.port == worker_port)
            return i;
    return -1;
}

static int
registry_free_slot(void)
{
    for (int i = 0; i < MAX_WORKERS; i++)
        if (registry[i].state == WORKER_EXPIRED ||
            registry[i].info.worker_id == 0)
            return i;
    return -1;
}

/*
 * create_probe_data — the nonce a worker must echo back to complete registration.
 *
 * This was a monotonic counter, which made the "authenticated" handshake
 * authenticate nothing: any party that had ever registered could predict the
 * next nonce and answer a probe it never received. RFC 4086 §3 is explicit that
 * a nonce used for security must come from an unpredictable source, so it is
 * drawn from getentropy() (IEEE Std 1003.1-2024), the same entropy pool the
 * stack canaries and stack ASLR use.
 *
 * Checks performed:
 *   1. getentropy() must succeed; on failure the caller is told (0) rather than
 *      being handed a guessable value, so registration fails closed.
 *   2. A zero draw is retried once, since 0 is used as "no nonce" by the
 *      registry's zero-initialised slots.
 */
uint32
create_probe_data(uint32 capabilities)
{
    uint32 nonce = 0;

    for (int attempt = 0; attempt < 2; attempt++) {
        if (getentropy(&nonce, sizeof(nonce)) < 0)
            return 0;
        if (nonce != 0)
            return nonce;
    }

    return 0;
}

/*
 * cap_probe_checksum — the value a correct RAM sized-probe returns.
 *
 * One LCG word (the glibc constants) per page, summed with 32-bit wrap. It
 * depends only on seed and page count, so the master and the host gate recompute
 * it without a buffer; the worker (cap_probe_run) computes the identical sum
 * while writing each word into the page it allocates. See discovery.h.
 */
#define CAP_PROBE_PGSIZE 4096
static uint32
cap_probe_checksum(uint32 seed, uint32 pages)
{
    uint32 x = seed, sum = 0;
    for (uint32 i = 0; i < pages; i++) {
        x = x * 1103515245u + 12345u;
        sum += x;
    }
    return sum;
}

/*
 * cap_probe_run — worker side: back the RAM claim for real, then checksum it.
 *
 * Checks performed:
 *   1. pages is within the ceiling, so a malformed reply cannot make us attempt
 *      an absurd allocation.
 *   2. malloc succeeds -- and malloc is eager (SBRK_EAGER -> uvmalloc kallocs
 *      every page), so a node that cannot back the claim, whether by physical
 *      exhaustion or its own RLIMIT_AS, fails here and we return -1.
 *   3. every page is written, so the allocation is genuinely resident, not a
 *      lazy/overcommitted reservation.
 * Returns the checksum (>= 0) on success, -1 if the claim cannot be backed.
 */
static long
cap_probe_run(uint32 seed, uint32 pages)
{
    if (pages == 0 || pages > CAP_PROBE_CEILING_BYTES / CAP_PROBE_PGSIZE)
        return -1;
    uint32 *buf = malloc((uint64)pages * CAP_PROBE_PGSIZE);
    if (!buf)
        return -1;
    uint32 x = seed, sum = 0;
    for (uint32 i = 0; i < pages; i++) {
        x = x * 1103515245u + 12345u;
        buf[i * (CAP_PROBE_PGSIZE / sizeof(uint32))] = x;   /* touch the page */
        sum += x;
    }
    free(buf);
    return (long)sum;
}

/* Returns slot index of the most recently activated worker before `current_slot`,
 * or -1 if none exists (i.e. this is the first active worker). */
static int
find_prev_active_worker(int current_slot)
{
    /* Walk backwards from current_slot - 1, wrapping around */
    for (int offset = 1; offset < MAX_WORKERS; offset++) {
        int i = (current_slot - offset + MAX_WORKERS) % MAX_WORKERS;
        if (registry[i].info.worker_id != 0 &&
            registry[i].state == WORKER_ACTIVE)
            return i;
    }
    return -1;
}

/* -----------------------------------------------------------------------
 * Worker side
 * ----------------------------------------------------------------------- */
int
discovery_cap_test(const rpc_addr_t *master, uint32 worker_id, cap_ack_t *cap_ack, rpc_msg_t *out_reply)
{
    static rpc_msg_t req;
    memset(&req, 0, sizeof(req));

    fill_call(&req, PROC_CAP_ACK);
    memcpy(req.payload, cap_ack, sizeof(cap_ack_t));
    req.payload_len = sizeof(cap_ack_t);

    return rpc_call(master, &req, out_reply);
}
int
discovery_register(const rpc_addr_t *master, worker_info_t *self, set_neighbor_t *out_neighbors)
{
    static rpc_msg_t req, reply;
    memset(&req, 0, sizeof(req));

    fill_call(&req, PROC_AUTH_HELLO);
    memcpy(req.payload, self, sizeof(worker_info_t));
    req.payload_len = sizeof(worker_info_t);

    int ret = rpc_call(master, &req, &reply);

    if (ret != RPC_OK) {
        printf("discovery_register: rpc_call failed, err=%d\n", ret);
        return ret;
    }

    if (reply.reply_stat != MSG_ACCEPTED) {
        printf("discovery_register: master rejected, stat=%d\n", reply.reply_stat);
        return -1;
    }

    if (reply.accepted.stat != SUCCESS) {
        printf("discovery_register: master accepted but failed, stat=%d\n", reply.accepted.stat);
        return -1;
    }

    if (reply.payload_len < sizeof(auth_hello_reply_t)) {
        printf("discovery_register: short reply\n");
        return -1;
    }

    auth_hello_reply_t *rep = (auth_hello_reply_t *)reply.payload;
    if (rep->status != WORKER_PENDING) {
        printf("discovery_register: unexpected status %d\n", rep->status);
        return -1;
    }

    /* Answer the RAM sized-probe: actually allocate the pages the master asked
     * for (proving we can back our advertised RAM) and checksum the seeded
     * pattern. If we cannot allocate them, we must not join -- abort registration
     * rather than send a value we did not earn. */
    long chk = cap_probe_run(rep->probe_seed, rep->probe_pages);
    if (chk < 0) {
        printf("discovery_register: cannot back RAM claim (%d pages), aborting\n",
               rep->probe_pages);
        return -1;
    }
    cap_ack_t ack = (cap_ack_t){ .probe_nonce = rep->probe_data, .checksum = (uint32)chk };
    cap_identity(rep->probe_data, ack.identity);   /* prove PSK possession */
    ret = discovery_cap_test(master, self->worker_id, &ack, &reply);
    if (ret != RPC_OK) {
        printf("discovery_register: failed to send cap test, err=%d\n", ret);
        return ret;
    }

    if (reply.reply_stat != MSG_ACCEPTED) {
        printf("discovery_register: master rejected rpc call, stat=%d\n", reply.reply_stat);
        return -1;
    }

    if (reply.accepted.stat != SUCCESS) {
        printf("discovery_register: cap test failed, stat=%d\n", reply.accepted.stat);
        return -1;
    }

    printf("discovery_register: registration successful\n");

    if (out_neighbors && reply.payload_len >= sizeof(set_neighbor_t))
        memcpy(out_neighbors, reply.payload, sizeof(set_neighbor_t));

    return ret;
}
int
discovery_heartbeat(const rpc_addr_t *master, uint32 worker_id)
{
    static rpc_msg_t req;
    memset(&req, 0, sizeof(req));

    fill_call(&req, PROC_HEARTBEAT);
    memcpy(req.payload, &worker_id, sizeof(uint32));
    req.payload_len = sizeof(uint32);

    return rpc_send_call(master, &req);  // fire and forget
}
void
discovery_listen_thread(void *arg)
{
    listen_args_t *a = (listen_args_t *)arg;
    rpc_msg_t msg;
    rpc_addr_t src;

    printf("worker: listen thread started\n");

    for (;;) {
        /*
         * Single-recv-owner coordination. This thread is the sole caller of
         * rpc_recv on the worker socket (README: "listen thread owns all
         * incoming traffic"). If the heartbeat thread ran a blocking rpc_call
         * (re-registration) at the same time, either thread could grab the
         * other's datagram — the master's AUTH_HELLO reply is a MSG_REPLY,
         * which we discard below, so a lost reply would stall the handshake.
         * While the heartbeat thread re-registers, park here so it owns the
         * socket alone, then resume.
         */
        if (*a->reregistering) {
            *a->listen_suspended = 1;
            while (*a->reregistering)
                yield();
            *a->listen_suspended = 0;
            continue;
        }

        int r = rpc_recv(&msg, &src, 5000 /* block forever */);
        if (r < 0) {
            continue;
        }

        if (msg.mtype != MSG_CALL) continue;

        switch ((rpc_proc_t)msg.call.proc) {
        case PROC_SET_NEIGHBOR: {
            if (msg.payload_len < sizeof(set_neighbor_t)) {
                rpc_send_reply(&src, msg.xid, GARBAGE_ARGS, 0, 0);
                break;
            }
            set_neighbor_t *nb = (set_neighbor_t *)msg.payload;
            *a->self_prev_ip   = nb->prev_ip;
            *a->self_prev_port = nb->prev_port;
            *a->self_next_ip   = nb->next_ip;
            *a->self_next_port = nb->next_port;
            printf("worker: neighbor updated — prev=%d:%d next=%d:%d\n",
                   nb->prev_ip, nb->prev_port,
                   nb->next_ip, nb->next_port);
            rpc_send_reply(&src, msg.xid, SUCCESS, 0, 0);
            break;
        }
        case PROC_EVICT:
            printf("worker: evicted by master, will re-register\n");
            *a->needs_reregister = 1;
            rpc_send_reply(&src, msg.xid, SUCCESS, 0, 0);
            break;

        case PROC_ASSIGN_LAYERS:
        case PROC_INFER_REQ:
            /*
             * Inference work is handed to the inference thread rather than done
             * here: this thread is the sole owner of rpc_recv, and a multi-minute
             * weight fetch or a full layer computation performed inline would
             * stall every other message, including the master's eviction notice.
             * discovery_inference_hook is installed by distinf.c; a build without
             * it (or a message arriving before the worker is wired up) answers
             * SYSTEM_ERR rather than pretending the work was accepted.
             */
            if (discovery_inference_hook) {
                discovery_inference_hook(&msg, &src);
            } else {
                rpc_send_reply(&src, msg.xid, SYSTEM_ERR, 0, 0);
            }
            break;
        default:
            rpc_send_reply(&src, msg.xid, PROC_UNAVAIL, 0, 0);
            break;
        }
    }
}

/* -----------------------------------------------------------------------
 * Master side — handlers
 * ----------------------------------------------------------------------- */

static int
handle_auth_hello(const rpc_msg_t *msg, const rpc_addr_t *src, uint32 now_ms)
{
    if (msg->payload_len < sizeof(worker_info_t)) {
        disc_drops.malformed++;
        return rpc_send_reply(src, msg->xid, GARBAGE_ARGS, 0, 0);
    }

    worker_info_t *info = (worker_info_t *)msg->payload;

    /* Identity commitment: the worker must present SHA-256(PSK). The proof of
     * possession (HMAC over our nonce) comes in the CAP_ACK; this early check
     * rejects a peer that does not even know the PSK before we allocate a slot
     * or draw entropy for it. */
    uint8 expect_hash[32];
    sha256_hash((const uint8 *)DISTINF_PSK, DISTINF_PSK_LEN, expect_hash);
    if (memcmp(info->psk_hash, expect_hash, 32) != 0) {
        printf("master: AUTH_HELLO from %d with wrong PSK commitment, refusing\n",
               info->worker_id);
        return rpc_send_reply(src, msg->xid, GARBAGE_ARGS, 0, 0);
    }

    int existing = registry_find(info->worker_id);

    if (existing >= 0 && registry[existing].state != WORKER_EXPIRED) {
        /* duplicate — re-send the same probe (nonce + RAM challenge) so a
         * retransmitted AUTH_HELLO is idempotent and answered identically. */
        auth_hello_reply_t rep = {0};
        rep.status      = WORKER_PENDING;
        rep.probe_data  = registry[existing].cap_ack_expected.probe_nonce;
        rep.probe_seed  = registry[existing].probe_seed;
        rep.probe_pages = registry[existing].probe_pages;
        return rpc_send_reply(src, msg->xid, SUCCESS, (const uint8 *)&rep, sizeof(rep));
    }

    int slot;
    if (existing >= 0) {
        /* expired — reuse the same slot */
        slot = existing;
    } else {
        /* brand new worker — find a free slot */
        slot = registry_free_slot();
        if (slot < 0)
            return rpc_send_reply(src, msg->xid, SYSTEM_ERR, 0, 0);
    }

    registry[slot].info          = *info;
    registry[slot].last_seen_ms  = now_ms;
    registry[slot].state         = WORKER_PENDING;
    
    auth_hello_reply_t rep = {0};
    rep.status      = WORKER_PENDING;
    uint32 nonce = create_probe_data(info->RAM);
    uint32 seed  = create_probe_data(0);   /* independent draw for the RAM probe */
    if (nonce == 0 || seed == 0) {
        /* No entropy, no probe: fail the registration rather than issue a
         * predictable nonce (RFC 4086 §3). The slot stays PENDING and ages out. */
        printf("master: cannot draw probe entropy, refusing registration\n");
        return rpc_send_reply(src, msg->xid, SYSTEM_ERR, 0, 0);
    }

    /* RAM sized-probe: challenge the worker to allocate (a bounded slice of) the
     * RAM it advertised and checksum a seeded pattern over it. pages is the claim
     * capped at CAP_PROBE_CEILING_BYTES; a claim below one page still gets one. */
    uint32 probe_bytes = info->RAM < CAP_PROBE_CEILING_BYTES ? info->RAM
                                                             : CAP_PROBE_CEILING_BYTES;
    uint32 pages = probe_bytes / CAP_PROBE_PGSIZE;
    if (pages == 0)
        pages = 1;

    rep.probe_data  = nonce;
    rep.probe_seed  = seed;
    rep.probe_pages = pages;
    registry[slot].probe_seed  = seed;
    registry[slot].probe_pages = pages;
    registry[slot].cap_ack_expected =
        (cap_ack_t){ .probe_nonce = nonce, .checksum = cap_probe_checksum(seed, pages) };

    return rpc_send_reply(src, msg->xid, SUCCESS, (const uint8 *)&rep, sizeof(rep));
}

static int
handle_cap_ack(const rpc_msg_t *msg, const rpc_addr_t *src, uint32 now_ms)
{
    if (msg->payload_len < sizeof(cap_ack_t)) {
        disc_drops.malformed++;
        return rpc_send_reply(src, msg->xid, GARBAGE_ARGS, 0, 0);
    }

    int slot = registry_find_ip_port(src->ip, src->port);
    if (slot < 0)
        return rpc_send_reply(src, msg->xid, SYSTEM_ERR, 0, 0);
    if (registry[slot].state != WORKER_PENDING)
        return rpc_send_reply(src, msg->xid, SYSTEM_ERR, 0, 0);

    cap_ack_t *ack = (cap_ack_t *)msg->payload;

    /* Liveness: the nonce proves the worker saw our AUTH_HELLO reply. */
    if (ack->probe_nonce != registry[slot].cap_ack_expected.probe_nonce)
        return rpc_send_reply(src, msg->xid, GARBAGE_ARGS, 0, 0);

    /* RAM sized-probe: the checksum proves the worker allocated and wrote the
     * pages we challenged it with; a node that could not back its RAM claim
     * (physical exhaustion or RLIMIT_AS) never produced this value. A mismatch
     * fails the registration -- the slot stays PENDING and ages out. */
    if (ack->checksum != registry[slot].cap_ack_expected.checksum) {
        printf("master: worker %d failed the RAM probe (claimed %d MB, %d pages), refusing\n",
               registry[slot].info.worker_id, registry[slot].info.RAM / (1024 * 1024),
               registry[slot].probe_pages);
        return rpc_send_reply(src, msg->xid, GARBAGE_ARGS, 0, 0);
    }

    /* Identity: only a PSK holder can MAC the master's fresh nonce (RFC 2104).
     * A peer that guessed/replayed the nonce but lacks the key fails here. */
    uint8 expect_id[32];
    cap_identity(registry[slot].cap_ack_expected.probe_nonce, expect_id);
    if (memcmp(ack->identity, expect_id, 32) != 0) {
        printf("master: worker %d failed PSK identity (HMAC mismatch), refusing\n",
               registry[slot].info.worker_id);
        return rpc_send_reply(src, msg->xid, GARBAGE_ARGS, 0, 0);
    }

    registry[slot].last_seen_ms = now_ms;
    registry[slot].state = WORKER_ACTIVE;

    uint32 new_ip   = registry[slot].info.ip;
    uint16 new_port = registry[slot].info.port;

    int prev_slot = find_prev_active_worker(slot);

    uint32 prev_ip, next_ip;
    uint16 prev_port, next_port;

    if (prev_slot < 0) {
        /*
         * First active worker — the ring points back at the master on both sides.
         * The sentinel must be the port the master is actually listening on
         * (rpc_local_port(), set by rpc_init from argv), not a fixed number: it
         * was hardcoded to 499 while both the README and the L3 gate start the
         * master on 5499, so the worker's `next` pointed at a dead port and the
         * ring could never close back to the master.
         */
        prev_ip   = ip(); prev_port = rpc_local_port();
        next_ip   = ip(); next_port = rpc_local_port();
    } else {
        uint32 old_next_ip   = registry[prev_slot].next_ip;
        uint16 old_next_port = registry[prev_slot].next_port;  /* was master (0) */

        /* New worker's prev = old tail, new worker's next = old tail's next (master or further) */
        prev_ip   = registry[prev_slot].info.ip;
        prev_port = registry[prev_slot].info.port;
        next_ip   = old_next_ip;
        next_port = old_next_port;

        /* Update old tail's next to point at new worker */
        registry[prev_slot].next_ip   = new_ip;
        registry[prev_slot].next_port = new_port;

        /* Notify old tail of its new next neighbor */
        rpc_addr_t prev_addr = { .ip = prev_ip, .port = prev_port };
        int r = discovery_notify_neighbor(&prev_addr,
                                          registry[prev_slot].prev_ip,
                                          registry[prev_slot].prev_port,
                                          new_ip, new_port);
        if (r != RPC_OK)
            printf("master: warning: failed to notify prev worker of new neighbor\n");
    }

    /* Store new worker's ring pointers in registry */
    registry[slot].prev_ip   = prev_ip;
    registry[slot].prev_port = prev_port;
    registry[slot].next_ip   = next_ip;
    registry[slot].next_port = next_port;

    /* Send ring info to new worker in the cap_ack reply */
    set_neighbor_t ring_reply = {
        .prev_ip   = prev_ip,
        .prev_port = prev_port,
        .next_ip   = next_ip,
        .next_port = next_port,
    };
    return rpc_send_reply(src, msg->xid, SUCCESS,
                          (const uint8 *)&ring_reply, sizeof(ring_reply));
}

static int
handle_heartbeat(const rpc_msg_t *msg, const rpc_addr_t *src, uint32 now_ms)
{
    if (msg->payload_len < sizeof(uint32)) {
        disc_drops.malformed++;
        return rpc_send_reply(src, msg->xid, GARBAGE_ARGS, 0, 0);
    }

    uint32 worker_id;
    memcpy(&worker_id, msg->payload, sizeof(uint32));

    int slot = registry_find(worker_id);
    if (slot < 0)
        return rpc_send_reply(src, msg->xid, SYSTEM_ERR, 0, 0);

    registry[slot].last_seen_ms = now_ms;

    if (registry[slot].state == WORKER_SUSPECTED) {
        registry[slot].state = WORKER_ACTIVE;   // revive from suspected
        printf("master: worker %d revived from suspected\n", worker_id);
    }
    else if (registry[slot].state == WORKER_EXPIRED) {
        printf("master: worker %d is expired\n", worker_id);
        return rpc_send_reply(src, msg->xid, SYSTEM_ERR, 0, 0);
    }

    return rpc_send_reply(src, msg->xid, SUCCESS, 0, 0);
}

int
discovery_notify_neighbor(const rpc_addr_t *dst,
                          uint32 prev_ip, uint16 prev_port,
                          uint32 next_ip, uint16 next_port)
{
    static rpc_msg_t req, reply;
    memset(&req, 0, sizeof(req));

    fill_call(&req, PROC_SET_NEIGHBOR);

    set_neighbor_t payload = {
        .prev_ip   = prev_ip,
        .prev_port = prev_port,
        .next_ip   = next_ip,
        .next_port = next_port,
    };
    memcpy(req.payload, &payload, sizeof(set_neighbor_t));
    req.payload_len = sizeof(set_neighbor_t);

    return rpc_call(dst, &req, &reply);
}

/* -----------------------------------------------------------------------
 * Master side — dispatch
 * ----------------------------------------------------------------------- */

int
discovery_handle_call(const rpc_msg_t *msg, const rpc_addr_t *src, uint32 now_ms)
{
    if (msg->mtype != MSG_CALL)
        return -1;

    /* Admission control: throttle a peer flooding CALLs. A denied call is
     * dropped silently (no reply), matching the RFC 1812 §4.3.2.8 model -- an
     * error reply would itself be amplifiable traffic. */
    if (!disc_rl_allow(src->ip, src->port, now_ms)) {
        disc_drops.rate++;
        return -1;
    }

    if (msg->call.prog != INFERENCE_PROG ||
        msg->call.vers != INFERENCE_VERS) {
        disc_drops.badprog++;
        return rpc_send_reply(src, msg->xid, PROG_UNAVAIL, 0, 0);
    }

    switch ((rpc_proc_t)msg->call.proc) {
    case PROC_AUTH_HELLO:
        return handle_auth_hello(msg, src, now_ms);
    case PROC_HEARTBEAT:
        return handle_heartbeat(msg, src, now_ms);
    case PROC_CAP_ACK:
        return handle_cap_ack(msg, src, now_ms);
    case PROC_SET_NEIGHBOR:
        disc_drops.unknownproc++;
        return rpc_send_reply(src, msg->xid, PROC_UNAVAIL, 0, 0);
    default:
        disc_drops.unknownproc++;
        return rpc_send_reply(src, msg->xid, PROC_UNAVAIL, 0, 0);
    }
}

/*
 * master_send_evict — tell an expired worker it must re-register.
 * Fire-and-forget (rpc_send_call, not rpc_call): a genuinely-dead worker
 * would otherwise block the master's recv loop for the full retransmit
 * budget. The worker's listen thread replies SUCCESS, which we ignore.
 */
static void
master_send_evict(uint32 worker_ip, uint16 worker_port, uint32 worker_id)
{
    static rpc_msg_t req;
    memset(&req, 0, sizeof(req));

    fill_call(&req, PROC_EVICT);
    memcpy(req.payload, &worker_id, sizeof(uint32));
    req.payload_len = sizeof(uint32);

    rpc_addr_t dst = { .ip = worker_ip, .port = worker_port };
    rpc_send_call(&dst, &req);
}

/*
 * discovery_expire_workers — age the registry against the clock.
 *
 * Checks performed, per registered worker:
 *   1. Empty slots are skipped, and a worker already EXPIRED has nothing left
 *      to transition to, so it is skipped before the clock is even read.
 *   2. Past EXPIRED_TIMEOUT the worker is expired and told so (PROC_EVICT).
 *   3. Past SUSPECTED_TIMEOUT it is suspected -- but only on the *edge* into
 *      that state. Without the state test this fired on every pass: the caller
 *      polls at MASTER_POLL_MS and master_run_token pumps every 200 ms, so a
 *      stalled token reprinted the same line dozens of times and flooded the
 *      serial console during exactly the window a recovery has to be read
 *      from it.
 */
void
discovery_expire_workers(uint32 now)
{
    for (int i = 0; i < MAX_WORKERS; i++) {
        if (registry[i].info.worker_id == 0)
            continue;
        if (registry[i].state == WORKER_EXPIRED)
            continue;
        uint32 age = now - registry[i].last_seen_ms;
        /*
         * Soft-state expiry (RFC 2205 model). Note a known divergence from the
         * maintainer's lifecycle diagram: a PENDING worker that never completes
         * the cap probe is aged through SUSPECTED→EXPIRED here like an ACTIVE
         * one, whereas the diagram routes "worker pending --timeout--> unregistered"
         * (free the slot). Documented as a follow-up in README.md, not fixed here.
         */
        if (age > EXPIRED_TIMEOUT) {
            registry[i].state = WORKER_EXPIRED;
            printf("master: worker %d expired\n", registry[i].info.worker_id);
            /*
             * Drive the EXPIRED → hello edge: the worker re-runs the full
             * handshake on receipt (cf. DHCP lease rebind, RFC 2131 §4.4.5).
             */
            master_send_evict(registry[i].info.ip, registry[i].info.port,
                              registry[i].info.worker_id);
        }
        // TODO: handle capability claim timeout if implemented
        else if (age > SUSPECTED_TIMEOUT &&
                 registry[i].state != WORKER_SUSPECTED) {
            registry[i].state = WORKER_SUSPECTED;
            printf("master: worker %d suspected\n", registry[i].info.worker_id);
        }
    }
}


/* -----------------------------------------------------------------------
 * Layer assignment (inference pipeline)
 * ----------------------------------------------------------------------- */

int
discovery_ring_order(int *out, int max)
{
    int n = 0;
    for (int i = 0; i < MAX_WORKERS && n < max; i++)
        if (registry[i].info.worker_id != 0 && registry[i].state == WORKER_ACTIVE)
            out[n++] = i;
    return n;
}

/*
 * discovery_restitch_ring — rebuild every survivor's prev/next over the ACTIVE
 * set. See discovery.h for why this exists.
 *
 * Checks performed (by construction over the ordered ACTIVE list):
 *
 *   1. discovery_ring_order supplies the membership, so state filtering lives
 *      in one place and a non-ACTIVE worker can never be linked in here.
 *   2. k == 0 and k == n-1 close on the master, using rpc_local_port() rather
 *      than a literal -- the bug that once left the first worker's next
 *      pointing at a dead port and the ring unable to close.
 *   3. Interior links are taken from the neighbouring slots of that same
 *      ordered list, which is what makes this agree with handle_cap_ack's
 *      incremental stitch by construction.
 *   4. n == 0 writes nothing; the caller decides whether an empty ring is an
 *      error (run_generation_session treats it as unrecoverable).
 */
int
discovery_restitch_ring(void)
{
    int slots[MAX_WORKERS];
    int n = discovery_ring_order(slots, MAX_WORKERS);

    uint32 mip   = ip();
    uint16 mport = rpc_local_port();

    for (int k = 0; k < n; k++) {
        int slot = slots[k];

        if (k == 0) {
            registry[slot].prev_ip   = mip;
            registry[slot].prev_port = mport;
        } else {
            registry[slot].prev_ip   = registry[slots[k - 1]].info.ip;
            registry[slot].prev_port = registry[slots[k - 1]].info.port;
        }

        if (k == n - 1) {
            registry[slot].next_ip   = mip;
            registry[slot].next_port = mport;
        } else {
            registry[slot].next_ip   = registry[slots[k + 1]].info.ip;
            registry[slot].next_port = registry[slots[k + 1]].info.port;
        }
    }

    return n;
}

/*
 * discovery_assign_layers — even split of [0, n_layers_total) over the ACTIVE
 * workers, remainder to the lowest-indexed ones.
 *
 * Checks performed:
 *   1. There must be at least one ACTIVE worker, and no more layers than we can
 *      hand out one-per-worker minimum (a worker with an empty range would sit
 *      in the ring contributing nothing but latency).
 *   2. Ranges are emitted contiguously and cover the model exactly; the caller
 *      can rely on worker k's layer_start being worker k-1's layer_end.
 *   3. Each PROC_ASSIGN_LAYERS is answered immediately by the worker (SUCCESS
 *      means "assignment accepted", not "weights resident"), so the multi-minute
 *      fetch that follows never runs against RPC_TIMEOUT_MS. Readiness arrives
 *      out of band as PROC_SHARD_READY.
 */
int
discovery_assign_layers(const assign_layers_t *tmpl, uint32 *out_ring_ids, int max_ids)
{
    int slots[MAX_WORKERS];
    int n = discovery_ring_order(slots, MAX_WORKERS);

    if (n <= 0) {
        printf("master: no active workers to assign layers to\n");
        return -1;
    }
    if ((int)tmpl->n_layers_total < n) {
        printf("master: %d layers cannot be split over %d workers\n",
               tmpl->n_layers_total, n);
        return -1;
    }

    int per = tmpl->n_layers_total / n;
    int rem = tmpl->n_layers_total % n;
    int next_layer = 0;

    for (int k = 0; k < n; k++) {
        int slot = slots[k];
        int count = per + (k < rem ? 1 : 0);

        assign_layers_t a = *tmpl;
        a.layer_start = next_layer;
        a.layer_end   = next_layer + count;
        next_layer    = a.layer_end;

        static rpc_msg_t req, reply;
        memset(&req, 0, sizeof(req));
        fill_call(&req, PROC_ASSIGN_LAYERS);

        uint32 words[ASSIGN_LAYERS_WORDS];
        memcpy(words, &a, sizeof(words));
        for (int i = 0; i < ASSIGN_LAYERS_WORDS; i++)
            xdr_put_u32(req.payload + i * 4, words[i]);
        req.payload_len = ASSIGN_LAYERS_WORDS * 4;

        rpc_addr_t dst = { .ip = registry[slot].info.ip,
                           .port = registry[slot].info.port };

        int r = rpc_call(&dst, &req, &reply);
        if (r != RPC_OK) {
            printf("master: worker %d refused assignment, err=%d\n",
                   registry[slot].info.worker_id, r);
            return -1;
        }
        printf("master: worker %d assigned layers [%d,%d)\n",
               registry[slot].info.worker_id, a.layer_start, a.layer_end);

        if (out_ring_ids && k < max_ids)
            out_ring_ids[k] = registry[slot].info.worker_id;
    }

    return n;
}

/*
 * discovery_assign_one — assign layers to the k-th active worker only.
 *
 * Splitting assignment per worker lets the master interleave each assignment
 * with the wait for that worker's shard to finish loading. This matters at
 * scale: a worker begins fetching its shard (~100 MB for the 110M model) the
 * instant it is assigned, and that fetch floods the shared segment for minutes.
 * If the master assigned the next worker during that flood, the assignment RPC
 * would be lost — rpc_call's retry budget (RPC_MAX_RETRIES × RPC_TIMEOUT_MS) is
 * far shorter than the fetch. Assigning one worker and waiting for its
 * PROC_SHARD_READY before assigning the next keeps the control plane and the
 * data plane from ever overlapping across workers. (At 15M the shards are ~4 MB,
 * so the contention never appeared; 110M's shard size surfaced it.)
 *
 * The even split is recomputed from k and the active-worker count, identical to
 * discovery_assign_layers, so worker k's range is the same whichever path emits
 * it: contiguous, remainder to the lowest indices.
 *
 * Checks performed:
 *   1. k is within the active-worker count.
 *   2. The model has at least one layer per worker (no empty range).
 *   3. The worker answers SUCCESS (assignment accepted, not yet resident); any
 *      transport error or rejection is returned so the master can abort.
 *
 * @return RPC_OK on success, negative on error.
 */
int
discovery_assign_one(const assign_layers_t *tmpl, int k)
{
    int slots[MAX_WORKERS];
    int n = discovery_ring_order(slots, MAX_WORKERS);

    if (k < 0 || k >= n)
        return -1;
    if ((int)tmpl->n_layers_total < n)
        return -1;

    int per = tmpl->n_layers_total / n;
    int rem = tmpl->n_layers_total % n;
    int start = k * per + (k < rem ? k : rem);   /* == sum of counts for j < k */
    int count = per + (k < rem ? 1 : 0);

    assign_layers_t a = *tmpl;
    a.layer_start = start;
    a.layer_end   = start + count;

    static rpc_msg_t req, reply;
    memset(&req, 0, sizeof(req));
    fill_call(&req, PROC_ASSIGN_LAYERS);

    uint32 words[ASSIGN_LAYERS_WORDS];
    memcpy(words, &a, sizeof(words));
    for (int i = 0; i < ASSIGN_LAYERS_WORDS; i++)
        xdr_put_u32(req.payload + i * 4, words[i]);
    req.payload_len = ASSIGN_LAYERS_WORDS * 4;

    rpc_addr_t dst = { .ip = registry[slots[k]].info.ip,
                       .port = registry[slots[k]].info.port };

    int r = rpc_call(&dst, &req, &reply);
    if (r != RPC_OK) {
        printf("master: worker %d refused assignment, err=%d\n",
               registry[slots[k]].info.worker_id, r);
        return r;
    }
    printf("master: worker %d assigned layers [%d,%d)\n",
           registry[slots[k]].info.worker_id, a.layer_start, a.layer_end);
    return RPC_OK;
}

// void
// discovery_assign_layers_OLD(uint32 worker_id, uint32 layer_start, uint32 layer_end)
// {
//     int slot = registry_find(worker_id);
//     if (slot < 0) {
//         printf("master: cannot assign layers to unknown worker %d\n", worker_id);
//         return;
//     }
//     registry[slot].info.capabilities |= CAP_INFER; // Mark as capable of inference
//     printf("master: assigned layers %d-%d to worker %d\n", layer_start, layer_end, worker_id);
// }