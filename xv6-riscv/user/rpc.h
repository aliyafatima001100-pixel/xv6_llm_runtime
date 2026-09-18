#ifndef _RPC_H_
#define _RPC_H_

/*
 * ONC RPC message layer — RFC 5531 compliant
 * XDR encoding per RFC 4506
 *
 * Wire structures follow Section 9 of RFC 5531 exactly.
 * We run over UDP (unreliable transport), so timeout/retransmit
 * are our responsibility per Section 5 of RFC 5531.
 * Record marking (Section 11) is TCP-only; we skip it.
 *
 * Program number 0x20000001 is in the "Defined by local administrator"
 * block (0x20000000–0x3fffffff) per Section 8.3 of RFC 5531.
 */

#include "../kernel/types.h"
#include "xdr.h"

/* -----------------------------------------------------------------------
 * RFC 5531 §9 — fixed constants
 * ----------------------------------------------------------------------- */

#define RPC_VERSION       2          /* rpcvers MUST be 2 (RFC 5531 §9)   */

/*
 * Program number — "Defined by local administrator" block (RFC 5531 §8.3).
 * Students extending this system must use numbers from 0x20000000–0x3fffffff.
 */
#define INFERENCE_PROG    0x20000001
#define INFERENCE_VERS    1          /* version 1; increment on wire changes */

#define TICK_HZ          10         /* xv6-riscv default*/

/*
 * Procedure numbers within INFERENCE_PROG version 1.
 * Procedure 0 is reserved as NULL/ping by convention (RFC 5531 §12.1).
 */
typedef enum {
    PROC_NULL         = 0,   /* ping / round-trip test                    */
    PROC_AUTH_HELLO   = 1,   /* worker → master: hello + HMAC'd identity  */
    PROC_CAP_ACK      = 2,   /* worker → master: "results for cap probe"  */
    PROC_CAP_PROBE    = 3,   /* master → worker: probe with known input    */
    PROC_INFER_REQ    = 4,   /* master → worker: inference job             */
    PROC_HEARTBEAT    = 5,   /* bidirectional keep-alive                   */
    PROC_SET_NEIGHBOR = 6,   /* procedure advertises capabilities */
    PROC_EVICT         = 7,   /* master → worker: "you're expired" */
    PROC_CAP_ADVERTISE = 8,   /* procedure advertises capabilities */
    PROC_ASSIGN_LAYERS = 9,   /* master -> worker: own layers [a,b), fetch here */
    PROC_SHARD_READY   = 10,  /* worker -> master: my layers are resident       */
} rpc_proc_t;

/* -----------------------------------------------------------------------
 * RFC 5531 §9 — msg_type discriminant
 * ----------------------------------------------------------------------- */
typedef enum {
    MSG_CALL  = 0,
    MSG_REPLY = 1,
} msg_type_t;

/* -----------------------------------------------------------------------
 * RFC 5531 §9 — reply_stat
 * ----------------------------------------------------------------------- */
typedef enum {
    MSG_ACCEPTED = 0,
    MSG_DENIED   = 1,
} reply_stat_t;

/* -----------------------------------------------------------------------
 * RFC 5531 §9 — accept_stat
 * ----------------------------------------------------------------------- */
typedef enum {
    SUCCESS       = 0,   /* RPC executed successfully      */
    PROG_UNAVAIL  = 1,   /* remote hasn't exported program */
    PROG_MISMATCH = 2,   /* remote can't support version # */
    PROC_UNAVAIL  = 3,   /* program can't support procedure*/
    GARBAGE_ARGS  = 4,   /* procedure can't decode params  */
    SYSTEM_ERR    = 5,   /* e.g. memory allocation failure */
} accept_stat_t;

/* -----------------------------------------------------------------------
 * RFC 5531 §9 — reject_stat
 * ----------------------------------------------------------------------- */
typedef enum {
    RPC_MISMATCH = 0,   /* RPC version number != 2           */
    AUTH_ERROR   = 1,   /* remote can't authenticate caller  */
} reject_stat_t;

/* -----------------------------------------------------------------------
 * RFC 5531 §8.2 — opaque_auth
 *
 * flavor = AUTH_NONE (0), body_len = 0 throughout.
 * We use AUTH_NONE because our PSK authentication is implemented at the
 * application payload level (PROC_AUTH_HELLO), not as an RPC auth flavor.
 * AUTH_NONE is mandatory in every conforming RPC implementation (§10.1).
 * ----------------------------------------------------------------------- */
typedef enum {
    AUTH_NONE  = 0,
    AUTH_SYS   = 1,
    AUTH_SHORT = 2,
} auth_flavor_t;

#define OPAQUE_AUTH_BODY_MAX  400    /* RFC 5531 §8.2 hard limit           */

typedef struct {
    auth_flavor_t flavor;            /* AUTH_NONE = 0                      */
    uint32      body_len;          /* 0 for AUTH_NONE                    */
    uint8       body[OPAQUE_AUTH_BODY_MAX];
} opaque_auth_t;

/* -----------------------------------------------------------------------
 * RFC 5531 §9 — call_body
 *
 * struct call_body {
 *     unsigned int rpcvers;   // must be 2
 *     unsigned int prog;
 *     unsigned int vers;
 *     unsigned int proc;
 *     opaque_auth  cred;
 *     opaque_auth  verf;
 *     // procedure-specific parameters follow
 * };
 * ----------------------------------------------------------------------- */
typedef struct {
    uint32      rpcvers;           /* MUST be RPC_VERSION (2)            */
    uint32      prog;              /* INFERENCE_PROG                     */
    uint32      vers;              /* INFERENCE_VERS                     */
    uint32      proc;              /* one of rpc_proc_t                  */
    opaque_auth_t cred;              /* AUTH_NONE                          */
    opaque_auth_t verf;              /* AUTH_NONE                          */
} call_body_t;

/* -----------------------------------------------------------------------
 * RFC 5531 §9 — accepted_reply
 *
 * struct accepted_reply {
 *     opaque_auth  verf;
 *     union switch (accept_stat stat) {
 *         case SUCCESS:       opaque results[0];
 *         case PROG_MISMATCH: mismatch_info;
 *         default:            void;
 *     } reply_data;
 * };
 * ----------------------------------------------------------------------- */
typedef struct {
    uint32 low;
    uint32 high;
} mismatch_info_t;

typedef struct {
    opaque_auth_t  verf;
    accept_stat_t  stat;
    mismatch_info_t mismatch;        /* valid only when stat == PROG_MISMATCH */
} accepted_reply_t;

/* -----------------------------------------------------------------------
 * RFC 5531 §9 — rejected_reply
 * ----------------------------------------------------------------------- */
typedef struct {
    reject_stat_t stat;
    mismatch_info_t mismatch;        /* valid only when stat == RPC_MISMATCH  */
    uint32        auth_stat;       /* valid only when stat == AUTH_ERROR    */
} rejected_reply_t;

/* -----------------------------------------------------------------------
 * RFC 5531 §9 — rpc_msg (top-level message)
 *
 * struct rpc_msg {
 *     unsigned int xid;
 *     union switch (msg_type mtype) {
 *         case CALL:  call_body  cbody;
 *         case REPLY: reply_body rbody;
 *     } body;
 * };
 * ----------------------------------------------------------------------- */

#define RPC_PAYLOAD_MAX  4096        /* max procedure-specific bytes; your
                                        fragmentation handles larger payloads */

typedef struct {
    uint32       xid;              /* transaction ID                     */
    msg_type_t     mtype;            /* CALL or REPLY                      */

    /* CALL fields */
    call_body_t    call;

    /* REPLY fields */
    reply_stat_t   reply_stat;
    accepted_reply_t accepted;
    rejected_reply_t rejected;

    /* procedure-specific payload (parameters on CALL, results on REPLY) */
    uint8  payload[RPC_PAYLOAD_MAX];
    uint32 payload_len;
} rpc_msg_t;

/* -----------------------------------------------------------------------
 * Transport address — adapt to our UDP stack's types
 * ----------------------------------------------------------------------- */
typedef struct {
    uint32 ip;
    uint16 port;
} rpc_addr_t;

/* -----------------------------------------------------------------------
 * Return codes (transport layer, not RPC accept_stat)
 * ----------------------------------------------------------------------- */
#define RPC_OK           0
#define RPC_ERR_TIMEOUT  (-1)
#define RPC_ERR_NET      (-2)
#define RPC_ERR_ENCODE   (-3)
#define RPC_ERR_DECODE   (-4)
#define RPC_ERR_TOOBIG   (-5)
#define RPC_ERR_DENIED   (-6)   /* server returned MSG_DENIED             */
#define RPC_ERR_PROG     (-7)   /* PROG_UNAVAIL / PROG_MISMATCH           */
#define RPC_ERR_PROC     (-8)   /* PROC_UNAVAIL                           */
#define RPC_ERR_GARBAGE  (-9)   /* GARBAGE_ARGS — our call_body was wrong */

/*
 * Timeout for rpc_call() in milliseconds.
 * RFC 5531 §5: "must implement its own time-out ... policies".
 * Calibrate against your QEMU RTT with uptime() deltas; start here.
 */
#define RPC_TIMEOUT_MS   500
#define RPC_MAX_RETRIES  3

/* -----------------------------------------------------------------------
 * Public API
 * ----------------------------------------------------------------------- */

/*
 * rpc_init — bind local UDP socket on `local_port`.
 * Call once at master/worker startup.
 */
int rpc_init(uint16 local_port);

/*
 * rpc_local_port — the local UDP port bound by rpc_init(), or 0 if unbound.
 * Use this rather than assuming a port number when a node has to advertise
 * its own address (e.g. the master as a ring sentinel).
 */
uint16 rpc_local_port(void);

/*
 * rpc_fill_call — fill in the standard CALL header fields (rpcvers, prog, vers,
 * proc, AUTH_NONE cred/verf) and a fresh xid, per RFC 5531 §9.
 */
void rpc_fill_call(rpc_msg_t *msg, uint32 proc);

/*
 * rpc_next_xid — monotonically increasing transaction ID.
 * Exposed so callers can pre-fill xid for fire-and-forget sends.
 */
uint32 rpc_next_xid(void);

/*
 * rpc_send_call — encode a CALL message and send it over UDP.
 * Does NOT wait for a reply. Use for one-way messages or when you
 * will poll rpc_recv yourself.
 */
int rpc_send_call(const rpc_addr_t *dst, const rpc_msg_t *msg);

/*
 * rpc_send_reply — encode an ACCEPTED reply and send it over UDP.
 * `xid` must match the xid of the CALL being answered.
 * `stat` is the accept_stat. On SUCCESS, payload/payload_len carry results.
 */
int rpc_send_reply(const rpc_addr_t *dst,
                   uint32          xid,
                   accept_stat_t     stat,
                   const uint8    *payload,
                   uint32          payload_len);

/*
 * rpc_recv — blocking receive with timeout.
 * Decodes any incoming datagram (CALL or REPLY) into `out_msg`.
 * Fills `out_src` with the sender's address.
 */
int rpc_recv(rpc_msg_t *out_msg, rpc_addr_t *out_src, int timeout_ms);

/*
 * rpc_call — send CALL + wait for matching REPLY (same xid).
 * Retries up to RPC_MAX_RETRIES times per RFC 5531 §5.
 * Returns RPC_OK on SUCCESS, or a negative error code.
 * On RPC_OK, out_reply->payload / payload_len hold the server's results.
 */
int rpc_call(const rpc_addr_t *dst,
             const rpc_msg_t  *req,
             rpc_msg_t        *out_reply);

/* -----------------------------------------------------------------------
 * XDR encode/decode helpers for rpc_msg_t
 *
 * These are thin wrappers around xdrmem_create + the RFC 5531 field order.
 * Higher layers (auth, capability, inference) encode their own payloads
 * and pass them in as opaque bytes; we never inspect payload contents.
 * ----------------------------------------------------------------------- */

/*
 * rpc_encode_call — XDR-encode a CALL message into `buf`.
 * Returns bytes written, or negative error code.
 */
int rpc_encode_call(uint8 *buf, uint32 buflen, const rpc_msg_t *msg);

/*
 * rpc_encode_reply — XDR-encode an ACCEPTED reply into `buf`.
 * Returns bytes written, or negative error code.
 */
int rpc_encode_reply(uint8 *buf, uint32 buflen,
                     uint32 xid, accept_stat_t stat,
                     const uint8 *payload, uint32 payload_len);

/*
 * rpc_decode_msg — XDR-decode a raw datagram into `out_msg`.
 * Handles both CALL and REPLY.
 * Returns RPC_OK or RPC_ERR_DECODE.
 */
int rpc_decode_msg(const uint8 *buf, uint32 buflen, rpc_msg_t *out_msg);

#endif /* _RPC_H_ */