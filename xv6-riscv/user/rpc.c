/*
 * rpc.c — ONC RPC transport layer, RFC 5531 compliant
 * XDR encoding per RFC 4506
 *
 * Runs over UDP (unreliable transport).
 * Record marking (RFC 5531 §11) is TCP-only; not implemented here.
 *
 * -----------------------------------------------------------------------
 * UDP shim — replace the three _udp_* stubs with your e1000/UDP API.
 * Everything else in this file is portable across your xv6 instances.
 * -----------------------------------------------------------------------
 */

#include "rpc.h"
#include "../kernel/types.h"
#include "user/user.h"       /* xv6 syscalls */
#include "xdr.h"

/* -----------------------------------------------------------------------
 * UDP platform shim
 *
 * Your stack almost certainly exposes something like:
 *   int  udp_open(uint16 local_port);
 *   int  udp_sendto(int fd, const void *buf, int len,
 *                   uint32 dst_ip, uint16 dst_port);
 *   int  udp_recvfrom(int fd, void *buf, int maxlen,
 *                     uint32 *src_ip, uint16 *src_port,
 *                     int timeout_ms);
 *
 * Return convention expected by this file:
 *   udp_sendto  → bytes sent on success, negative on error
 *   udp_recvfrom→ bytes received on success, RPC_ERR_TIMEOUT on timeout,
 *                 negative on error
 * ----------------------------------------------------------------------- */

static int g_port = -1;  // track current bound port

static int _udp_bind(uint16 port)
{
    if (g_port >= 0)
        unbind((uint16)g_port);
    int r = bind(port);
    if (r < 0)
        return -1;
    g_port = port;
    return 0;
}

static int _udp_send(uint32 dst_ip, uint16 dst_port,
                      const uint8 *buf, int len)
{
    return send(g_port, dst_ip, dst_port, (char *)buf, (uint32)len);
}

static int _udp_recv(uint8 *buf, int maxlen,
                      uint32 *src_ip, uint16 *src_port,
                      int timeout_ms)
{
    int timeout_ticks = (timeout_ms * TICK_HZ) / 1000;

    int n = recvtimeo(g_port, src_ip, src_port, (char *)buf, maxlen, timeout_ticks);

    if (n == -2)
        return RPC_ERR_TIMEOUT;
    if (n < 0)
        return RPC_ERR_NET;
    return n;
}
/* -----------------------------------------------------------------------
 * Wire buffers
 *
 * An RPC datagram is up to RPC_PAYLOAD_MAX + header, so each of these is 4352
 * bytes. They used to be automatic (`uint8 wire[...]` inside each function),
 * which put ~13 KB of them live at once along the deep path
 * discovery_register -> rpc_call -> rpc_send_call / rpc_recv. Measured on a
 * worker whose master was absent: 15,392 of the 16 KB user stack (USERSTACK = 4
 * pages) were consumed by the time rpc_recv was reached, and the next printf
 * pushed the frame into the guard page -- a store fault at the top byte of the
 * guard page, tracking the stack-ASLR gap from run to run. Hoisting them to
 * static storage removes that ~13 KB from every RPC call chain.
 *
 * Concurrency, which differs per buffer:
 *   - g_rx_wire is touched only by rpc_recv, and a node has exactly one
 *     recv-owner by construction: the worker's listen thread, which parks while
 *     the heartbeat thread re-registers (see discovery_listen_thread). No lock
 *     is needed, but that invariant is what makes it safe -- a second concurrent
 *     rpc_recv would corrupt this buffer as surely as it would steal datagrams.
 *   - g_tx_wire is shared by every sender: the heartbeat, inference and listen
 *     threads all transmit. It is therefore serialised with g_tx_lock.
 * ----------------------------------------------------------------------- */
static uint8 g_rx_wire[RPC_PAYLOAD_MAX + 256];
static uint8 g_tx_wire[RPC_PAYLOAD_MAX + 256];
static int   g_tx_lock;

/* -----------------------------------------------------------------------
 * XID counter — monotonic; single-core xv6 needs no atomics
 * ----------------------------------------------------------------------- */
static uint32 g_xid = 1;

uint32 rpc_next_xid(void)
{
    return g_xid++;
}

/*
 * rpc_local_port — the port rpc_init() bound, i.e. this node's RPC address.
 * Callers that must name themselves on the wire (the master's ring sentinel,
 * for one) read it here instead of hardcoding a port and drifting out of sync
 * with however the process was actually started.
 */
/*
 * rpc_fill_call — populate the RFC 5531 §9 call_body fields common to every
 * request this program makes: version 2, our program/version, AUTH_NONE
 * credentials, and a fresh xid. Callers then add their procedure payload.
 */
void rpc_fill_call(rpc_msg_t *msg, uint32 proc)
{
    msg->xid                = rpc_next_xid();
    msg->mtype              = MSG_CALL;
    msg->call.rpcvers       = RPC_VERSION;
    msg->call.prog          = INFERENCE_PROG;
    msg->call.vers          = INFERENCE_VERS;
    msg->call.proc          = proc;
    msg->call.cred.flavor   = AUTH_NONE;
    msg->call.cred.body_len = 0;
    msg->call.verf.flavor   = AUTH_NONE;
    msg->call.verf.body_len = 0;
}

uint16 rpc_local_port(void)
{
    return g_port < 0 ? 0 : (uint16)g_port;
}

/* -----------------------------------------------------------------------
 * rpc_init
 * ----------------------------------------------------------------------- */
int rpc_init(uint16 local_port)
{
    /* Serialises the shared transmit buffer; every thread that sends takes it. */
    mutex_init(&g_tx_lock);

    int fd = _udp_bind(local_port);
    if (fd < 0)
        return RPC_ERR_NET;
    return RPC_OK;
}

/* -----------------------------------------------------------------------
 * XDR helpers — opaque_auth
 *
 * RFC 5531 §8.2:
 *   struct opaque_auth {
 *       auth_flavor flavor;
 *       opaque body<400>;
 *   };
 *
 * We always write AUTH_NONE (flavor=0, body_len=0).
 * We decode whatever arrives but only trust AUTH_NONE.
 * ----------------------------------------------------------------------- */
static int xdr_encode_auth_none(XDR *xdrs)
{
    uint32 flavor   = AUTH_NONE;
    uint32 body_len = 0;
    if (!xdr_u_int(xdrs, &flavor))   return RPC_ERR_ENCODE;
    if (!xdr_u_int(xdrs, &body_len)) return RPC_ERR_ENCODE;
    return RPC_OK;
}

static int xdr_decode_opaque_auth(XDR *xdrs, opaque_auth_t *auth)
{
    uint32 flavor = 0, body_len = 0;
    if (!xdr_u_int(xdrs, &flavor))   return RPC_ERR_DECODE;
    if (!xdr_u_int(xdrs, &body_len)) return RPC_ERR_DECODE;

    auth->flavor   = (auth_flavor_t)flavor;
    auth->body_len = body_len;

    if (body_len > OPAQUE_AUTH_BODY_MAX)
        return RPC_ERR_DECODE;

    /* consume the body bytes even if we don't use them */
    if (body_len > 0) {
        if (!xdr_u_int(xdrs, &body_len)) /* XDR opaque is 4-byte-aligned */
            return RPC_ERR_DECODE;
        /* actually read the bytes */
        if (!xdrs->x_ops->x_getbytes(xdrs, (char *)auth->body, body_len))
            return RPC_ERR_DECODE;
    }
    return RPC_OK;
}

/* -----------------------------------------------------------------------
 * rpc_encode_call
 *
 * RFC 5531 §9 CALL wire layout:
 *
 *   xid          (uint32)
 *   mtype        (uint32) = CALL (0)
 *   rpcvers      (uint32) = 2
 *   prog         (uint32)
 *   vers         (uint32)
 *   proc         (uint32)
 *   cred         (opaque_auth) = AUTH_NONE
 *   verf         (opaque_auth) = AUTH_NONE
 *   <payload — procedure parameters, already XDR-encoded by caller>
 * ----------------------------------------------------------------------- */
int rpc_encode_call(uint8 *buf, uint32 buflen, const rpc_msg_t *msg)
{
    XDR xdrs;

    if (msg->call.rpcvers != RPC_VERSION)
        return RPC_ERR_ENCODE;

    /* Reject payloads exceeding the protocol maximum before touching
     * the XDR stream — mirrors the rpcvers check, fail fast on bad input. */
    if (msg->payload_len > RPC_PAYLOAD_MAX)
        return RPC_ERR_ENCODE;

    xdrmem_create(&xdrs, (char *)buf, buflen, XDR_ENCODE);
    uint32 xid    = msg->xid;
    uint32 mtype  = (uint32)MSG_CALL;
    uint32 rpcvers= msg->call.rpcvers;   // now round-tripped, not hardcoded
    uint32 prog   = msg->call.prog;
    uint32 vers   = msg->call.vers;
    uint32 proc   = msg->call.proc;

    if (!xdr_u_int(&xdrs, &xid))     goto fail;
    if (!xdr_u_int(&xdrs, &mtype))   goto fail;
    if (!xdr_u_int(&xdrs, &rpcvers)) goto fail;
    if (!xdr_u_int(&xdrs, &prog))    goto fail;
    if (!xdr_u_int(&xdrs, &vers))    goto fail;
    if (!xdr_u_int(&xdrs, &proc))    goto fail;

    /* cred — AUTH_NONE */
    if (xdr_encode_auth_none(&xdrs) != RPC_OK) goto fail;
    /* verf — AUTH_NONE */
    if (xdr_encode_auth_none(&xdrs) != RPC_OK) goto fail;

    /* procedure parameters */
    if (msg->payload_len > 0) {
        if (!xdrs.x_ops->x_putbytes(&xdrs,
                                     (char *)msg->payload,
                                     msg->payload_len))
            goto fail;
    }

    uint32 written = XDR_GETPOS(&xdrs);
    XDR_DESTROY(&xdrs);
    return (int)written;

fail:
    XDR_DESTROY(&xdrs);
    return RPC_ERR_ENCODE;
}

int rpc_encode_reply(uint8 *buf, uint32 buflen,
                      uint32 xid, accept_stat_t stat,
                      const uint8 *payload, uint32 payload_len)
{
    XDR xdrs;

    /* Reject oversized payloads before touching the XDR stream —
     * mirrors rpc_encode_call's bound check. */
    if (payload_len > RPC_PAYLOAD_MAX)
        return RPC_ERR_ENCODE;

    xdrmem_create(&xdrs, (char *)buf, buflen, XDR_ENCODE);
    uint32 mtype       = (uint32)MSG_REPLY;
    uint32 reply_stat  = (uint32)MSG_ACCEPTED;
    uint32 accept      = (uint32)stat;

    if (!xdr_u_int(&xdrs, &xid))         goto fail;
    if (!xdr_u_int(&xdrs, &mtype))       goto fail;
    if (!xdr_u_int(&xdrs, &reply_stat))  goto fail;

    /* verf — AUTH_NONE */
    if (xdr_encode_auth_none(&xdrs) != RPC_OK) goto fail;

    if (!xdr_u_int(&xdrs, &accept))      goto fail;

    if (stat == SUCCESS && payload_len > 0) {
        if (!xdrs.x_ops->x_putbytes(&xdrs, (char *)payload, payload_len))
            goto fail;
    }

    /* PROG_MISMATCH mismatch_info: callers needing this can extend here */
    uint32 written = XDR_GETPOS(&xdrs);
    XDR_DESTROY(&xdrs);
    return (int)written;

fail:
    XDR_DESTROY(&xdrs);
    return RPC_ERR_ENCODE;
}

/* -----------------------------------------------------------------------
 * rpc_decode_msg
 *
 * Handles both CALL and REPLY. Decodes the fixed RFC 5531 header fields
 * then copies the remaining bytes verbatim into msg->payload for the
 * upper layer (auth, capability, inference) to decode.
 * ----------------------------------------------------------------------- */
int rpc_decode_msg(const uint8 *buf, uint32 buflen, rpc_msg_t *out)
{
    XDR xdrs;
    /* xdrmem DECODE does not write to buf — cast away const is safe */
    xdrmem_create(&xdrs, (char *)buf, buflen, XDR_DECODE);

    uint32 xid = 0, mtype = 0;
    if (!xdr_u_int(&xdrs, &xid))   goto fail;
    if (!xdr_u_int(&xdrs, &mtype)) goto fail;

    out->xid   = xid;
    out->mtype = (msg_type_t)mtype;

    if (mtype == (uint32)MSG_CALL) {
        /* ---- decode call_body ---- */
        uint32 rpcvers = 0, prog = 0, vers = 0, proc = 0;
        if (!xdr_u_int(&xdrs, &rpcvers)) goto fail;
        if (!xdr_u_int(&xdrs, &prog))    goto fail;
        if (!xdr_u_int(&xdrs, &vers))    goto fail;
        if (!xdr_u_int(&xdrs, &proc))    goto fail;

        /* RFC 5531 §9: rpcvers != 2 → must reply MSG_DENIED / RPC_MISMATCH */
        if (rpcvers != RPC_VERSION) {
            XDR_DESTROY(&xdrs);
            return RPC_ERR_DECODE;
        }

        out->call.rpcvers = rpcvers;
        out->call.prog    = prog;
        out->call.vers    = vers;
        out->call.proc    = proc;

        if (xdr_decode_opaque_auth(&xdrs, &out->call.cred) != RPC_OK) goto fail;
        if (xdr_decode_opaque_auth(&xdrs, &out->call.verf) != RPC_OK) goto fail;

    } else if (mtype == (uint32)MSG_REPLY) {
        /* ---- decode reply_body ---- */
        uint32 reply_stat = 0;
        if (!xdr_u_int(&xdrs, &reply_stat)) goto fail;
        out->reply_stat = (reply_stat_t)reply_stat;

        if (reply_stat == (uint32)MSG_ACCEPTED) {
            if (xdr_decode_opaque_auth(&xdrs, &out->accepted.verf) != RPC_OK)
                goto fail;

            uint32 stat = 0;
            if (!xdr_u_int(&xdrs, &stat)) goto fail;
            out->accepted.stat = (accept_stat_t)stat;

            if (stat == (uint32)PROG_MISMATCH) {
                if (!xdr_u_int(&xdrs, &out->accepted.mismatch.low))  goto fail;
                if (!xdr_u_int(&xdrs, &out->accepted.mismatch.high)) goto fail;
            }

        } else {
            /* MSG_DENIED */
            uint32 reject_stat = 0;
            if (!xdr_u_int(&xdrs, &reject_stat)) goto fail;
            out->rejected.stat = (reject_stat_t)reject_stat;

            if (reject_stat == (uint32)RPC_MISMATCH) {
                if (!xdr_u_int(&xdrs, &out->rejected.mismatch.low))  goto fail;
                if (!xdr_u_int(&xdrs, &out->rejected.mismatch.high)) goto fail;
            } else {
                /* AUTH_ERROR */
                if (!xdr_u_int(&xdrs, &out->rejected.auth_stat)) goto fail;
            }
            /* Per RFC 5531 §9, MSG_DENIED is a well-formed reply variant, not
            * a decode error — reply_body's accepted/denied split is purely a
            * content discriminant. Decoding ends here; whether the call was
            * accepted or denied is for the caller (rpc_call) to act on. */
        }
    } else {
        goto fail;   /* unknown mtype */
    }

    /* whatever bytes remain in the datagram are the procedure payload */
    uint32 pos     = XDR_GETPOS(&xdrs);
    uint32 remaining = buflen - pos;

    if (remaining > RPC_PAYLOAD_MAX) goto fail;

    out->payload_len = remaining;
    if (remaining > 0)
        xdrs.x_ops->x_getbytes(&xdrs, (char *)out->payload, remaining);

    XDR_DESTROY(&xdrs);
    return RPC_OK;

fail:
    XDR_DESTROY(&xdrs);
    return RPC_ERR_DECODE;
}

/* -----------------------------------------------------------------------
 * rpc_send_call — encode CALL and fire over UDP
 * ----------------------------------------------------------------------- */
int rpc_send_call(const rpc_addr_t *dst, const rpc_msg_t *msg)
{
    mutex_lock(&g_tx_lock);

    int n = rpc_encode_call(g_tx_wire, sizeof(g_tx_wire), msg);
    if (n < 0) {
        mutex_unlock(&g_tx_lock);
        return n;
    }

    int sent = _udp_send(dst->ip, dst->port, g_tx_wire, n);
    mutex_unlock(&g_tx_lock);
    if (sent < 0) {
        return RPC_ERR_NET;
    }

    return RPC_OK;
}

/* -----------------------------------------------------------------------
 * rpc_send_reply — encode accepted REPLY and fire over UDP
 * ----------------------------------------------------------------------- */
int rpc_send_reply(const rpc_addr_t *dst,
                   uint32          xid,
                   accept_stat_t     stat,
                   const uint8    *payload,
                   uint32          payload_len)
{
    mutex_lock(&g_tx_lock);

    int n = rpc_encode_reply(g_tx_wire, sizeof(g_tx_wire), xid, stat,
                             payload, payload_len);
    if (n < 0) {
        mutex_unlock(&g_tx_lock);
        return n;
    }

    int sent = _udp_send(dst->ip, dst->port, g_tx_wire, n);
    mutex_unlock(&g_tx_lock);

    if (sent < 0)
        return RPC_ERR_NET;

    return RPC_OK;
}

/* -----------------------------------------------------------------------
 * rpc_recv — blocking receive with timeout
 * ----------------------------------------------------------------------- */
int rpc_recv(rpc_msg_t *out_msg, rpc_addr_t *out_src, int timeout_ms)
{
    uint32   src_ip   = 0;
    uint16   src_port = 0;

    int n = _udp_recv(g_rx_wire, sizeof(g_rx_wire), &src_ip, &src_port, timeout_ms);
    if (n == RPC_ERR_TIMEOUT) {
        /* A zero-ms call is a non-blocking poll (the master's cooperative pump
         * fires thousands during a weight fetch); an empty poll is the normal
         * case, not an event, so it is silent. Blocking waits still report. */
        return RPC_ERR_TIMEOUT;
    }
    if (n < 0) {
        printf("_udp_recv: recvtimeo failed, raw=%d, g_port=%d, ticks=%d\n",
               n, g_port, timeout_ms);
        return RPC_ERR_NET;
    }
    int ret = rpc_decode_msg(g_rx_wire, (uint32)n, out_msg);
    if (ret != RPC_OK) {
        return ret;
    }

    if (out_src) {
        out_src->ip   = src_ip;
        out_src->port = src_port;
    }
    return RPC_OK;
}

/* -----------------------------------------------------------------------
 * rpc_call — send CALL, wait for matching REPLY (same xid)
 *
 * RFC 5531 §5: on UDP, callers must handle retransmission themselves.
 * We retry RPC_MAX_RETRIES times, each with RPC_TIMEOUT_MS.
 * Stale replies (wrong xid) are silently discarded — common on QEMU
 * loopback when a previous call timed out and the reply arrives late.
 * ----------------------------------------------------------------------- */
int rpc_call(const rpc_addr_t *dst,
             const rpc_msg_t  *req,
             rpc_msg_t        *out_reply)
{
    rpc_msg_t call = *req;
    call.xid            = rpc_next_xid();
    call.mtype          = MSG_CALL;
    call.call.rpcvers   = RPC_VERSION;
    call.call.prog      = INFERENCE_PROG;
    call.call.vers      = INFERENCE_VERS;
    /* call.call.proc and call.payload* set by caller */
    call.call.cred.flavor    = AUTH_NONE;
    call.call.cred.body_len  = 0;
    call.call.verf.flavor    = AUTH_NONE;
    call.call.verf.body_len  = 0;

    for (int attempt = 0; attempt < RPC_MAX_RETRIES; attempt++) {
        int ret = rpc_send_call(dst, &call);
        if (ret != RPC_OK)
            return ret;

        /*
         * Drain incoming datagrams until we match our xid or exhaust
         * the per-attempt timeout. Per RFC 5531 §5, we do not increase
         * the timeout between retries here — add exponential backoff if
         * you observe QEMU congestion.
         */
        rpc_msg_t  reply;
        rpc_addr_t src;
        int        remaining_ms = RPC_TIMEOUT_MS;

        while (remaining_ms > 0) {
            ret = rpc_recv(&reply, &src, remaining_ms);
            if (ret == RPC_ERR_TIMEOUT) break;
            if (ret != RPC_OK)          return ret;

            /*
             * Only a REPLY can answer our CALL. Incoming CALLs -- a worker's
             * PROC_HEARTBEAT or PROC_SHARD_READY, say -- must be drained, never
             * matched: xids are PER-NODE monotonic counters (rpc_next_xid), not
             * globally unique, so another node's CALL can carry the same xid as
             * ours by pure coincidence. Matching such a CALL by xid and then
             * finding mtype != MSG_REPLY used to fall through to RPC_ERR_DENIED,
             * i.e. the master would mistake a worker's heartbeat for a denied
             * assignment reply and abort. Skipping non-REPLYs closes that race.
             */
            if (reply.mtype != MSG_REPLY) {
                remaining_ms -= 10;   /* rough burn; replace with uptime() */
                continue;
            }
            if (reply.xid != call.xid) {
                remaining_ms -= 10;   /* stale reply from a prior timed-out call */
                continue;
            }
            /* matched our REPLY — check accept_stat */
            if (reply.reply_stat == MSG_ACCEPTED) {
                switch (reply.accepted.stat) {
                case SUCCESS:       *out_reply = reply; return RPC_OK;
                case PROG_UNAVAIL:  return RPC_ERR_PROG;
                case PROG_MISMATCH: return RPC_ERR_PROG;
                case PROC_UNAVAIL:  return RPC_ERR_PROC;
                case GARBAGE_ARGS:  return RPC_ERR_GARBAGE;
                case SYSTEM_ERR:    return RPC_ERR_NET;
                default:            return RPC_ERR_DECODE;
                }
            }
            /* reply.reply_stat == MSG_DENIED (RFC 5531 §9) */
            return RPC_ERR_DENIED;
        }
        /* timeout on this attempt — retransmit */
    }

    return RPC_ERR_TIMEOUT;
}