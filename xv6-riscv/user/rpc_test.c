/*
 * rpc_test.c — unit + integration tests for rpc.h / rpc.c
 *
 * Build with the rest of user-space: add rpc_test to UPROGS in Makefile.
 * Run inside QEMU: $ rpc_test
 *
 * Test strategy
 * -------------
 *  T1  Constants & enum sanity          (compile-time / value checks)
 *  T2  XDR encode → decode round-trip  (CALL)
 *  T3  XDR encode → decode round-trip  (REPLY, all accept_stat values)
 *  T4  Oversized payload rejection      (RPC_ERR_TOOBIG / RPC_ERR_ENCODE)
 *  T5  rpc_next_xid monotonicity
 *  T6  AUTH_NONE opaque_auth encoding
 *  T7  Loopback CALL/REPLY  (requires rpc_init; tests rpc_send_call +
 *      rpc_recv on the same port — QEMU loopback)
 *  T8  rpc_call timeout     (send to a port nobody is listening on)
 *  T9  PROC_NULL ping round-trip        (full rpc_call, needs two processes)
 *  T10 Rejected reply decoding          (RPC_MISMATCH, AUTH_ERROR)
 *
 * Tests T7–T9 require network; skip gracefully if rpc_init fails.
 *
 * Conventions
 * -----------
 *  - ASSERT(cond)        hard-fail if cond is false; print failing line.
 *  - EXPECT_EQ(a, b)     soft-fail, keep running.
 *  - Each test is a void function named test_TN_<description>().
 */

#include "kernel/types.h"
#include "user/user.h"       /* xv6 user-space syscall wrappers           */
#include "user/rpc.h"
#include "user/xdr.h"

/* -----------------------------------------------------------------------
 * Minimal test harness
 * ----------------------------------------------------------------------- */

static int g_pass = 0;
static int g_fail = 0;
static int g_skip = 0;

#define TEST_NAME(n) do { printf("[TEST] %s\n", n); } while(0)

#define MAKE_IP_ADDR(a, b, c, d) \
    (((uint32)(a) << 24) | ((uint32)(b) << 16) | ((uint32)(c) << 8) | (uint32)(d))


#define ASSERT(cond)                                                    \
    do {                                                                \
        if (!(cond)) {                                                  \
            printf("  FAIL  %s:%d  assert(%s)\n",                      \
                   __FILE__, __LINE__, #cond);                          \
            g_fail++;                                                   \
            return;   /* abort this test function */                    \
        }                                                               \
    } while (0)

#define EXPECT_EQ(a, b)                                                 \
    do {                                                                \
        if ((a) != (b)) {                                               \
            printf("  FAIL  %s:%d  expected %d got %d  (%s == %s)\n", \
                   __FILE__, __LINE__, (int)(b), (int)(a), #a, #b);    \
            g_fail++;                                                   \
        } else {                                                        \
            g_pass++;                                                   \
        }                                                               \
    } while (0)

#define EXPECT_NE(a, b)                                                 \
    do {                                                                \
        if ((a) == (b)) {                                               \
            printf("  FAIL  %s:%d  expected != %d  (%s)\n",            \
                   __FILE__, __LINE__, (int)(b), #a);                   \
            g_fail++;                                                   \
        } else {                                                        \
            g_pass++;                                                   \
        }                                                               \
    } while (0)

#define PASS() do { printf("  pass\n"); g_pass++; } while(0)

#define SKIP(reason) \
    do { printf("  SKIP  %s\n", reason); g_skip++; return; } while(0)

/* -----------------------------------------------------------------------
 * T1 — Constants & enum sanity
 * ----------------------------------------------------------------------- */
static void test_t1_constants(void)
{
    TEST_NAME("T1: constants & enum values");

    EXPECT_EQ(RPC_VERSION,    2);
    EXPECT_EQ(INFERENCE_PROG, 0x20000001u);
    EXPECT_EQ(INFERENCE_VERS, 1);

    /* RFC 5531 §8.3: INFERENCE_PROG must be in local-admin block */
    ASSERT(INFERENCE_PROG >= 0x20000000u && INFERENCE_PROG <= 0x3fffffffu);

    /* Procedure numbers */
    EXPECT_EQ(PROC_NULL,          0);
    EXPECT_EQ(PROC_AUTH_HELLO,    1);
    EXPECT_EQ(PROC_CAP_ADVERTISE, 2);
    EXPECT_EQ(PROC_CAP_PROBE,     3);
    EXPECT_EQ(PROC_INFER_REQ,     4);
    EXPECT_EQ(PROC_HEARTBEAT,     5);

    /* msg_type */
    EXPECT_EQ(MSG_CALL,  0);
    EXPECT_EQ(MSG_REPLY, 1);

    /* reply_stat */
    EXPECT_EQ(MSG_ACCEPTED, 0);
    EXPECT_EQ(MSG_DENIED,   1);

    /* accept_stat */
    EXPECT_EQ(SUCCESS,       0);
    EXPECT_EQ(PROG_UNAVAIL,  1);
    EXPECT_EQ(PROG_MISMATCH, 2);
    EXPECT_EQ(PROC_UNAVAIL,  3);
    EXPECT_EQ(GARBAGE_ARGS,  4);
    EXPECT_EQ(SYSTEM_ERR,    5);

    /* reject_stat */
    EXPECT_EQ(RPC_MISMATCH, 0);
    EXPECT_EQ(AUTH_ERROR,   1);

    /* auth_flavor */
    EXPECT_EQ(AUTH_NONE,  0);
    EXPECT_EQ(AUTH_SYS,   1);
    EXPECT_EQ(AUTH_SHORT, 2);

    /* Return codes are all distinct */
    EXPECT_NE(RPC_OK,          RPC_ERR_TIMEOUT);
    EXPECT_NE(RPC_ERR_TIMEOUT, RPC_ERR_NET);
    EXPECT_NE(RPC_ERR_NET,     RPC_ERR_ENCODE);
    EXPECT_NE(RPC_ERR_ENCODE,  RPC_ERR_DECODE);
    EXPECT_NE(RPC_ERR_DECODE,  RPC_ERR_TOOBIG);

    /* Payload fits in a UDP datagram without IP fragmentation concerns */
    ASSERT(RPC_PAYLOAD_MAX <= 65507u);

    PASS();
}

/* -----------------------------------------------------------------------
 * T2 — XDR encode → decode round-trip (CALL)
 * ----------------------------------------------------------------------- */
static void test_t2_encode_decode_call(void)
{
    TEST_NAME("T2: XDR encode/decode CALL round-trip");

    static uint8     buf[2048];
    static rpc_msg_t orig, decoded;

    /* Build a minimal PROC_NULL CALL */
    memset(&orig, 0, sizeof orig);
    orig.xid           = 0xDEADBEEFu;
    orig.mtype         = MSG_CALL;
    orig.call.rpcvers  = RPC_VERSION;
    orig.call.prog     = INFERENCE_PROG;
    orig.call.vers     = INFERENCE_VERS;
    orig.call.proc     = PROC_NULL;
    orig.call.cred.flavor   = AUTH_NONE;
    orig.call.cred.body_len = 0;
    orig.call.verf.flavor   = AUTH_NONE;
    orig.call.verf.body_len = 0;
    orig.payload_len   = 0;

    int n = rpc_encode_call(buf, sizeof buf, &orig);
    ASSERT(n > 0);

    memset(&decoded, 0, sizeof decoded);
    int rc = rpc_decode_msg(buf, (uint32)n, &decoded);
    EXPECT_EQ(rc, RPC_OK);

    EXPECT_EQ(decoded.xid,             orig.xid);
    EXPECT_EQ((int)decoded.mtype,      (int)MSG_CALL);
    EXPECT_EQ(decoded.call.rpcvers,    RPC_VERSION);
    EXPECT_EQ(decoded.call.prog,       INFERENCE_PROG);
    EXPECT_EQ(decoded.call.vers,       INFERENCE_VERS);
    EXPECT_EQ((int)decoded.call.proc,  (int)PROC_NULL);
    EXPECT_EQ((int)decoded.call.cred.flavor, (int)AUTH_NONE);
    EXPECT_EQ(decoded.call.cred.body_len,    0u);
    EXPECT_EQ((int)decoded.call.verf.flavor, (int)AUTH_NONE);
    EXPECT_EQ(decoded.call.verf.body_len,    0u);
    EXPECT_EQ(decoded.payload_len,     0u);

    /* Repeat with a non-trivial procedure and small payload */
    orig.xid          = 0x00000042u;
    orig.call.proc    = PROC_AUTH_HELLO;
    orig.payload[0]   = 0xAB;
    orig.payload[1]   = 0xCD;
    orig.payload_len  = 2;

    n = rpc_encode_call(buf, sizeof buf, &orig);
    ASSERT(n > 0);

    memset(&decoded, 0, sizeof decoded);
    rc = rpc_decode_msg(buf, (uint32)n, &decoded);
    EXPECT_EQ(rc, RPC_OK);
    EXPECT_EQ(decoded.xid,                  0x00000042u);
    EXPECT_EQ((int)decoded.call.proc,       (int)PROC_AUTH_HELLO);
    EXPECT_EQ(decoded.payload_len,          2u);
    EXPECT_EQ(decoded.payload[0],           0xABu);
    EXPECT_EQ(decoded.payload[1],           0xCDu);

    PASS();
}

/* -----------------------------------------------------------------------
 * T3 — XDR encode → decode round-trip (REPLY, all accept_stat values)
 * ----------------------------------------------------------------------- */
static void test_t3_encode_decode_reply(void)
{
    TEST_NAME("T3: XDR encode/decode REPLY round-trip (all accept_stat)");

    static uint8     buf[2048];
    static rpc_msg_t decoded;
    uint32    xid = 0x11223344u;

    /* SUCCESS with a small result payload */
    static uint8 result[4] = {0x01, 0x02, 0x03, 0x04};
    int n = rpc_encode_reply(buf, sizeof buf, xid, SUCCESS, result, 4);
    ASSERT(n > 0);

    memset(&decoded, 0, sizeof decoded);
    int rc = rpc_decode_msg(buf, (uint32)n, &decoded);
    EXPECT_EQ(rc, RPC_OK);
    EXPECT_EQ(decoded.xid,                    xid);
    EXPECT_EQ((int)decoded.mtype,             (int)MSG_REPLY);
    EXPECT_EQ((int)decoded.reply_stat,        (int)MSG_ACCEPTED);
    EXPECT_EQ((int)decoded.accepted.stat,     (int)SUCCESS);
    EXPECT_EQ(decoded.payload_len,            4u);
    EXPECT_EQ(decoded.payload[0],             0x01u);
    EXPECT_EQ(decoded.payload[3],             0x04u);

    /* PROC_UNAVAIL — no payload */
    n = rpc_encode_reply(buf, sizeof buf, xid, PROC_UNAVAIL, 0, 0);
    ASSERT(n > 0);
    memset(&decoded, 0, sizeof decoded);
    rc = rpc_decode_msg(buf, (uint32)n, &decoded);
    EXPECT_EQ(rc, RPC_OK);
    EXPECT_EQ((int)decoded.accepted.stat, (int)PROC_UNAVAIL);
    EXPECT_EQ(decoded.payload_len,        0u);

    /* GARBAGE_ARGS */
    n = rpc_encode_reply(buf, sizeof buf, xid, GARBAGE_ARGS, 0, 0);
    ASSERT(n > 0);
    memset(&decoded, 0, sizeof decoded);
    rc = rpc_decode_msg(buf, (uint32)n, &decoded);
    EXPECT_EQ(rc, RPC_OK);
    EXPECT_EQ((int)decoded.accepted.stat, (int)GARBAGE_ARGS);

    /* SYSTEM_ERR */
    n = rpc_encode_reply(buf, sizeof buf, xid, SYSTEM_ERR, 0, 0);
    ASSERT(n > 0);
    memset(&decoded, 0, sizeof decoded);
    rc = rpc_decode_msg(buf, (uint32)n, &decoded);
    EXPECT_EQ(rc, RPC_OK);
    EXPECT_EQ((int)decoded.accepted.stat, (int)SYSTEM_ERR);

    PASS();
}

/* -----------------------------------------------------------------------
 * T4 — Oversized payload rejection
 * ----------------------------------------------------------------------- */
static void test_t4_oversized_payload(void)
{
    TEST_NAME("T4: oversized payload rejection");

    static uint8     buf[8192];
    static rpc_msg_t msg;
    memset(&msg, 0, sizeof msg);
    msg.xid          = 1;
    msg.mtype        = MSG_CALL;
    msg.call.rpcvers = RPC_VERSION;
    msg.call.prog    = INFERENCE_PROG;
    msg.call.vers    = INFERENCE_VERS;
    msg.call.proc    = PROC_INFER_REQ;
    msg.call.cred.flavor = AUTH_NONE;
    msg.call.verf.flavor = AUTH_NONE;

    /* One byte over the declared maximum */
    msg.payload_len = RPC_PAYLOAD_MAX + 1;
    /* (don't bother filling payload bytes — the encoder should reject early) */

    int n = rpc_encode_call(buf, sizeof buf, &msg);
    ASSERT(n < 0);   /* must return an error */

    /* Also verify that a buf too small to hold even the fixed header fails */
    msg.payload_len = 0;
    n = rpc_encode_call(buf, 4 /* absurdly small */, &msg);
    ASSERT(n < 0);

    /* rpc_encode_reply with payload > RPC_PAYLOAD_MAX */
    static uint8 big[RPC_PAYLOAD_MAX + 2];
    memset(big, 0xAA, sizeof big);
    n = rpc_encode_reply(buf, sizeof buf, 1, SUCCESS, big, sizeof big);
    ASSERT(n < 0);

    PASS();
}

/* -----------------------------------------------------------------------
 * T5 — rpc_next_xid monotonicity
 * ----------------------------------------------------------------------- */
static void test_t5_xid_monotonic(void)
{
    TEST_NAME("T5: rpc_next_xid monotonicity");

    uint32 prev = rpc_next_xid();
    for (int i = 0; i < 64; i++) {
        uint32 next = rpc_next_xid();
        ASSERT(next > prev);   /* strictly increasing — no wrap in 64 calls */
        prev = next;
    }

    PASS();
}

/* -----------------------------------------------------------------------
 * T6 — AUTH_NONE opaque_auth round-trip
 * ----------------------------------------------------------------------- */
static void test_t6_auth_none(void)
{
    TEST_NAME("T6: AUTH_NONE opaque_auth survives encode/decode");

    static uint8     buf[2048];
    static rpc_msg_t orig, decoded;
    memset(&orig, 0, sizeof orig);

    orig.xid              = 0xCAFEBABEu;
    orig.mtype            = MSG_CALL;
    orig.call.rpcvers     = RPC_VERSION;
    orig.call.prog        = INFERENCE_PROG;
    orig.call.vers        = INFERENCE_VERS;
    orig.call.proc        = PROC_HEARTBEAT;
    orig.call.cred.flavor = AUTH_NONE;
    orig.call.cred.body_len = 0;
    orig.call.verf.flavor = AUTH_NONE;
    orig.call.verf.body_len = 0;
    orig.payload_len      = 0;

    int n = rpc_encode_call(buf, sizeof buf, &orig);
    ASSERT(n > 0);

    memset(&decoded, 0, sizeof decoded);
    int rc = rpc_decode_msg(buf, (uint32)n, &decoded);
    EXPECT_EQ(rc, RPC_OK);

    /* RFC 5531 §10.1: AUTH_NONE body_len MUST be 0 */
    EXPECT_EQ((int)decoded.call.cred.flavor,   (int)AUTH_NONE);
    EXPECT_EQ(decoded.call.cred.body_len,       0u);
    EXPECT_EQ((int)decoded.call.verf.flavor,   (int)AUTH_NONE);
    EXPECT_EQ(decoded.call.verf.body_len,       0u);

    PASS();
}

/* -----------------------------------------------------------------------
 * T7 — Loopback CALL/REPLY (needs UDP + rpc_init)
 * ----------------------------------------------------------------------- */
#define LOOPBACK_IP    MAKE_IP_ADDR(10, 0, 0, 2)
#define TEST_PORT_A    9000u
#define TEST_PORT_B    9001u

static void test_t7_loopback(void)
{
    TEST_NAME("T7: loopback send_call / recv");

    /* Try to init a local socket */
    int rc = rpc_init(TEST_PORT_A);
    if (rc != RPC_OK)
        SKIP("rpc_init failed — no network in this build");

    static rpc_msg_t call;
    memset(&call, 0, sizeof call);
    call.xid             = rpc_next_xid();
    call.mtype           = MSG_CALL;
    call.call.rpcvers    = RPC_VERSION;
    call.call.prog       = INFERENCE_PROG;
    call.call.vers       = INFERENCE_VERS;
    call.call.proc       = PROC_NULL;
    call.call.cred.flavor = AUTH_NONE;
    call.call.verf.flavor = AUTH_NONE;
    call.payload_len     = 0;

    rpc_addr_t dst = { .ip = LOOPBACK_IP, .port = TEST_PORT_A };

    rc = rpc_send_call(&dst, &call);
    EXPECT_EQ(rc, RPC_OK);

    /* recv the datagram we just sent to ourselves */
    static rpc_msg_t  received;
    rpc_addr_t src;
    memset(&received, 0, sizeof received);
    rc = rpc_recv(&received, &src, 2000 /* ms */);

    EXPECT_EQ(rc, RPC_OK);
    EXPECT_EQ(received.xid,              call.xid);
    EXPECT_EQ((int)received.mtype,      (int)MSG_CALL);
    EXPECT_EQ((int)received.call.proc,  (int)PROC_NULL);

    PASS();
}

/* -----------------------------------------------------------------------
 * T8 — rpc_call timeout (nobody listening)
 * ----------------------------------------------------------------------- */
static void test_t8_timeout(void)
{
    TEST_NAME("T8: rpc_call times out when no server is present");

    /* Use port B so we don't conflict with T7 */
    int rc = rpc_init(TEST_PORT_B);
    if (rc != RPC_OK)
        SKIP("rpc_init failed — no network");

    static rpc_msg_t req, reply;
    memset(&req, 0, sizeof req);
    req.xid             = rpc_next_xid();
    req.mtype           = MSG_CALL;
    req.call.rpcvers    = RPC_VERSION;
    req.call.prog       = INFERENCE_PROG;
    req.call.vers       = INFERENCE_VERS;
    req.call.proc       = PROC_NULL;
    req.call.cred.flavor = AUTH_NONE;
    req.call.verf.flavor = AUTH_NONE;
    req.payload_len     = 0;

    /* Port 9999: nothing listening */
    rpc_addr_t dst = { .ip = LOOPBACK_IP, .port = 9999u };

    rc = rpc_call(&dst, &req, &reply);
    EXPECT_EQ(rc, RPC_ERR_TIMEOUT);

    PASS();
}

/* -----------------------------------------------------------------------
 * T9 — PROC_NULL ping round-trip via fork
 *
 * We fork a tiny "server" child that calls rpc_recv, validates the CALL,
 * and sends back a SUCCESS reply. The parent calls rpc_call and checks the
 * result. Uses ports 9002 (server) and 9003 (client).
 * ----------------------------------------------------------------------- */
#define SERVER_PORT  9002u
#define CLIENT_PORT  9003u

static void rpc_server_child(void)
{
    int rc = rpc_init(SERVER_PORT);
    if (rc != RPC_OK)
        exit(1);

    static rpc_msg_t  req;
    rpc_addr_t src;
    rc = rpc_recv(&req, &src, 2000 /* ms */);
    if (rc != RPC_OK)
        exit(2);

    /* Validate it looks like a PROC_NULL CALL */
    if (req.mtype != MSG_CALL || req.call.proc != PROC_NULL)
        exit(3);

    /* Send SUCCESS reply, no payload */
    rc = rpc_send_reply(&src, req.xid, SUCCESS, 0, 0);
    exit(rc == RPC_OK ? 0 : 4);
}

static void test_t9_null_ping(void)
{
    TEST_NAME("T9: PROC_NULL ping round-trip (fork)");

    /* Quick sanity: can we even init a socket? */
    int probe = rpc_init(CLIENT_PORT);
    if (probe != RPC_OK)
        SKIP("rpc_init failed — no network");

    int pid = fork();
    if (pid < 0)
        SKIP("fork failed");

    if (pid == 0) {
        /* child: be the server */
        rpc_server_child();
        exit(99); /* unreachable */
    }

    /* parent: be the client */
    static rpc_msg_t req, reply;
    memset(&req, 0, sizeof req);
    req.xid              = rpc_next_xid();
    req.mtype            = MSG_CALL;
    req.call.rpcvers     = RPC_VERSION;
    req.call.prog        = INFERENCE_PROG;
    req.call.vers        = INFERENCE_VERS;
    req.call.proc        = PROC_NULL;
    req.call.cred.flavor = AUTH_NONE;
    req.call.verf.flavor = AUTH_NONE;
    req.payload_len      = 0;

    rpc_addr_t dst = { .ip = LOOPBACK_IP, .port = SERVER_PORT };

    int rc = rpc_call(&dst, &req, &reply);
    EXPECT_EQ(rc, RPC_OK);

    if (rc == RPC_OK) {
        EXPECT_EQ(reply.xid,                    req.xid);
        EXPECT_EQ((int)reply.reply_stat,        (int)MSG_ACCEPTED);
        EXPECT_EQ((int)reply.accepted.stat,     (int)SUCCESS);
        EXPECT_EQ(reply.payload_len,            0u);
    }

    /* reap child */
    int status = 0;
    wait(&status);
    EXPECT_EQ(status, 0);

    PASS();
}

/* -----------------------------------------------------------------------
 * T10 — Rejected reply decoding (MSG_DENIED variants)
 *
 * We manually construct a rejected reply in XDR and verify rpc_decode_msg
 * parses it correctly. This tests the path that rpc_call must expose via
 * RPC_ERR_DENIED without actually having a hostile server.
 * ----------------------------------------------------------------------- */
static void test_t10_rejected_reply(void)
{
    TEST_NAME("T10: rejected reply decoding (RPC_MISMATCH / AUTH_ERROR)");

    /*
     * Manually build XDR for a MSG_DENIED / RPC_MISMATCH reply:
     *   xid           = 0xBEEF0001
     *   mtype         = MSG_REPLY (1)
     *   reply_stat    = MSG_DENIED (1)
     *   reject_stat   = RPC_MISMATCH (0)
     *   low           = 2
     *   high          = 2
     *
     * XDR is big-endian 4-byte aligned words.
     */

    /* Helper macro: write big-endian uint32 at byte offset off */
#define WR32(buf, off, val) do {                   \
        (buf)[(off)+0] = ((val) >> 24) & 0xFF;     \
        (buf)[(off)+1] = ((val) >> 16) & 0xFF;     \
        (buf)[(off)+2] = ((val) >>  8) & 0xFF;     \
        (buf)[(off)+3] = ((val)      ) & 0xFF;     \
    } while (0)

    static uint8    buf[64];
    uint32   off = 0;
    memset(buf, 0, sizeof buf);

    WR32(buf, off, 0xBEEF0001u); off += 4;  /* xid           */
    WR32(buf, off, MSG_REPLY);   off += 4;  /* mtype         */
    WR32(buf, off, MSG_DENIED);  off += 4;  /* reply_stat    */
    WR32(buf, off, RPC_MISMATCH);off += 4;  /* reject_stat   */
    WR32(buf, off, 2);           off += 4;  /* mismatch.low  */
    WR32(buf, off, 2);           off += 4;  /* mismatch.high */

    static rpc_msg_t decoded;
    memset(&decoded, 0, sizeof decoded);
    int rc = rpc_decode_msg(buf, off, &decoded);
    EXPECT_EQ(rc, RPC_OK);
    EXPECT_EQ(decoded.xid,                     0xBEEF0001u);
    EXPECT_EQ((int)decoded.mtype,              (int)MSG_REPLY);
    EXPECT_EQ((int)decoded.reply_stat,         (int)MSG_DENIED);
    EXPECT_EQ((int)decoded.rejected.stat,      (int)RPC_MISMATCH);
    EXPECT_EQ(decoded.rejected.mismatch.low,   2u);
    EXPECT_EQ(decoded.rejected.mismatch.high,  2u);

    /* AUTH_ERROR variant */
    memset(buf, 0, sizeof buf);
    off = 0;
    WR32(buf, off, 0xBEEF0002u); off += 4;  /* xid           */
    WR32(buf, off, MSG_REPLY);   off += 4;  /* mtype         */
    WR32(buf, off, MSG_DENIED);  off += 4;  /* reply_stat    */
    WR32(buf, off, AUTH_ERROR);  off += 4;  /* reject_stat   */
    WR32(buf, off, 1);           off += 4;  /* auth_stat     */

    memset(&decoded, 0, sizeof decoded);
    rc = rpc_decode_msg(buf, off, &decoded);
    EXPECT_EQ(rc, RPC_OK);
    EXPECT_EQ((int)decoded.rejected.stat,  (int)AUTH_ERROR);
    EXPECT_EQ(decoded.rejected.auth_stat,  1u);

#undef WR32

    PASS();
}

/* -----------------------------------------------------------------------
 * T11 — Corrupt / truncated datagram rejection
 * ----------------------------------------------------------------------- */
static void test_t11_corrupt_decode(void)
{
    TEST_NAME("T11: corrupt / truncated datagram returns RPC_ERR_DECODE");

    static uint8    buf[8];
    static rpc_msg_t decoded;

    /* Zero bytes — clearly not a valid RPC message */
    memset(&decoded, 0, sizeof decoded);
    int rc = rpc_decode_msg(buf, 0, &decoded);
    EXPECT_EQ(rc, RPC_ERR_DECODE);

    /* Four bytes (just an xid, nothing else) */
    buf[0] = 0xDE; buf[1] = 0xAD; buf[2] = 0xBE; buf[3] = 0xEF;
    memset(&decoded, 0, sizeof decoded);
    rc = rpc_decode_msg(buf, 4, &decoded);
    EXPECT_EQ(rc, RPC_ERR_DECODE);

    /* Eight bytes with an invalid mtype (99) */
    buf[4] = 0x00; buf[5] = 0x00; buf[6] = 0x00; buf[7] = 99;
    memset(&decoded, 0, sizeof decoded);
    rc = rpc_decode_msg(buf, 8, &decoded);
    EXPECT_EQ(rc, RPC_ERR_DECODE);

    PASS();
}

/* -----------------------------------------------------------------------
 * T12 — rpc_encode_call rejects wrong rpcvers
 *
 * Callers must set rpcvers = RPC_VERSION; encoding a message with any
 * other value should be rejected (or at least the decode should detect
 * the mismatch). We test that the encode+decode path preserves the value
 * so that a receiver could enforce this.
 * ----------------------------------------------------------------------- */
static void test_t12_rpcvers_check(void)
{
    TEST_NAME("T12: wrong rpcvers in CALL is detectable after decode");

    static uint8     buf[2048];
    static rpc_msg_t msg, decoded;
    memset(&msg, 0, sizeof msg);

    msg.xid              = 1;
    msg.mtype            = MSG_CALL;
    msg.call.rpcvers     = 99;   /* invalid — RFC 5531 says MUST be 2 */
    msg.call.prog        = INFERENCE_PROG;
    msg.call.vers        = INFERENCE_VERS;
    msg.call.proc        = PROC_NULL;
    msg.call.cred.flavor = AUTH_NONE;
    msg.call.verf.flavor = AUTH_NONE;
    msg.payload_len      = 0;

    /*
     * The encoder MAY reject this (return < 0), OR it may encode it
     * faithfully and leave enforcement to the receiver.  Either is
     * acceptable at the transport layer, but the decoded rpcvers MUST
     * NOT silently become 2.
     */
    int n = rpc_encode_call(buf, sizeof buf, &msg);
    if (n < 0) {
        /* Encoder enforces: that's fine */
        printf("  (encoder rejected invalid rpcvers — acceptable)\n");
        g_pass++;
        return;
    }

    memset(&decoded, 0, sizeof decoded);
    int rc = rpc_decode_msg(buf, (uint32)n, &decoded);
    if (rc == RPC_ERR_DECODE) {
        /* Decoder enforces: also fine */
        printf("  (decoder rejected invalid rpcvers — acceptable)\n");
        g_pass++;
        return;
    }

    EXPECT_EQ(rc, RPC_OK);
    /* If both encode & decode succeeded, rpcvers must be preserved */
    EXPECT_EQ(decoded.call.rpcvers, 99u);

    PASS();
}

/* -----------------------------------------------------------------------
 * T13 — Max-size payload round-trip
 * ----------------------------------------------------------------------- */
static void test_t13_max_payload(void)
{
    TEST_NAME("T13: max-size payload round-trip");

    /* buf must be large enough to hold header + max payload */
    static uint8 buf[RPC_PAYLOAD_MAX + 512];
    static rpc_msg_t msg, decoded;
    memset(&msg, 0, sizeof msg);

    msg.xid              = 0xABCD1234u;
    msg.mtype            = MSG_CALL;
    msg.call.rpcvers     = RPC_VERSION;
    msg.call.prog        = INFERENCE_PROG;
    msg.call.vers        = INFERENCE_VERS;
    msg.call.proc        = PROC_INFER_REQ;
    msg.call.cred.flavor = AUTH_NONE;
    msg.call.verf.flavor = AUTH_NONE;
    msg.payload_len      = RPC_PAYLOAD_MAX;

    /* Fill payload with a recognisable pattern */
    for (uint32 i = 0; i < RPC_PAYLOAD_MAX; i++)
        msg.payload[i] = (uint8)(i & 0xFF);

    int n = rpc_encode_call(buf, sizeof buf, &msg);
    ASSERT(n > 0);

    memset(&decoded, 0, sizeof decoded);
    int rc = rpc_decode_msg(buf, (uint32)n, &decoded);
    EXPECT_EQ(rc, RPC_OK);
    EXPECT_EQ(decoded.payload_len, (uint32)RPC_PAYLOAD_MAX);

    /* Spot-check a few payload bytes */
    EXPECT_EQ(decoded.payload[0],                0x00u);
    EXPECT_EQ(decoded.payload[1],                0x01u);
    EXPECT_EQ(decoded.payload[255],              0xFFu);
    EXPECT_EQ(decoded.payload[RPC_PAYLOAD_MAX-1],
              (uint8)((RPC_PAYLOAD_MAX - 1) & 0xFF));

    PASS();
}

/* -----------------------------------------------------------------------
 * main
 * ----------------------------------------------------------------------- */
int main(void)
{
    printf("=== rpc_test: ONC RPC layer (RFC 5531) ===\n\n");

    test_t1_constants();
    test_t2_encode_decode_call();
    test_t3_encode_decode_reply();
    test_t4_oversized_payload();
    test_t5_xid_monotonic();
    test_t6_auth_none();
    test_t7_loopback();              // e1000 does not handle loopback
    test_t8_timeout();
    test_t9_null_ping();
    test_t10_rejected_reply();
    test_t11_corrupt_decode();
    test_t12_rpcvers_check();
    test_t13_max_payload();

    printf("\n=== Results: %d passed, %d failed, %d skipped ===\n",
           g_pass, g_fail, g_skip);

    exit(g_fail > 0 ? 1 : 0);
}