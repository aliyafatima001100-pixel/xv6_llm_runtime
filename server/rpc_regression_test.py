"""
L3 (DistInf) regression gate — the sibling of the L1 kernel gate
(kernel_regression_test.py) and the L2 network gate (net_regression_test.py).

Where the L2 gate crafts raw frames and asserts xv6's on-wire reaction, this
gate speaks the *RPC* wire format (RFC 5531 over UDP, mirrored in rpc_proto.py)
and asserts xv6's DistInf reaction: the two-phase auth handshake, ring stitching,
soft-state heartbeat/expiry, and — the flow this pass implements — worker
re-registration after eviction (EXPIRED -> hello -> PENDING -> ACTIVE).

The host plays the counterparty to one live xv6 node. Two roles, selected by the
XV6_ROLE env var (the operational model mirrors the net gate: a human boots the
guest in tap mode and starts the in-guest program, then runs this gate):

    XV6_ROLE=master   xv6 runs `distinf --master <PORT>`; host = synthetic worker
    XV6_ROLE=worker   xv6 runs `distinf --worker 10.0.0.1 <PORT> 1`; host = master

Boot path (from xv6-riscv/): `make bridge-setup` brings up br0 (host = 10.0.0.1)
plus tap1/2/3; `make qemu-node1` builds the guest with IP 10.0.0.2 and attaches
it to tap1. (A bare `make qemu-tap` will not compile — the guest IP macro
XV6_IP_D has no default; only the qemu-node* targets define it.)

Run with --noconftest so the net suite's netecho autouse fixture does not fire:

    # terminal 1 — guest (master role):
    #   xv6-riscv$ make bridge-setup && make qemu-node1
    #   xv6$ distinf --master 5499
    # terminal 2 — host:
    XV6_ROLE=master .venv/bin/python -m pytest server/rpc_regression_test.py -v --noconftest

No root is needed for the sockets themselves (the default master port 5499 is
unprivileged); the tap/bridge must be up (`make bridge-setup`) and the guest
booted, as for the L2 gate. Set DISTINF_SLOW=1 to also run the natural-expiry
case (waits > EXPIRED_TIMEOUT).
"""

import os
import time

import pytest

import rpc_proto as R

# -----------------------------------------------------------------------
# Configuration (overridable via env, mirroring conftest.py's style)
# -----------------------------------------------------------------------
XV6_IP      = os.environ.get("XV6_IP", "10.0.0.2")
HOST_IP     = os.environ.get("XV6_HOST_IP", "10.0.0.1")
MASTER_PORT = int(os.environ.get("DISTINF_MASTER_PORT", "5499"))
ROLE        = os.environ.get("XV6_ROLE", "master")
RUN_SLOW    = os.environ.get("DISTINF_SLOW", "") not in ("", "0")

XV6_IP_U32  = R.ip_to_u32(XV6_IP)
MASTER_ADDR = (XV6_IP, MASTER_PORT)

# The single-worker ring points both neighbors back at the master. Note the
# port here is the sentinel 499 hard-coded in discovery.c:handle_cap_ack
# (independent of MASTER_PORT) — asserted verbatim so a change there is caught.
RING_SENTINEL_PORT = 499

master_only = pytest.mark.skipif(ROLE != "master",
                                 reason="XV6_ROLE != master (host plays worker)")
worker_only = pytest.mark.skipif(ROLE != "worker",
                                 reason="XV6_ROLE != worker (host plays master)")


# -----------------------------------------------------------------------
# Small helpers shared by both roles
# -----------------------------------------------------------------------
def new_worker(port=0):
    """A synthetic worker socket, source IP pinned to the tap address so xv6
    can ARP us and route its replies back into this socket."""
    return R.RpcPeer(local_port=port, bind_ip=HOST_IP)


def register_worker(peer, worker_id, ram=512 * 1024 * 1024):
    """Drive the full two-phase handshake as a worker. Returns (hello_reply,
    cap_ack_reply). Raises AssertionError on any protocol deviation."""
    info = R.pack_worker_info(worker_id, R.ip_to_u32(HOST_IP), peer.port, ram)
    hello = peer.call(MASTER_ADDR, R.PROC_AUTH_HELLO, info)
    assert hello is not None, "no reply to PROC_AUTH_HELLO"
    assert hello["accept_stat"] == R.SUCCESS, R.ACCEPT_STAT_NAME.get(hello["accept_stat"])
    rep = R.unpack_auth_hello_reply(hello["payload"])
    assert rep["status"] == R.WORKER_PENDING
    # Answer the RAM sized-probe: the master issued a seed + page count; a
    # conforming peer returns the checksum over that seeded pattern (a real xv6
    # worker also allocates the pages, which a host peer need not).
    chk = R.cap_probe_checksum(rep["probe_seed"], rep["probe_pages"])
    ack = peer.call(MASTER_ADDR, R.PROC_CAP_ACK, R.pack_cap_ack(rep["probe_data"], chk))
    assert ack is not None, "no reply to PROC_CAP_ACK"
    return rep, ack


# =======================================================================
# Environment gate — fail fast with instructions (like conftest.environment)
# =======================================================================
@pytest.fixture(scope="session", autouse=True)
def environment():
    if ROLE not in ("master", "worker"):
        pytest.exit(f"XV6_ROLE must be 'master' or 'worker', got {ROLE!r}", returncode=2)

    # Both roles need our tap source address to exist before any socket binds.
    try:
        probe = new_worker()
    except OSError as e:
        pytest.exit(
            f"cannot bind source IP {HOST_IP} ({e}) — bring the tap/bridge up "
            f"(`make bridge-setup`, host = 10.0.0.1) as documented in the README",
            returncode=2)

    if ROLE == "master":
        # PROC_NULL is unhandled -> master answers PROC_UNAVAIL: proof of life.
        reply = probe.call(MASTER_ADDR, R.PROC_NULL, timeout=2.0)
        probe.close()
        if reply is None:
            pytest.exit(
                f"no DistInf master at {XV6_IP}:{MASTER_PORT} — boot xv6 in tap "
                f"mode and run 'distinf --master {MASTER_PORT}' in the guest",
                returncode=3)
    else:
        # Worker role: the worker registers once at startup, so the host master
        # must already be listening. The SyntheticMaster fixture owns MASTER_PORT;
        # just confirm the address is bindable here, then release it.
        probe.close()
    yield


# =======================================================================
# Role: master-under-test  (xv6 = master, host = synthetic worker)
# =======================================================================
@master_only
class TestMasterUnderTest:

    def test_auth_hello_new(self):
        """A fresh AUTH_HELLO is accepted with status PENDING and a nonce."""
        w = new_worker()
        try:
            hello = w.call(MASTER_ADDR, R.PROC_AUTH_HELLO,
                           R.pack_worker_info(101, R.ip_to_u32(HOST_IP), w.port, 1 << 29))
            assert hello is not None and hello["accept_stat"] == R.SUCCESS
            rep = R.unpack_auth_hello_reply(hello["payload"])
            assert rep["status"] == R.WORKER_PENDING
            assert rep["probe_data"] != 0, "expected a non-zero probe nonce"
        finally:
            w.close()

    def test_cap_ack_correct_nonce(self):
        """Echoing the nonce activates the worker; the single-worker ring points
        both neighbors at the master sentinel."""
        w = new_worker()
        try:
            _rep, ack = register_worker(w, 102)
            assert ack["accept_stat"] == R.SUCCESS
            ring = R.unpack_set_neighbor(ack["payload"])
            assert ring["prev_ip"] == XV6_IP_U32 and ring["prev_port"] == RING_SENTINEL_PORT
            assert ring["next_ip"] == XV6_IP_U32 and ring["next_port"] == RING_SENTINEL_PORT
        finally:
            w.close()

    def test_cap_ack_wrong_nonce(self):
        """A CAP_ACK whose nonce does not match the issued probe is rejected."""
        w = new_worker()
        try:
            info = R.pack_worker_info(103, R.ip_to_u32(HOST_IP), w.port, 1 << 29)
            hello = w.call(MASTER_ADDR, R.PROC_AUTH_HELLO, info)
            rep = R.unpack_auth_hello_reply(hello["payload"])
            bad = w.call(MASTER_ADDR, R.PROC_CAP_ACK, R.pack_cap_ack(rep["probe_data"] ^ 0xDEAD))
            assert bad is not None and bad["accept_stat"] == R.GARBAGE_ARGS
        finally:
            w.close()

    def test_auth_hello_duplicate_is_idempotent(self):
        """A duplicate AUTH_HELLO (same id, not expired) re-issues the same nonce."""
        w = new_worker()
        try:
            info = R.pack_worker_info(104, R.ip_to_u32(HOST_IP), w.port, 1 << 29)
            r1 = R.unpack_auth_hello_reply(w.call(MASTER_ADDR, R.PROC_AUTH_HELLO, info)["payload"])
            r2 = R.unpack_auth_hello_reply(w.call(MASTER_ADDR, R.PROC_AUTH_HELLO, info)["payload"])
            assert r1["probe_data"] == r2["probe_data"]
        finally:
            w.close()

    def test_cap_ack_from_unknown_source(self):
        """A CAP_ACK from an ip:port that never sent AUTH_HELLO is rejected —
        registry lookup is by source address, not self-reported id."""
        w = new_worker()
        try:
            bad = w.call(MASTER_ADDR, R.PROC_CAP_ACK, R.pack_cap_ack(12345))
            assert bad is not None and bad["accept_stat"] == R.SYSTEM_ERR
        finally:
            w.close()

    def test_wrong_prog_unavail(self):
        """A CALL for an unexported program number gets PROG_UNAVAIL (RFC 5531 §9)."""
        w = new_worker()
        try:
            reply = w.call(MASTER_ADDR, R.PROC_AUTH_HELLO, b"", prog=0xDEADBEEF)
            assert reply is not None and reply["accept_stat"] == R.PROG_UNAVAIL
        finally:
            w.close()

    def test_unknown_proc_unavail(self):
        """PROC_NULL is not exported by the master -> PROC_UNAVAIL (RFC 5531 §12.1)."""
        w = new_worker()
        try:
            reply = w.call(MASTER_ADDR, R.PROC_NULL)
            assert reply is not None and reply["accept_stat"] == R.PROC_UNAVAIL
        finally:
            w.close()

    def test_bad_rpcvers_dropped(self):
        """rpcvers != 2 is a decode error on the master; it sends no reply
        (RFC 5531 §9). The host observes a timeout."""
        w = new_worker()
        try:
            reply = w.call(MASTER_ADDR, R.PROC_AUTH_HELLO, b"", rpcvers=3, timeout=1.5)
            assert reply is None, "master should not reply to a bad-rpcvers CALL"
        finally:
            w.close()

    def test_two_workers_ring_stitch(self):
        """When a second worker joins, the master stitches the ring: worker B's
        prev = worker A, and worker A is sent a PROC_SET_NEIGHBOR whose next = B.

        Ordering note (discovery.c:handle_cap_ack): the master notifies A of its
        new neighbor *before* replying to B's CAP_ACK, so we service A's
        SET_NEIGHBOR first, then read B's reply."""
        a = new_worker()
        b = new_worker()
        try:
            register_worker(a, 105)

            # Kick off B's registration to the point of the CAP_ACK, then send
            # the CAP_ACK without blocking so we can service A in between.
            info_b = R.pack_worker_info(106, R.ip_to_u32(HOST_IP), b.port, 1 << 29)
            hello_b = b.call(MASTER_ADDR, R.PROC_AUTH_HELLO, info_b)
            rep_b = R.unpack_auth_hello_reply(hello_b["payload"])
            xid_ack = b.next_xid()
            chk_b = R.cap_probe_checksum(rep_b["probe_seed"], rep_b["probe_pages"])
            b.sendto(R.encode_call(xid_ack, R.PROC_CAP_ACK,
                                   R.pack_cap_ack(rep_b["probe_data"], chk_b)),
                     MASTER_ADDR)

            # A receives PROC_SET_NEIGHBOR pointing next -> B; ACK it.
            call_a, src = a.recv(timeout=3.0)
            assert call_a is not None and call_a.get("proc") == R.PROC_SET_NEIGHBOR
            nb = R.unpack_set_neighbor(call_a["payload"])
            assert nb["next_ip"] == R.ip_to_u32(HOST_IP) and nb["next_port"] == b.port
            a.sendto(R.encode_reply(call_a["xid"], R.SUCCESS), src)

            # Now B's CAP_ACK reply lands: its prev = A.
            while True:
                msg, _ = b.recv(timeout=3.0)
                assert msg is not None, "no CAP_ACK reply for worker B"
                if msg.get("mtype") == R.MSG_REPLY and msg.get("xid") == xid_ack:
                    break
            ring_b = R.unpack_set_neighbor(msg["payload"])
            assert ring_b["prev_ip"] == R.ip_to_u32(HOST_IP) and ring_b["prev_port"] == a.port
        finally:
            a.close()
            b.close()

    @pytest.mark.skipif(not RUN_SLOW,
                        reason="natural expiry waits > EXPIRED_TIMEOUT; set DISTINF_SLOW=1")
    def test_expiry_emits_evict(self):
        """A worker that stops heartbeating past EXPIRED_TIMEOUT is evicted: the
        master sends it a PROC_EVICT. (The master runs expiry only when its recv
        loop wakes, so we poke it with a heartbeat from another id.)"""
        victim = new_worker()
        poker = new_worker()
        try:
            register_worker(victim, 107)
            # EXPIRED_TIMEOUT = HEARTBEAT_INTERVAL_TICKS*4 = 800 ticks = ~80 s.
            deadline = time.time() + 100
            saw_evict = False
            while time.time() < deadline and not saw_evict:
                # Poke the master loop so discovery_expire_workers runs.
                poker.sendto(R.encode_call(poker.next_xid(), R.PROC_HEARTBEAT,
                                           R.pack_cap_ack(999)), MASTER_ADDR)
                msg, _ = victim.recv(timeout=5.0)
                if msg and msg.get("mtype") == R.MSG_CALL and msg.get("proc") == R.PROC_EVICT:
                    saw_evict = True
            assert saw_evict, "expected PROC_EVICT after EXPIRED_TIMEOUT"
        finally:
            victim.close()
            poker.close()


# =======================================================================
# Role: worker-under-test  (xv6 = worker, host = synthetic master)
# =======================================================================
class SyntheticMaster:
    """Host-side master: accepts a worker's registration and tracks its address."""

    def __init__(self):
        self.peer = R.RpcPeer(local_port=MASTER_PORT, bind_ip=HOST_IP)
        self.worker_addr = None
        self.nonce = 0x1234

    def accept_registration(self, timeout=30.0):
        """Serve one AUTH_HELLO -> CAP_ACK handshake. Returns the worker addr."""
        deadline = time.time() + timeout
        got_hello = got_ack = False
        while time.time() < deadline and not (got_hello and got_ack):
            msg, src = self.peer.recv(timeout=timeout)
            if msg is None or msg.get("mtype") != R.MSG_CALL:
                continue
            proc = msg.get("proc")
            if proc == R.PROC_AUTH_HELLO:
                self.worker_addr = src
                self.peer.sendto(
                    R.encode_reply(msg["xid"], R.SUCCESS,
                                   R.pack_auth_hello_reply(R.WORKER_PENDING, self.nonce)), src)
                got_hello = True
            elif proc == R.PROC_CAP_ACK:
                # Ring: single worker points both ways at the master sentinel.
                ring = R.pack_set_neighbor(XV6_IP_U32, RING_SENTINEL_PORT,
                                           XV6_IP_U32, RING_SENTINEL_PORT)
                self.peer.sendto(R.encode_reply(msg["xid"], R.SUCCESS, ring), src)
                got_ack = True
        assert got_hello and got_ack, "worker did not complete registration"
        return self.worker_addr

    def close(self):
        self.peer.close()


@pytest.fixture(scope="class")
def registered_worker():
    if ROLE != "worker":
        pytest.skip("XV6_ROLE != worker")
    m = SyntheticMaster()
    addr = m.accept_registration(timeout=40.0)
    yield m, addr
    m.close()


@worker_only
class TestWorkerUnderTest:

    def test_worker_registers(self, registered_worker):
        """The worker completed the two-phase handshake against our master."""
        _m, addr = registered_worker
        assert addr is not None

    def test_worker_heartbeats(self, registered_worker):
        """The worker emits periodic PROC_HEARTBEAT keepalives."""
        m, _addr = registered_worker
        deadline = time.time() + 30   # one HEARTBEAT_INTERVAL is ~20 s
        while time.time() < deadline:
            msg, _ = m.peer.recv(timeout=30)
            if msg and msg.get("mtype") == R.MSG_CALL and msg.get("proc") == R.PROC_HEARTBEAT:
                return
        pytest.fail("no PROC_HEARTBEAT observed within one interval")

    def test_worker_set_neighbor(self, registered_worker):
        """The worker's listen thread accepts a ring update and ACKs SUCCESS."""
        m, addr = registered_worker
        payload = R.pack_set_neighbor(R.ip_to_u32(HOST_IP), MASTER_PORT,
                                      R.ip_to_u32(HOST_IP), MASTER_PORT)
        reply = m.peer.call(addr, R.PROC_SET_NEIGHBOR, payload, timeout=5.0)
        assert reply is not None and reply["accept_stat"] == R.SUCCESS

    def test_reregister_after_evict(self, registered_worker):
        """THE flow this pass implements: on PROC_EVICT the worker re-runs the
        full handshake. We evict it, then expect a fresh AUTH_HELLO."""
        m, addr = registered_worker
        # Evict (the listen thread ACKs and sets needs_reregister).
        m.peer.call(addr, R.PROC_EVICT, R.pack_cap_ack(1), timeout=5.0)

        # The heartbeat thread notices on its next interval (~20 s) and
        # re-registers via the pause/resume socket hand-off.
        deadline = time.time() + 40
        saw_rehello = False
        while time.time() < deadline and not saw_rehello:
            msg, src = m.peer.recv(timeout=40)
            if msg is None or msg.get("mtype") != R.MSG_CALL:
                continue
            if msg.get("proc") == R.PROC_AUTH_HELLO:
                # Complete the re-registration so the worker returns to ACTIVE.
                m.peer.sendto(
                    R.encode_reply(msg["xid"], R.SUCCESS,
                                   R.pack_auth_hello_reply(R.WORKER_PENDING, 0x5678)), src)
                saw_rehello = True
            elif msg.get("proc") == R.PROC_CAP_ACK:
                ring = R.pack_set_neighbor(XV6_IP_U32, RING_SENTINEL_PORT,
                                           XV6_IP_U32, RING_SENTINEL_PORT)
                m.peer.sendto(R.encode_reply(msg["xid"], R.SUCCESS, ring), src)
        assert saw_rehello, "worker did not re-register (no fresh AUTH_HELLO) after PROC_EVICT"
