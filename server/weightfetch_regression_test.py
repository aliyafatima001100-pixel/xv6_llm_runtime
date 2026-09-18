#!/usr/bin/env python3
"""
weightfetch_regression_test.py -- regression gate for LLM-RFTP range fetching and the
UDP bulk-flow admission class (L2/L3, increment I1).

This is the third host-feature gate, alongside kernel_regression_test.py (L1) and
net_regression_test.py (L2). It boots one xv6 node, starts the LLM-RFTP weight server
on the host, and drives the in-guest `shardspike` program over the serial console --
the same QEMU subprocess pattern as the kernel gate, so it needs no root and no tap.

Networking: QEMU user-mode SLIRP is placed on 10.0.0.0/24 with the host at 10.0.0.1.
That is the prefix xv6's static IP (10.0.0.2) and its BCP38 ingress filter already
expect, so the guest can reach a host service without a tap/bridge and without
relaxing any filtering rule.

Coverage (each row traces to the behaviour it pins down):

    case                    behaviour                        basis
    ---------------------   ------------------------------   ---------------------------
    range_digest_aligned    a chunk-aligned byte window is    RFC 768 (UDP checksum is
                            fetched byte-for-byte             what covers a partial
                                                              window; META_RESP's digest
                                                              is whole-file only)
    range_digest_unaligned  a window starting and ending      same, plus the head/tail
                            mid-chunk is trimmed correctly    trim in process_data_packet
    worker_absent_master    node bring-up: a worker whose    RFC 5531 §5 (timeout and
                            master is not listening fails    retransmission are the
                            cleanly, not with a trap         caller's responsibility)
    metered_without_bulk    an undeclared flow is still       local admission policy;
                            throttled by the token bucket     the default posture the
                            (UDP_RL_BURST, 1 token/tick)      existing net gate asserts

The third row is the control for the first two: it shows the transfer succeeds because
the flow was *declared* bulk, not because the rate limiter was weakened for everyone.

Run (from the xv6-project/ directory). --noconftest skips the net suite's autouse
fixture, which would demand root + a tap/echo setup this gate does not use:

    .venv/bin/python -m pytest server/weightfetch_regression_test.py -v --noconftest

Requires server/models/stories110M.bin (see README "Weight server"). The whole file is
skipped if it is absent, since it is ~418 MiB and not kept in the repository.
"""

import hashlib
import os
import select
import signal
import subprocess
import time

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
PROJ = os.path.dirname(HERE)
XV6_DIR = os.path.join(PROJ, "xv6-riscv")
MODEL = os.path.join(HERE, "models", "stories110M.bin")

# file id under which server.py serves stories110M.bin
FILE_WEIGHTS_110M = 3

MAKE_ENV = {**os.environ, "LAB": "net", "NETDEV": "user"}

QEMU_CMD = [
    "qemu-system-riscv64",
    "-machine", "virt", "-bios", "none", "-kernel", "kernel/kernel",
    "-m", "256M", "-smp", "3", "-nographic",
    "-global", "virtio-mmio.force-legacy=false",
    "-drive", "file=fs.img,if=none,format=raw,id=x0",
    "-device", "virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0",
    # See the module docstring: SLIRP on the prefix the kernel already trusts.
    "-netdev", "user,id=net0,net=10.0.0.0/24,host=10.0.0.1",
    "-device", "e1000,netdev=net0,bus=pcie.0",
]

BOOT_TIMEOUT = 90.0
PROMPT = "$ "

pytestmark = pytest.mark.skipif(
    not os.path.exists(MODEL),
    reason=f"{MODEL} not present (~418 MiB, fetched separately; see README)",
)


class Qemu:
    """A booted xv6 instance driven over its serial console."""

    def __init__(self):
        if not (os.path.isfile(os.path.join(XV6_DIR, "kernel", "kernel"))
                and os.path.isfile(os.path.join(XV6_DIR, "fs.img"))):
            subprocess.run(["make", "kernel/kernel", "fs.img"],
                           cwd=XV6_DIR, env=MAKE_ENV, check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
        self.proc = subprocess.Popen(
            QEMU_CMD, cwd=XV6_DIR, env=MAKE_ENV,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, start_new_session=True)
        self.buf = ""
        self._wait_for([PROMPT, "init: starting sh"], BOOT_TIMEOUT)

    def _drain(self, timeout):
        fd = self.proc.stdout.fileno()
        r, _, _ = select.select([fd], [], [], timeout)
        if r:
            chunk = os.read(fd, 65536)
            if chunk:
                self.buf += chunk.decode("utf-8", "replace")
                return True
        return False

    def _wait_for(self, markers, timeout):
        deadline = time.time() + timeout
        start = len(self.buf)
        while time.time() < deadline:
            self._drain(0.5)
            window = self.buf[start:]
            if any(m in window for m in markers):
                return window
        raise AssertionError(
            f"timed out after {timeout}s waiting for {markers!r}; recent output:\n"
            + self.buf[-1500:])

    def run(self, cmd, markers, timeout):
        """Send `cmd`, read until a marker appears; return the output either way."""
        start = len(self.buf)
        self.proc.stdin.write((cmd + "\n").encode())
        self.proc.stdin.flush()
        deadline = time.time() + timeout
        while time.time() < deadline:
            self._drain(0.5)
            window = self.buf[start:]
            if any(m in window for m in markers):
                return window
        return self.buf[start:]

    def close(self):
        try:
            self.proc.stdin.write(b"\x01x")
            self.proc.stdin.flush()
        except Exception:
            pass
        try:
            os.killpg(os.getpgid(self.proc.pid), signal.SIGKILL)
        except Exception:
            pass
        try:
            self.proc.wait(timeout=10)
        except Exception:
            pass


@pytest.fixture(scope="module")
def weight_server():
    """The LLM-RFTP server the guest fetches from."""
    proc = subprocess.Popen(
        [os.path.join(PROJ, ".venv", "bin", "python"), "server.py"],
        cwd=HERE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        start_new_session=True)
    time.sleep(3)
    if proc.poll() is not None:
        out = proc.stdout.read().decode("utf-8", "replace")
        pytest.fail(f"weight server failed to start:\n{out}")
    yield proc
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except Exception:
        pass


@pytest.fixture(scope="module")
def qemu(weight_server):
    q = Qemu()
    yield q
    q.close()


def host_digest(off, length):
    """SHA-256 of the same byte range, read straight from the checkpoint."""
    with open(MODEL, "rb") as f:
        f.seek(off)
        data = f.read(length)
    assert len(data) == length, f"host read {len(data)} of {length} bytes"
    return hashlib.sha256(data).hexdigest()


def guest_digest(out):
    for line in out.splitlines():
        if "sha256=" in line:
            return line.split("sha256=")[1].strip()
    return None


# (id, byte_off, byte_len) -- 512 is CHUNK_SIZE, so offset 1000 starts mid-chunk
# and the length leaves the tail chunk partial too.
RANGES = [
    ("range_digest_aligned", 512, 65536),
    ("range_digest_unaligned", 1000, 65536 + 137),
]


@pytest.mark.parametrize("case,off,length", RANGES, ids=[r[0] for r in RANGES])
def test_range_fetch_is_byte_exact(qemu, case, off, length):
    """A fetched byte window matches the same range hashed on the host."""
    out = qemu.run(
        f"shardspike {FILE_WEIGHTS_110M} {off} {length} 10.0.0.1 {case}",
        ["shardspike: OK", "FAIL", "Transfer failed"], timeout=180)

    assert "shardspike: OK" in out, f"fetch did not complete:\n{out[-1200:]}"
    assert guest_digest(out) == host_digest(off, length), (
        f"digest mismatch for [{off},{off+length}):\n{out[-1200:]}")


def test_undeclared_flow_is_rate_limited(qemu):
    """
    Control case: the same fetch without the bulk declaration is metered.

    The per-source token bucket (UDP_RL_BURST tokens, one refilled per tick) admits
    roughly ten datagrams a second, so a 64-chunk window either fails outright or
    is still unfinished long after the declared-flow version completed in seconds.
    This is what proves the two rows above pass because the flow was *declared*,
    not because the limiter was weakened for everyone.
    """
    out = qemu.run(
        f"shardspike {FILE_WEIGHTS_110M} 512 32768 10.0.0.1 nobulk 0",
        ["shardspike: OK", "FAIL", "Transfer failed"], timeout=45)

    assert "bulk flow declaration off" in out, f"control case misconfigured:\n{out[-800:]}"
    assert "shardspike: OK" not in out, (
        "an undeclared flow completed at full speed -- the UDP rate limiter is not "
        f"metering unsolicited traffic any more:\n{out[-1200:]}")


def test_worker_survives_absent_master(qemu):
    """
    Node bring-up: a worker started before its master must fail cleanly.

    This is the order nodes are actually launched in, and it used to end in a
    store page fault: the RPC wire buffers were automatic, so
    discovery_register -> rpc_call -> rpc_recv held ~13 KB of them at once and
    consumed 15,392 of the 16 KB user stack, leaving the next printf to fault in
    the guard page (the address tracked the stack-ASLR gap run to run). The
    buffers now live in static storage.

    Checks performed:
      1. The registration attempt reports the RPC timeout (RFC 5531 §5 retry
         budget exhausted) rather than succeeding against a phantom master.
      2. No trap: `scause` must not appear: a usertrap here means the guard page
         was hit again.
      3. The shell prompt returns, i.e. the process exited rather than hanging.
    """
    out = qemu.run("distinf --worker 10.0.0.1 5499 1",
                   ["registration failed", "scause"], timeout=60)

    assert "scause" not in out, f"worker trapped instead of failing cleanly:\n{out[-1200:]}"
    assert "registration failed" in out, f"no clean failure reported:\n{out[-1200:]}"
