#!/usr/bin/env python3
"""
kernel_regression_test.py -- regression gate for the xv6 process-isolation hardening.

This is the host-feature sibling of net_regression_test.py: where that suite injects
packets over a tap interface and checks the wire behaviour, this one boots xv6 under
QEMU, drives the shell over the serial console (the QEMU subprocess pattern from
xv6-riscv/test-xv6.py), runs the in-guest test programs, and asserts on their console
output -- the same parametrized "one row per behaviour" structure.

Coverage (each row traces to a ratified standard, mirrored against a POSIX host):

    case               feature                         standard / host differential
    ----------------   -----------------------------   -----------------------------
    canary             stack-smashing protection       RISC-V psABI + SSP/StackGuard;
                                                        same GCC -fstack-protector PoC
    mem_rlimit_as      per-process address-space cap    IEEE Std 1003.1-2017 RLIMIT_AS;
                                                        `ulimit -v`
    mem_inherit        RLIMIT_AS inherited across fork  IEEE Std 1003.1-2017 fork()
    exec_rlimit        RLIMIT_AS bounds exec()'s image  IEEE Std 1003.1-2017 RLIMIT_AS
    cpu_rlimit         per-process CPU-time cap         IEEE Std 1003.1-2017 RLIMIT_CPU;
                                                        `ulimit -t`
    cpu_sleep          CPU cap charges consumed CPU,    IEEE Std 1003.1-2017 RLIMIT_CPU
                       not wall time (sleep survives)
    cap_rlimit         CAP_SYS_RESOURCE gates raising   IEEE Std 1003.1-2017 setrlimit +
                       a hard limit (POSIX [EPERM])     POSIX.1e capabilities
    getentropy         entropy syscall + per-exec       IEEE Std 1003.1-2024 getentropy;
                       canary randomization             getentropy(3)
    thread_stack       per-thread stack > 1 page +      guard-page invariant, as
                       guard page (no silent overflow)  exec() builds for main
    stack_aslr         stack base varies across execs   Linux randomize_stack_top()
    wx_reject          exec refuses a non-exempt W+X     OpenBSD W^X + PT_OPENBSD_WXNEEDED
                       binary (wxneeded exemption)
    id_priv            uid/euid/suid + drop-root clears  IEEE Std 1003.1-2017 setuid/seteuid
                       the resource capability
    usertests          no regression with SSP on        existing xv6 test corpus

Run (from the xv6-project/ directory; no root/tap needed -- user-mode networking).
--noconftest skips the net suite's conftest.py, whose autouse fixture would otherwise
demand root + a tap/echo setup these host-feature tests do not use:

    .venv/bin/python -m pytest server/kernel_regression_test.py -v --noconftest

Set KERNEL_TEST_SKIP_USERTESTS=1 to skip the slow usertests row.
"""

import os
import select
import signal
import subprocess
import time

import pytest

# xv6-riscv tree (where `make` and the kernel/fs.img artifacts live).
HERE = os.path.dirname(os.path.abspath(__file__))
XV6_DIR = os.path.join(os.path.dirname(HERE), "xv6-riscv")

# Build with LAB=net so the kernel and the e1000 device agree (the kernel is compiled
# with networking); NETDEV=user keeps it root-free (no tap interface).
MAKE_ENV = {**os.environ, "LAB": "net", "NETDEV": "user"}

# We launch QEMU directly rather than via `make qemu`: the net lab's target adds host
# UDP port-forwarding (hostfwd) + a packet dump, and the fixed forwarding ports collide
# with any other instance / the echo server, killing the VM before it boots. These
# host-feature tests need neither, so we keep the e1000 device (the kernel's netinit
# expects it) but drop hostfwd/filter-dump -- no port conflict, no root, no pcap.
QEMU_CMD = [
    "qemu-system-riscv64",
    "-machine", "virt", "-bios", "none", "-kernel", "kernel/kernel",
    "-m", "256M", "-smp", "3", "-nographic",
    "-global", "virtio-mmio.force-legacy=false",
    "-drive", "file=fs.img,if=none,format=raw,id=x0",
    "-device", "virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0",
    "-netdev", "user,id=net0",
    "-device", "e1000,netdev=net0,bus=pcie.0",
]

BOOT_TIMEOUT = 60.0   # seconds to reach the shell prompt
PROMPT = "$ "


class Qemu:
    """A booted xv6 instance driven over its serial console."""

    def __init__(self):
        # Build the kernel + filesystem image first (uses the Makefile, so the SSP flag
        # flip and the new user programs are all picked up).
        if not (os.path.isfile(os.path.join(XV6_DIR, "kernel", "kernel"))
                and os.path.isfile(os.path.join(XV6_DIR, "fs.img"))):
            subprocess.run(["make", "kernel/kernel", "fs.img"],
                           cwd=XV6_DIR, env=MAKE_ENV, check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
        self.proc = subprocess.Popen(
            QEMU_CMD,
            cwd=XV6_DIR,
            env=MAKE_ENV,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,   # own process group, so we can kill QEMU cleanly
        )
        self.buf = ""
        self._wait_for(PROMPT, "init: starting sh", timeout=BOOT_TIMEOUT)

    def _drain(self, timeout):
        """Append whatever bytes QEMU has produced within `timeout` seconds."""
        fd = self.proc.stdout.fileno()
        r, _, _ = select.select([fd], [], [], timeout)
        if r:
            chunk = os.read(fd, 4096)
            if chunk:
                self.buf += chunk.decode("utf-8", "replace")
                return True
        return False

    def _wait_for(self, *markers, timeout):
        """Read until any marker appears in fresh output, or raise on timeout."""
        # `timeout` is keyword-only here via the call sites below.
        deadline = time.time() + timeout
        start = len(self.buf)
        while time.time() < deadline:
            self._drain(0.5)
            window = self.buf[start:]
            for m in markers:
                if m and m in window:
                    return window
        raise AssertionError(
            f"timed out after {timeout}s waiting for {markers!r}; recent output:\n"
            + self.buf[-1500:]
        )

    def run(self, cmd, markers, timeout):
        """Send `cmd`, then read until one of `markers` shows up; return that output."""
        marks = markers if isinstance(markers, (list, tuple)) else [markers]
        start = len(self.buf)
        self.proc.stdin.write((cmd + "\n").encode())
        self.proc.stdin.flush()
        deadline = time.time() + timeout
        while time.time() < deadline:
            self._drain(0.5)
            window = self.buf[start:]
            if any(m in window for m in marks):
                return window
        return self.buf[start:]   # let the caller's assertion report the miss

    def close(self):
        # Ctrl-A x asks QEMU to quit; then kill the whole process group as a backstop.
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
def qemu():
    q = Qemu()
    yield q
    q.close()


# --- cases -------------------------------------------------------------------
# (id, command, expect, forbid, timeout)
#   expect : substring proving the feature worked
#   forbid : substring proving it did NOT (a test program's "FAIL" line)
CASES = [
    # Phase 1: the user-space canary trips on a deliberate overflow.
    # Per-thread stack: a thread must get more than one page, and a frame larger
    # than the old single-page stack must not collide with the heap or another
    # thread's stack. thread_create() maps THREAD_STACK_PAGES pages plus a guard
    # page, the shape exec() already builds for the main thread.
    ("thread_stack", "threadstack",
     "threadstack: OK", "FAIL", 20),

    ("canary", "canarytest",
     "stack smashing detected", "FAIL", 15),

    # Phase 2: RLIMIT_AS refuses growth (eager + lazy) at the cap instead of OOMing.
    ("mem_rlimit_as", "rlimittest mem",
     "mem OK", "FAIL", 20),

    # Phase 2: the limit is inherited across fork().
    ("mem_inherit", "rlimittest fork",
     "fork OK", "FAIL", 20),

    # Phase 2: RLIMIT_AS also bounds exec() -- a capped process cannot escape its limit
    # by exec'ing a larger binary (regression for the exec bypass).
    ("exec_rlimit", "rlimittest exec",
     "exec OK", "FAIL", 20),

    # Phase 3: a spinning child is killed at its CPU-time limit (parent reaps it).
    ("cpu_rlimit", "rlimittest cpu",
     "cpu OK", "FAIL", 20),

    # Phase 3: RLIMIT_CPU charges consumed CPU, not wall time -- a sleeping capped child
    # is not killed.
    ("cpu_sleep", "rlimittest cpusleep",
     "cpusleep OK", "FAIL", 20),

    # Capabilities: after capdrop(CAP_SYS_RESOURCE) a process can no longer raise its
    # hard limit (POSIX [EPERM]) -- the rlimit becomes a real confinement boundary.
    ("cap_rlimit", "rlimittest cap",
     "cap OK", "FAIL", 20),

    # getentropy() (POSIX.1-2024): exact-length fills, no buffer overrun, boundary/error
    # rejection, and distinct non-zero draws.
    ("getentropy", "randtest",
     "rand OK", "FAIL", 15),

    # W^X (OpenBSD model): exec refuses a writable+executable binary (wxbad) that lacks the
    # PT_OPENBSD_WXNEEDED exemption. (forktest -- W+X but wxneeded-tagged -- runs under
    # usertests, exercising the exempt path.)
    ("wx_reject", "wxtest",
     "wx OK", "FAIL", 15),

    # POSIX uid/euid/suid: default root; setuid(1000) drops the identity and the resource
    # capability (raise refused, no regain); seteuid save/restore; fork inherits.
    ("id_priv", "idtest",
     "id OK", "FAIL", 20),
]


@pytest.mark.parametrize("name,cmd,expect,forbid,timeout",
                         CASES, ids=[c[0] for c in CASES])
def test_case(qemu, name, cmd, expect, forbid, timeout):
    out = qemu.run(cmd, [expect, forbid], timeout)
    assert forbid not in out, f"{name}: saw failure marker in:\n{out}"
    assert expect in out, f"{name}: expected {expect!r}, got:\n{out}"


def test_canary_per_exec(qemu):
    """The user stack canary is re-seeded on every exec (crt0 -> getentropy): two runs of
    the same program must print different guard values."""
    import re

    def read_guard():
        # randtest prints "canary=<hex>;"; wait for the ';' so the full value is buffered.
        out = qemu.run("randtest guard", [";"], 15)
        m = re.search(r"canary=([0-9a-fA-F]+);", out)
        assert m, f"no canary line in:\n{out}"
        return m.group(1)

    g1 = read_guard()
    g2 = read_guard()
    assert g1 != g2, f"user canary not randomized per exec: {g1} == {g2}"


def test_stack_aslr(qemu):
    """Stack-base ASLR (kernel/exec.c): the user stack does not start at a fixed address.
    The offset is page-granular, so read three runs and require they are not all equal
    (a single collision has ~1/2**STACK_RND_BITS odds; all three colliding is negligible)."""
    import re

    def read_sp():
        out = qemu.run("aslrtest", [";"], 15)
        m = re.search(r"sp=0x([0-9a-fA-F]+);", out)
        assert m, f"no sp line in:\n{out}"
        return m.group(1)

    addrs = {read_sp() for _ in range(3)}
    assert len(addrs) > 1, f"stack address never varied across execs: {addrs}"


@pytest.mark.skipif(os.environ.get("KERNEL_TEST_SKIP_USERTESTS") == "1",
                    reason="usertests skipped via KERNEL_TEST_SKIP_USERTESTS=1")
def test_usertests_clean(qemu):
    """The whole xv6 test corpus still passes with SSP + rlimits enabled."""
    out = qemu.run("usertests -q", ["ALL TESTS PASSED", "FAILED"], 300)
    assert "FAILED" not in out, f"usertests regressed:\n{out[-2000:]}"
    assert "ALL TESTS PASSED" in out, f"usertests did not finish:\n{out[-2000:]}"
