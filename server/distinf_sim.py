#!/usr/bin/env python3
"""
distinf_sim.py -- boot and drive a DistInf ring: the distributed-inference simulation.

Runs a master and N workers (N up to 5) as separate QEMU machines on one Ethernet
segment, drives each over its serial console, and checks the bring-up milestones
in order: registration -> layer assignment -> shard fetch -> per-token ring
traversal -> sampled output. Optionally kills a node mid-generation to exercise
the ring's fault tolerance, and prints a run summary at the end either way.

**No privilege required.** The nodes are connected with QEMU multicast socket
networking (`-netdev socket,mcast=...`), which forms a shared L2 segment over a
UDP multicast group -- no tap, no bridge, no root. The host joins the same segment
as the weight server via `mcast_switch.py`, so the whole simulation is root-free.
(A tap bridge, `make bridge-setup`, is the alternative and needs sudo; the mcast
path exists so this can run anywhere.)

Topology:

    host (mcast_switch)  10.0.0.1   weight server (LLM-RFTP over the segment)
    master               10.0.0.2   embedding + final norm + classifier + sampler
    worker k             10.0.0.2+k  a contiguous range of transformer layers

Each node needs its own kernel build (XV6_IP_D / XV6_MAC_LAST are compile-time)
and its own fs.img (QEMU write-locks the image), so images are built once up front.

Usage:
    python3 server/distinf_sim.py --workers 5 --model 1 --steps 32 \\
        --prompt "Once upon a time"

    # kill worker 3 once four tokens are done; the ring must reform and finish
    python3 server/distinf_sim.py --workers 5 --kill-worker 3 --kill-at-token 4

Exit status is 0 only if every milestone was observed and the generated token
stream was recovered.

**Two nodes may not share the segment concurrently.** The multicast group and the
MACs are fixed, so two overlapping runs collide on duplicate MACs and the weight
fetch stalls in a way that looks exactly like a code bug. Before each run:

    pkill -f qemu-system-riscv64; pkill -f mcast_switch.py
"""

import argparse
import json
import os
import re
import select
import shutil
import signal
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
PROJ = os.path.dirname(HERE)
XV6 = os.path.join(PROJ, "xv6-riscv")
VENV_PY = sys.executable   # interpreter running this script; activate .venv first

MCAST = "230.0.0.1:5678"
MASTER_PORT = 5499
HOST_IP = "10.0.0.1"
MASTER_IP = "10.0.0.2"

# (ip_last_octet, mac_last_octet) per node, matching the qemu-node1..qemu-node6
# build flags in the Makefile. Index 0 is the master, so this caps the run at
# five workers -- add a qemu-node7 target and an entry here to go further.
NODE_IDS = [(2, "0x56"), (3, "0x57"), (4, "0x58"),
            (5, "0x59"), (6, "0x5a"), (7, "0x5b")]

# Transformer layers per LLM-RFTP file id. Only used for an up-front warning:
# the master refuses an assignment with more workers than layers
# (discovery.c:discovery_assign_one), and finding that out twenty minutes into a
# run -- after every image is built and every shard fetched -- is a poor way to
# learn it. The master remains the authority.
MODEL_LAYERS = {1: 6, 3: 12}
MODEL_NAMES = {1: "stories15M", 3: "stories110M"}

# Ways a worker can be told to misbehave, and what the cluster should do about it.
#
# `refused` is the part the rest of the sim has to know: a node the master
# rejects never becomes ACTIVE, and run_master blocks in `while (n <
# want_workers)` counting ACTIVE workers -- so the quota the master is started
# with must exclude it, and its rejection has to be scored as the pass rather
# than as a failed registration.
#
# `flags` is what gets appended to that worker's command line; `{v}` takes the
# spec's value.
#
# `lie-ram` takes `CLAIM[/REAL]`, both in MB, and the two forms test opposite
# things. The master probes only up to CAP_PROBE_CEILING_BYTES (32 MB), so it
# can only ever verify "has at least min(claim, 32 MB)":
#
#   lie-ram:1024/16  the node claims 1024 MB and can genuinely back 16 MB, which
#                    is *below* the ceiling -- the probe it is asked to satisfy
#                    is larger than its budget, the allocation fails for real,
#                    and it is refused. This is the lie the design catches.
#   lie-ram:1024     the node claims 1024 MB and can back the usual 512 MB. The
#                    probe asks for 32 MB, which it has, so it is ACCEPTED --
#                    the documented ceiling deviation, and not a defect in the
#                    probe so much as a limit on what a bounded probe can mean.
ADVERSARY_MODES = {
    "lie-ram":  {"refused": None,  "needs_value": True},   # depends on the value
    "signflip": {"refused": False, "flags": "--corrupt signflip",  "needs_value": False},
    "zero":     {"refused": False, "flags": "--corrupt zero",      "needs_value": False},
    "delta":    {"refused": False, "flags": "--corrupt delta {v}", "needs_value": True},
}

# The probe ceiling, mirrored from user/discovery.h. A lie is only detectable
# when the node's real budget is under it.
CAP_PROBE_CEILING_MB = 32

BUILD_ENV = {**os.environ, "LAB": "net", "NETDEV": "user"}

# Console lines that share the serial port with the generated token pieces.
# Matched to end of line and stripped mid-line too, because a piece is printed
# without a trailing newline (safe_printf) and so shares its line with whatever
# the kernel prints next.
#
# The colon is required: "worker", "shard" and "send" are ordinary English words
# the model can generate, and an alternation loose enough to match them bare
# would eat real token text.
#
# The list is every log prefix reachable on a node's console during a run -- the
# kernel plus the sources linked into _distinf -- rather than the handful seen so
# far. A fault run reaches parts of the kernel a clean one never does: killing
# the *tail* leaves its predecessor ARP-ing an address nobody answers for, and
# `arp_lookup:` / `sys_send:` landed in the middle of the token stream. Missing a
# prefix does not corrupt anything silently; it shows up as a golden-text
# mismatch. Regenerate after adding a log line:
#
#   grep -rhoE '(printf|panic)\("[a-z_]+:' kernel/*.c user/{distinf,discovery,
#       rpc,xdr,shard,llama_core,perf,ftpclient,...}.c | sed -E 's/.*"([a-z_]+):/\1/' | sort -u
NOISE_RE = re.compile(
    r"(?:arp_lookup|arp_send_request|balloc|bget|bmap|discovery_register|"
    r"discovery_listen|freewalk|heartbeat|ialloc|iget|ilock|init|initlog|ip_rx|"
    r"ireclaim|isdirempty|kerneltrap|loadseg|mappages|master|panic|perf|"
    r"rpc_recv|rpc_send|rwspinlock_test|send|shard|sys_send|thread_create|"
    r"threadstack|_udp_recv|unlink|usage|usertrap|uvmunmap|worker):[^\n]*")


class SimError(Exception):
    """A milestone that could not be reached; aborts the run but still summarises."""


class Node:
    """One xv6 instance on the multicast segment, driven over its serial console."""

    def __init__(self, name, build_dir, mac, logpath, smp=8, binary="kernel"):
        self.name = name
        self.buf = ""
        self.logpath = logpath
        self.log = open(logpath, "w")
        self.state = "running"      # running | killed | paused
        self.proc = subprocess.Popen(
            ["qemu-system-riscv64", "-machine", "virt", "-bios", "none",
             "-kernel", os.path.join(build_dir, "kernel"),
             "-m", "256M", "-smp", str(smp), "-nographic",
             "-global", "virtio-mmio.force-legacy=false",
             "-drive", f"file={os.path.join(build_dir, 'fs.img')},if=none,format=raw,id=x0",
             "-device", "virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0",
             "-netdev", f"socket,id=n0,mcast={MCAST}",
             "-device", f"e1000,netdev=n0,mac={mac},bus=pcie.0"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, start_new_session=True)

    def pump(self, timeout=0.2):
        """Drain whatever is on the console. Returns the byte count read."""
        if self.state == "killed":
            return 0
        fd = self.proc.stdout.fileno()
        r, _, _ = select.select([fd], [], [], timeout)
        if not r:
            return 0
        chunk = os.read(fd, 65536)
        if not chunk:
            return 0
        text = chunk.decode("utf-8", "replace")
        self.buf += text
        self.log.write(text)
        self.log.flush()
        return len(chunk)

    def send(self, cmd):
        self.proc.stdin.write((cmd + "\n").encode())
        self.proc.stdin.flush()

    def fault(self, mode):
        """
        Take the node out of the ring.

        `crash` SIGKILLs the process group -- the node vanishes, its socket dies
        with it. `pause` SIGSTOPs it, modelling a node that is still present on
        the segment but has stopped answering; the master can only notice that
        one through heartbeat expiry, so it exercises the lifecycle rather than
        an abrupt transport failure.
        """
        sig = signal.SIGKILL if mode == "crash" else signal.SIGSTOP
        os.killpg(os.getpgid(self.proc.pid), sig)
        self.state = "killed" if mode == "crash" else "paused"

    def close(self):
        for fn in (lambda: os.killpg(os.getpgid(self.proc.pid), signal.SIGKILL),
                   lambda: self.proc.wait(timeout=5), self.log.close):
            try:
                fn()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Console pumping
#
# Every wait pumps *every* node, not just the one being waited on. This is not
# tidiness: a QEMU whose stdout pipe fills its 64 KB kernel buffer blocks on the
# next write, so draining only the awaited console silently freezes the master
# for the whole wait -- which then looks like the master hanging.
# ---------------------------------------------------------------------------

def pump_all(nodes, timeout=0.05):
    return sum(n.pump(timeout) for n in nodes)


def wait_for_on(target, nodes, markers, timeout, label="", stall=None, after=0):
    """
    Wait for any of `markers` on `target`'s console, pumping all of `nodes`.

    `after` is an offset into the console buffer to search from, so a retry does
    not immediately re-match the previous attempt's output. `stall` (seconds) is
    a secondary watchdog: if *no* node emits a byte for that long the wait gives
    up early, since a segment that has gone completely quiet is not going to
    produce the marker by burning the rest of the budget. Returns the matched
    marker, or None on timeout.

    Checks performed:
      1. Every node is pumped on each pass, not just `target`. A QEMU whose
         stdout pipe fills its 64 KB kernel buffer blocks on the next write, so
         draining one console silently freezes every other node for the whole
         wait -- which then presents as the master hanging.
      2. Markers are searched from `after`, so output left over from a previous
         attempt cannot satisfy this one.
      3. The stall watchdog fires only on total silence across the segment; one
         chatty node is enough to keep the wait alive, which is correct, since
         a shard fetch is quiet on the console that is waiting.
    """
    deadline = time.time() + timeout
    last_output = time.time()
    while time.time() < deadline:
        if pump_all(nodes):
            last_output = time.time()
        for m in markers:
            if target.buf.find(m, after) >= 0:
                return m
        if stall and time.time() - last_output > stall:
            print(f"  [{target.name}] STALLED -- no console output from any node "
                  f"for {stall}s while waiting for {label or markers}")
            return None
    print(f"  [{target.name}] TIMEOUT after {timeout}s waiting for {label or markers}")
    print(f"  [{target.name}] tail: {target.buf[-600:]}")
    return None


# ---------------------------------------------------------------------------
# Build / boot
# ---------------------------------------------------------------------------

# The Milestone 1 handoff ships the kernel as a prebuilt binary, not its source,
# so the per-node images cannot be compiled here. They were built once, up front,
# one kernel per (XV6_IP_D / XV6_MAC_LAST) entry in NODE_IDS under prebuilt/node<i>/.
# The fs.img is identical for every node, so a single shared copy lives at
# prebuilt/fs.img. `stage_node` assembles node i's image in the run's working dir.
PREBUILT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "prebuilt")


def stage_node(index, build_dir):
    """Copy the prebuilt kernel for node `index` plus the shared fs.img into build_dir."""
    kernel = os.path.join(PREBUILT, f"node{index}", "kernel")
    fs_img = os.path.join(PREBUILT, "fs.img")
    if not os.path.isfile(kernel):
        raise SimError(
            f"no prebuilt kernel for node{index} at {kernel}. This handoff ships "
            f"{len(NODE_IDS)} prebuilt node kernels (master + up to "
            f"{len(NODE_IDS) - 1} workers); ask for more if you need a larger ring.")
    os.makedirs(build_dir, exist_ok=True)
    shutil.copy(kernel, os.path.join(build_dir, "kernel"))
    shutil.copy(fs_img, os.path.join(build_dir, "fs.img"))


def build_all(args, stats):
    n_nodes = args.workers + 1
    print(f"[sim] staging {n_nodes} prebuilt node image(s)...", flush=True)
    t0 = time.time()
    for i in range(n_nodes):
        stage_node(i, os.path.join(args.outdir, f"node{i}"))
    stats["build_s"] = time.time() - t0
    stats["images"] = n_nodes


def boot_all(args, stats, nodes):
    """
    Boot every node, then wait for each to reach its shell.

    Booting is fired for all nodes before waiting for any: they are independent
    machines, and serialising the waits would add each node's boot time to the
    next one's rather than overlapping them. Nodes are appended to the caller's
    list as they are spawned, so a boot failure still leaves every already-started
    QEMU reachable for teardown.

    Checks performed:
      1. Every node reaches "init: starting sh"; a node that does not is fatal,
         since the master is launched with a fixed worker count and cannot form
         a ring around a machine that never booted.
      2. The budget scales with node count -- six QEMUs contend for the same
         cores, so a fixed timeout sized for three would fail spuriously.
      3. Nodes are registered with the caller before any wait, so teardown
         reaches them even when this raises.
    """
    n_nodes = args.workers + 1
    boot_timeout = args.boot_timeout or (120 + 40 * n_nodes)
    print(f"[sim] booting {n_nodes} node(s) (timeout {boot_timeout}s each)...", flush=True)

    for i in range(n_nodes):
        ip_last, mac_last = NODE_IDS[i]
        name = "master" if i == 0 else f"worker{i}"
        mac = f"52:54:00:12:{mac_last[2:]}:56"
        nodes.append(Node(name, os.path.join(args.outdir, f"node{i}"), mac,
                          os.path.join(args.outdir, f"{name}.log"), smp=args.smp))

    t0 = time.time()
    for n in nodes:
        if wait_for_on(n, nodes, ["init: starting sh"], boot_timeout,
                       "boot", stall=args.stall_timeout) is None:
            raise SimError(f"{n.name} did not boot within {boot_timeout}s")
        stats["boot_s"][n.name] = time.time() - t0


# ---------------------------------------------------------------------------
# Bring-up phases
# ---------------------------------------------------------------------------

def lie_ram_parts(value):
    """`CLAIM[/REAL]` in MB -> (claim, real_or_None)."""
    claim, _, real = value.partition("/")
    return int(claim), (int(real) if real else None)


def worker_flags(args, idx):
    """The misbehaviour flags for worker `idx`, or "" if it is honest."""
    spec = args.adversary_spec.get(idx)
    if not spec:
        return ""
    mode, value = spec
    if mode == "lie-ram":
        claim, real = lie_ram_parts(value)
        return f" --claim-ram {claim}" + (f" --real-ram {real}" if real else "")
    return " " + ADVERSARY_MODES[mode]["flags"].format(v=value)


def expect_refused(mode, value):
    """
    Whether the master should refuse this node at registration.

    For `lie-ram` the answer is a property of the numbers, not the mode: the
    probe asks for min(claim, ceiling), so the node is refused only when the
    budget it can really back falls short of that -- i.e. when a real budget was
    given and it is under the ceiling. A large claim backed by an ordinary budget
    is accepted, and a test that expected otherwise would be asserting a defence
    the bounded probe does not provide.
    """
    if mode != "lie-ram":
        return bool(ADVERSARY_MODES[mode]["refused"])
    claim, real = lie_ram_parts(value)
    return real is not None and real < min(claim, CAP_PROBE_CEILING_MB)


def refused_workers(args):
    """Worker indices the master is expected to refuse at registration."""
    return [i for i, (mode, value) in args.adversary_spec.items()
            if expect_refused(mode, value)]


def start_master(args, nodes, stats):
    """
    Launch the master, told how many workers to expect.

    Checks performed:
      1. The expected count excludes any node the master is meant to REFUSE.
         run_master blocks in `while (n < want_workers)` counting ACTIVE workers,
         and a refused node never becomes ACTIVE -- counting it here would hang
         the run before a single token, reported only as a timeout with no
         indication that the topology was impossible from the start.
      2. The master is confirmed listening before any worker starts, so the first
         handshake cannot be sent into a closed port.
    """
    master = nodes[0]
    expect = args.workers - len(refused_workers(args))
    note = "" if expect == args.workers else f" ({args.workers - expect} expected refused)"
    print(f"[sim] master: expecting {expect} worker(s){note}, model {args.model} "
          f"({MODEL_NAMES.get(args.model, '?')}), {args.steps} tokens", flush=True)
    master.send(f'distinf --master {MASTER_PORT} {expect} {args.model} '
                f'"{args.prompt}" {args.steps} {HOST_IP}')
    if wait_for_on(master, nodes, ["waiting for"], 60, "master listening",
                   stall=args.stall_timeout) is None:
        raise SimError("master did not start listening")


def register_serially(args, nodes, stats):
    """
    Start the workers one at a time, each fully registered before the next.

    This is a requirement, not a stylistic choice. The master is single-threaded,
    and `handle_cap_ack` makes a *blocking* `discovery_notify_neighbor` ->
    `rpc_call` to the previous tail while it is inside the pump. An AUTH_HELLO or
    CAP_ACK arriving during that window is consumed by that call's receive and
    discarded as a non-matching xid, and a registering worker only has
    RPC_MAX_RETRIES (3) x RPC_TIMEOUT_MS (500 ms) = 1.5 s of budget before it
    gives up with `discovery_register: rpc_call failed`. Start five workers at
    once and the later ones lose that race.

    A worker that fails is retried once -- a genuinely lost handshake datagram is
    exactly what the RPC retry budget cannot cover -- and then fatal regardless
    of --strict, because the master's `want_workers` is fixed at launch: it will
    block in its registration loop forever waiting for a worker that will never
    arrive, so there is no reduced topology to fall back to.

    Checks performed, per worker:
      1. "registration successful" appears on that worker's console before the
         next worker is started, which is what serialises the handshakes.
      2. The failure line is watched for alongside the success line, so a
         rejected handshake retries at once instead of burning the full budget
         first -- the worker prints it and exits straight back to the shell.
      3. Both markers are matched only after this attempt's offset, so the
         previous attempt's output cannot be mistaken for this one's.
      4. Two attempts, then fatal (see above -- there is no smaller ring to
         fall back to once the master has been told how many to expect).
      5. A quiet gap follows each success, so the master is back in its pump
         loop rather than still completing the previous stitch.
      6. For a node whose misbehaviour should get it REFUSED, the test inverts:
         rejection is the pass and acceptance is a hard failure. A liar that got
         in would mean the capability probe did not hold, which must never be
         reported as a successful registration.
      7. A refused node is dropped from the list handed to the later phases. It
         is never assigned layers and never loads a shard, so leaving it in
         would time out a phase that in fact succeeded.
    """
    workers = nodes[1:]
    for i, w in enumerate(workers, start=1):
        t0 = time.time()
        spec = args.adversary_spec.get(i)          # None for an honest worker
        expect_refusal = bool(spec) and expect_refused(*spec)
        cmd = f"distinf --worker {MASTER_IP} {MASTER_PORT} {i}" + worker_flags(args, i)

        for attempt in (1, 2):
            mark = len(w.buf)
            w.send(cmd)
            # Watch for the failure lines too, not just success: on a rejected
            # handshake the worker prints one and exits straight back to the
            # shell, so waiting out the full budget would waste two minutes
            # before a retry that could start immediately.
            got = wait_for_on(w, nodes,
                              ["registration successful", "registration failed",
                               "cap test failed", "master rejected"],
                              args.register_timeout, f"{w.name} registration",
                              stall=args.stall_timeout, after=mark)

            if expect_refusal:
                if got is not None and got != "registration successful":
                    stats["adversaries"].append(
                        {"worker": w.name, "mode": spec[0], "value": spec[1],
                         "outcome": "refused at registration"})
                    print(f"[sim] OK  {w.name} [{spec[0]}] REFUSED by the master "
                          f"-- {got}", flush=True)
                    break
                raise SimError(
                    f"{w.name} claimed RAM it cannot back and was ACCEPTED "
                    f"(got {got!r}) -- the capability probe did not hold")

            if got == "registration successful":
                break
            if attempt == 1:
                print(f"[sim] WARN {w.name} did not register ({got or 'timeout'}), "
                      f"retrying once", flush=True)
        else:
            raise SimError(f"{w.name} failed to register after 2 attempts")

        stats["register_s"][w.name] = time.time() - t0
        if expect_refusal:
            continue
        if spec:
            stats["adversaries"].append(
                {"worker": w.name, "mode": spec[0], "value": spec[1],
                 "outcome": "joined the ring"})
        suffix = f"  [{spec[0]}]" if spec else ""
        print(f"[sim] OK  {w.name} registered "
              f"({stats['register_s'][w.name]:.1f}s){suffix}", flush=True)
        # A beat of quiet before the next handshake, so the master is back in its
        # pump loop rather than still finishing the previous stitch.
        end = time.time() + args.register_gap
        while time.time() < end:
            pump_all(nodes)

    refused = {f"worker{i}" for i in refused_workers(args)}
    joined = [w for w in workers if w.name not in refused]
    print(f"[sim] OK  {len(joined)} worker(s) registered (serialized)"
          + (f", {len(refused)} refused" if refused else ""), flush=True)
    return joined


def await_layers(args, nodes, workers, stats):
    """
    Wait for every worker to be told its layer range.

    The master fetches its own weights (embedding + classifier) before it assigns
    anything, and then assigns workers one at a time, waiting for each shard to
    load before the next -- so this milestone spans several multi-minute fetches.

    Checks performed:
      1. Every worker sees "assigned layers"; the phase is not complete while
         any is still unassigned, so a ring that forms around a subset cannot
         slip through as success.
      2. The budget is the shard timeout, not a shorter one, because the
         master's own multi-megabyte fetch happens inside this window.
    """
    deadline = time.time() + args.shard_timeout
    while time.time() < deadline:
        pump_all(nodes)
        remaining = [w for w in workers if "assigned layers" not in w.buf]
        if not remaining:
            print("[sim] OK  layers assigned", flush=True)
            return
    remaining = [w.name for w in workers if "assigned layers" not in w.buf]
    raise SimError(f"never assigned layers within {args.shard_timeout}s: {remaining}")


def await_shards(args, nodes, workers, stats):
    """
    Wait for every worker's layer range to become resident, then for the master
    to agree that the ring is ready.

    Checks performed:
      1. Each worker reports "shard: ready" on its own console -- the worker's
         own account of what it has in memory.
      2. The master independently reports "all shards resident", which is
         driven by the PROC_SHARD_READY it received rather than by anything the
         simulation observed. Both are required: a worker whose report never
         reached the master would otherwise look ready to us and not to it.
      3. A worker still pending at the deadline is fatal -- generation against
         a partly-loaded ring produces a stall, not a diagnosis.
    """
    master = nodes[0]
    deadline = time.time() + args.shard_timeout
    t0 = time.time()
    pending = list(workers)
    while pending and time.time() < deadline:
        pump_all(nodes)
        for w in list(pending):
            if "shard: ready" in w.buf:
                stats["shard_s"][w.name] = time.time() - t0
                print(f"[sim] OK  {w.name} shard resident "
                      f"({stats['shard_s'][w.name]:.0f}s)", flush=True)
                pending.remove(w)
    if pending:
        raise SimError(f"shard fetch timed out for: {[w.name for w in pending]}")

    if wait_for_on(master, nodes, ["all shards resident"], 120, "master ready",
                   stall=args.stall_timeout) is None:
        raise SimError("master never saw every shard become ready")
    print("[sim] OK  all shards resident -- generating", flush=True)


# ---------------------------------------------------------------------------
# Generation, fault injection, recovery
# ---------------------------------------------------------------------------

RE_SUSPECTED = re.compile(r"master: worker (\d+) suspected")
RE_EXPIRED = re.compile(r"master: worker (\d+) expired")
RE_RESTART = re.compile(r"master: --- restarting generation \(attempt (\d+)/(\d+)\)")
RE_HOP_TIMEOUT = re.compile(r"master: token at pos (\d+) timed out \(attempt (\d+)/(\d+)\)")
RE_RING_WIDTH = re.compile(r"master: all shards resident \((\d+) worker\(s\)\)")

# The worker announces the lie it is telling, and the master announces catching
# it. Both halves are needed: the first proves the mode actually fired, the
# second proves the defence held. Asserting only the second would pass on a run
# where nothing was ever claimed.
RE_CLAIM_MADE = re.compile(
    r"worker: \[MALICIOUS\] claiming (\d+) MB RAM \(real budget (\d+) MB\)")
RE_PROBE_REJECT = re.compile(
    r"master: worker (\d+) failed the RAM probe \(claimed (\d+) MB, (\d+) pages\), refusing")
RE_CORRUPT_APPLIED = re.compile(
    r"worker: \[MALICIOUS\] (sign-flipped|zeroed|delta [-\d.]+ applied to) (\d+) floats seq=(\d+)")


def generate(args, nodes, workers, stats):
    """
    Drive generation to completion, injecting faults and following the recovery.

    The master's own recovery budget sets the pace here. It gives a token
    (INFER_MAX_RETRIES + 1) x INFER_TOKEN_TIMEOUT_MS = 45 s before declaring a
    hop failure, and marks a silent node SUSPECTED at SUSPECTED_TIMEOUT = 40 s --
    at which point the node leaves the ring, since `discovery_ring_order` walks
    ACTIVE workers only. So a killed worker drops out at ~40 s and the next of the
    four generation attempts reforms over the survivors.

    Each restart re-arms the deadline, because the survivors must re-fetch their
    new, wider shard ranges before the retry can produce a token -- minutes of
    work that would otherwise be charged against the original budget.

    Checks performed:
      1. "master: done" is required to leave the loop; a deadline or a stall
         raises instead, so an abandoned run is never reported as a finished one.
      2. "generation did not complete after" -- the master's own admission that
         it spent its restart budget -- fails immediately rather than waiting
         out the remaining time.
      3. Hop timeouts, suspicions and expiries are recorded and logged but do
         **not** fail the run: they are the mechanism recovery is made of, and
         treating them as errors would fail exactly the case under test.
      4. Each observed restart re-arms the deadline once (counted, not matched
         repeatedly), so recovery gets a full fetch-plus-generate budget while
         a genuinely stuck master still runs out of time.
      5. Kills fire on the master's committed-token count, one victim per
         token, so a multi-fault run lands its second kill on the reformed ring
         rather than firing every kill at the same instant.
    """
    master = nodes[0]
    gen_timeout = args.gen_timeout or (120 + args.steps * (10 + 6 * args.workers))
    deadline = time.time() + gen_timeout
    last_output = time.time()

    kills = list(args.kill_worker or [])
    announced = set()

    # Recorded as they are observed, not at the end: a run that fails here is
    # precisely the one whose recovery timeline the summary needs to show.
    stats.setdefault("suspected", [])
    stats.setdefault("expired", [])
    stats["restarts"] = 0
    stats["hop_timeouts"] = 0
    stats["corruptions_applied"] = 0

    while time.time() < deadline:
        if pump_all(nodes):
            last_output = time.time()

        tokens_done = master.buf.count("master: COMMIT final")

        # --- fault injection -------------------------------------------------
        # Staggered by one token per victim. tokens_done counts COMMITs across
        # every attempt, so after a restart it keeps climbing and the next kill
        # lands on the reformed ring rather than all of them firing at once.
        while kills and tokens_done >= args.kill_at_token + len(stats["faults"]):
            idx = kills.pop(0)
            # Index into `nodes`, not `workers`: worker N is always nodes[N],
            # whereas `workers` has had any refused node filtered out of it.
            victim = nodes[idx]
            victim.fault(args.kill_mode)
            stats["faults"].append({"worker": victim.name, "at_token": tokens_done,
                                    "mode": args.kill_mode})
            print(f"[sim] FAULT {args.kill_mode} {victim.name} at token {tokens_done}",
                  flush=True)

        # --- follow the master's recovery ------------------------------------
        for key, rx, msg in (("suspected", RE_SUSPECTED, "master suspects worker"),
                             ("expired", RE_EXPIRED, "master expired worker")):
            for wid in rx.findall(master.buf):
                if (key, wid) not in announced:
                    announced.add((key, wid))
                    stats[key].append(wid)
                    print(f"[sim]   {msg} {wid}", flush=True)

        n_hop = len(RE_HOP_TIMEOUT.findall(master.buf))
        if n_hop > stats["hop_timeouts"]:
            stats["hop_timeouts"] = n_hop
            print(f"[sim]   hop timeout #{n_hop} (master retrying)", flush=True)

        # Counted from the workers' own consoles: a corruption test that cannot
        # show the corruption was applied proves nothing, and would pass on a
        # run where the flag silently did nothing.
        n_corrupt = sum(len(RE_CORRUPT_APPLIED.findall(w.buf)) for w in workers)
        if n_corrupt > stats["corruptions_applied"]:
            if stats["corruptions_applied"] == 0:
                print("[sim]   ADVERSARY corrupted an activation -- nothing in the "
                      "pipeline inspects payload content, so it will be believed",
                      flush=True)
            stats["corruptions_applied"] = n_corrupt

        restarts = RE_RESTART.findall(master.buf)
        if len(restarts) > stats["restarts"]:
            stats["restarts"] = len(restarts)
            attempt, total = restarts[-1]
            deadline = time.time() + args.shard_timeout + gen_timeout
            last_output = time.time()
            print(f"[sim]   RECOVERY restarting generation, attempt {attempt}/{total} "
                  f"-- survivors re-fetch shards, deadline re-armed", flush=True)

        widths = RE_RING_WIDTH.findall(master.buf)
        if widths:
            stats["final_ring_width"] = int(widths[-1])

        if "master: generation did not complete after" in master.buf:
            raise SimError("master exhausted its restart attempts")
        if "master: done" in master.buf:
            break

        if args.stall_timeout and time.time() - last_output > args.stall_timeout:
            raise SimError(f"no console output from any node for {args.stall_timeout}s")
    else:
        raise SimError(f"generation did not finish within {gen_timeout}s")

    # discovery_stats() and the latency summary are printed *after* "master: done"
    # and the master then loops in master_pump forever, so keep pumping until they
    # have both arrived (or the grace period runs out) before teardown.
    #
    # Wait on the fully-matched regexes, not on a substring: over a slow serial
    # console the drops line arrives in pieces, and stopping at the first sight of
    # "rpc drops" tore the run down mid-line -- losing the tail of that line and
    # the latency line printed after it entirely.
    end = time.time() + 30
    while time.time() < end:
        pump_all(nodes)
        if RE_DROPS.search(master.buf) and RE_LATENCY.search(master.buf):
            break
    else:
        print("[sim] WARN master's stats lines did not fully arrive before teardown",
              flush=True)


# ---------------------------------------------------------------------------
# Output extraction and summary
# ---------------------------------------------------------------------------

def extract_tokens(buf):
    """
    The generated text, with interleaved kernel console lines removed.

    The token pieces and the kernel's own logging share one serial console, and
    the master prints three lines per token into exactly this region (`got
    INFER_REQ`, `decoded seq=`, `COMMIT final`) plus suspected/expired/restart
    lines on a fault run. Strip any known log prefix through to end of line --
    mid-line included, since a piece carries no trailing newline and so shares its
    line with whatever printed next -- then collapse whitespace. Callers that need
    an exact comparison should compare whitespace-insensitively, because a piece
    boundary can fall inside a removed line.

    On a restarted run generation replays from pos 0, so the text after the *last*
    "all shards resident" is the attempt that actually completed.

    Checks performed:
      1. Both delimiters must be present, and the end is searched *after* the
         start, so a "master: done" from an earlier attempt cannot close the
         region opened by the final one.
      2. The start is the last "all shards resident", which is the attempt that
         produced the surviving output.
      3. Log lines are stripped to end of line, mid-line included, because a
         token piece carries no trailing newline and shares its line with
         whatever the kernel printed next.
      4. Returns None rather than a partial string when either delimiter is
         missing, so the caller fails the run instead of comparing a fragment.
    """
    start = buf.rfind("all shards resident")
    if start < 0:
        return None
    end = buf.find("master: done", start)
    if end < 0:
        return None
    body = buf[buf.find("\n", start) + 1:end]
    return re.sub(r"\s+", " ", NOISE_RE.sub("", body)).strip()


RE_ASSIGNED = re.compile(r"master: worker (\d+) assigned layers \[(\d+),(\d+)\)")
RE_DONE = re.compile(r"master: done \((\d+) tokens\)")

# Both require their terminating newline. The console delivers a long line in
# pieces, and a pattern that can match a half-arrived line would report a
# truncated latency string and a drop count missing its last digit.
RE_LATENCY = re.compile(r"master: latency/token[^\n]*\n")
RE_DROPS = re.compile(r"master: rpc drops -- malformed (\d+), rate-limited (\d+), "
                      r"bad-prog (\d+), unknown-proc (\d+)\n")


def collect(master_buf, stats):
    """
    Pull the master's own accounting off its console into `stats`.

    Layer ranges are read only from the *last* generation session. Scanning the
    whole log instead would keep a dead worker's pre-fault row -- it is never
    reassigned, so nothing overwrites it -- and the summary would show its range
    alongside the survivor that took the range over, as though both owned it.

    Checks performed:
      1. Layer ranges come from after the last restart marker, or from the
         whole log when there was no restart.
      2. The drops and latency patterns require their terminating newline, so a
         line still arriving over the serial console cannot be read as a
         complete one -- without this a drop count can lose its last digit.
      3. Every field is optional: a run that failed before the master printed
         its summary still populates whatever did arrive, because that partial
         picture is what makes the failure diagnosable.
    """
    session = master_buf.rfind("--- restarting generation")
    stats["layers"] = {f"w{wid}": [int(a), int(b)]
                       for wid, a, b in RE_ASSIGNED.findall(
                           master_buf[session if session >= 0 else 0:])}
    m = RE_DONE.search(master_buf)
    if m:
        stats["tokens"] = int(m.group(1))
    m = RE_LATENCY.search(master_buf)
    if m:
        stats["latency"] = m.group(0).replace("master: ", "").strip()
    m = RE_DROPS.search(master_buf)
    if m:
        stats["drops"] = dict(zip(("malformed", "rate_limited", "bad_prog",
                                   "unknown_proc"), (int(x) for x in m.groups())))


def _row(label, value):
    print(f"[sim]  {label:<13} {value}")


def print_summary(args, stats):
    """
    The end-of-run block: what was built, what registered, what it cost, and
    whether anything was lost along the way.

    Checks performed:
      1. Printed on every exit path, success or failure, since a run that died
         mid-phase is the one whose timings and fault timeline are worth having.
      2. Rows are emitted only for figures that were actually collected, so a
         missing row means "never reached" rather than "zero".
      3. Faults are labelled unexpected when the run saw restarts or expiries
         without a kill being injected -- that combination means the ring lost
         a node on its own, which is a result, not noise.
    """
    print("[sim] ==================== run summary ====================")
    _row("topology", f"master {MASTER_IP} + {args.workers} worker(s) | "
                     f"model {args.model} ({MODEL_NAMES.get(args.model, '?')}) | "
                     f"{args.steps} steps")
    if stats.get("images"):
        _row("build", f"{stats['images']} image(s) in {stats['build_s']:.0f}s")
    if stats["boot_s"]:
        _row("boot", " | ".join(f"{k} {v:.0f}s" for k, v in stats["boot_s"].items()))
    if stats["register_s"]:
        _row("registration", " | ".join(f"{k} {v:.1f}s"
                                        for k, v in stats["register_s"].items())
                             + "   (serialized)")
    if stats.get("layers"):
        _row("layers", " | ".join(f"{k} [{a},{b})"
                                  for k, (a, b) in sorted(stats["layers"].items())))
    if stats["shard_s"]:
        _row("shard fetch", " | ".join(f"{k} {v:.0f}s" for k, v in stats["shard_s"].items()))

    if stats.get("adversaries"):
        _row("adversary", ", ".join(
            f"{a['worker']} {a['mode']}"
            + (f":{a['value']}" if a['value'] else "")
            + f" -> {a['outcome']}" for a in stats["adversaries"]))
        if stats.get("corruptions_applied"):
            _row("", f"{stats['corruptions_applied']} activation(s) tampered with "
                     f"and accepted -- no content check exists (threat model item 3)")
    if stats["faults"]:
        _row("faults", "injected " + ", ".join(
            f"{f['worker']} @ token {f['at_token']} ({f['mode']})"
            for f in stats["faults"]))
    # "Unexpected" means the ring lost a node nobody asked it to lose. A refused
    # adversary counts as asked-for: its PENDING slot ages SUSPECTED -> EXPIRED
    # like any other, so those transitions are the expected consequence of the
    # refusal rather than a second, unexplained failure.
    unexpected = (not stats["faults"] and not stats.get("adversaries")
                  and (stats.get("restarts") or stats.get("expired")))
    if stats.get("restarts") or stats.get("suspected") or stats.get("expired"):
        _row("", f"suspected {len(stats.get('suspected', []))} | "
                 f"expired {len(stats.get('expired', []))} | "
                 f"restarts {stats.get('restarts', 0)} | "
                 f"hop timeouts {stats.get('hop_timeouts', 0)}"
                 + ("   [UNEXPECTED -- no fault was injected]" if unexpected else ""))
    if stats.get("final_ring_width"):
        _row("final ring", f"{stats['final_ring_width']}/{args.workers} worker(s)")

    if stats.get("tokens") is not None:
        gen = f"{stats['tokens']} token(s)"
        if stats.get("generate_s"):
            gen += f" in {stats['generate_s']:.1f}s"
        _row("generation", gen)
    if stats.get("latency"):
        _row("latency", stats["latency"])
    if stats.get("drops"):
        d = stats["drops"]
        _row("rpc drops", f"malformed {d['malformed']} | rate-limited {d['rate_limited']} "
                          f"| bad-prog {d['bad_prog']} | unknown-proc {d['unknown_proc']}")
    _row("logs", os.path.join(args.outdir, "{master,worker1..N}.log"))
    _row("result", stats["result"])
    print("[sim] =====================================================")

    # The canonical one-line verdict, emitted after the block. The table above is
    # for humans and its layout is free to change; this line is the contract the
    # L3 gate greps for ("[sim] PASS"), so it stays a bare marker. Losing it when
    # the verdict moved into the table is exactly what broke test_ring_generates.
    print(f"[sim] {stats['result']}", flush=True)


# ---------------------------------------------------------------------------

def main():
    """
    Parse the run, drive the phases in order, and summarise whatever happened.

    Checks performed on the arguments, before anything is built (each of these
    would otherwise surface twenty minutes in, after every image is compiled and
    every shard fetched):
      1. The worker count fits the node table, which is bounded by the
         qemu-node* targets that exist in the Makefile.
      2. Each kill target names a worker that will exist in this run.
      3. The model has at least one layer per worker. The master enforces this
         itself and is the authority; checking here only moves the failure to
         the first second of the run instead of the last.

    And on the result, before PASS is reported:
      4. Real token text was recovered. "master: done" prints after a clean
         abort too, so a stalled ring would otherwise report success.
      5. Under --strict, a restart or expiry with no injected fault fails the
         run -- the ring lost a node it was not asked to lose.
    """
    ap = argparse.ArgumentParser(
        description="Run the DistInf ring simulation (root-free)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Note: the master refuses more workers than the model has layers "
               f"({', '.join(f'model {k} = {v}' for k, v in sorted(MODEL_LAYERS.items()))}).\n"
               "Kill every stale qemu-system-riscv64 and mcast_switch.py before "
               "running: the multicast group and MACs are fixed, so two overlapping "
               "runs collide and the weight fetch stalls.")
    ap.add_argument("--workers", type=int, default=2,
                    help=f"1..{len(NODE_IDS) - 1} (default 2)")
    ap.add_argument("--model", type=int, default=1,
                    help="LLM-RFTP file id: 1 = stories15M, 3 = stories110M")
    ap.add_argument("--steps", type=int, default=32)
    ap.add_argument("--prompt", default="Once upon a time")
    ap.add_argument("--outdir", default="/tmp/distinf_sim")
    ap.add_argument("--smp", type=int, default=8,
                    help="vCPUs per node (default 8; ring inference is sequential, "
                         "so co-resident nodes are mostly idle)")
    ap.add_argument("--json", metavar="PATH", help="also write the summary as JSON")

    ap.add_argument("--boot-timeout", type=int, default=0,
                    help="per node; default 120 + 40 x nodes")
    ap.add_argument("--register-timeout", type=int, default=120,
                    help="per worker handshake (default 120)")
    ap.add_argument("--register-gap", type=float, default=2.0,
                    help="quiet seconds between handshakes (default 2)")
    ap.add_argument("--shard-timeout", type=int, default=0,
                    help="assignment + fetch; default max(900, 240 x workers)")
    ap.add_argument("--gen-timeout", type=int, default=0,
                    help="default 120 + steps x (10 + 6 x workers); re-armed on restart")
    ap.add_argument("--stall-timeout", type=int, default=300,
                    help="fail early if no node prints anything for this long (0 = off)")

    ap.add_argument("--kill-worker", type=int, action="append", metavar="N",
                    help="1-based worker to kill mid-generation (repeatable)")
    ap.add_argument("--kill-at-token", type=int, default=4,
                    help="kill once the master has committed this many tokens")
    ap.add_argument("--kill-mode", choices=("crash", "pause"), default="crash",
                    help="crash = SIGKILL the node; pause = SIGSTOP (hung but present)")
    ap.add_argument("--strict", action="store_true",
                    help="also fail on faults that were not injected")
    ap.add_argument("--adversary", action="append", metavar="N:MODE[:VALUE]",
                    help="make worker N misbehave (repeatable). Modes: "
                         "lie-ram:<mb>, signflip, zero, delta:<amount>")
    args = ap.parse_args()

    if args.workers < 1 or args.workers > len(NODE_IDS) - 1:
        sys.exit(f"--workers must be 1..{len(NODE_IDS) - 1}")

    for k in (args.kill_worker or []):
        if k < 1 or k > args.workers:
            sys.exit(f"--kill-worker must be 1..{args.workers}")

    # Validated here, before a single image is built: every one of these would
    # otherwise surface twenty minutes in, after six kernels and every shard.
    args.adversary_spec = {}
    for spec in (args.adversary or []):
        parts = spec.split(":")
        if not 2 <= len(parts) <= 3 or not parts[0].isdigit():
            sys.exit(f"--adversary must be N:MODE[:VALUE], got {spec!r}")
        idx, mode = int(parts[0]), parts[1]
        value = parts[2] if len(parts) == 3 else ""
        if not 1 <= idx <= args.workers:
            sys.exit(f"--adversary worker must be 1..{args.workers}, got {idx}")
        if mode not in ADVERSARY_MODES:
            sys.exit(f"--adversary mode must be one of "
                     f"{', '.join(sorted(ADVERSARY_MODES))}, got {mode!r}")
        if ADVERSARY_MODES[mode]["needs_value"] and not value:
            sys.exit(f"--adversary {mode} needs a value, e.g. {idx}:{mode}:"
                     + ("4096" if mode == "lie-ram" else "0.5"))
        if idx in args.adversary_spec:
            sys.exit(f"--adversary given twice for worker {idx}")
        args.adversary_spec[idx] = (mode, value)

    # A refused node never joins, so the ring that actually forms is smaller
    # than --workers suggests.
    if args.workers - len(refused_workers(args)) < 1:
        sys.exit("every worker would be refused; no ring could form")

    if args.workers > MODEL_LAYERS.get(args.model, args.workers):
        sys.exit(f"model {args.model} has only {MODEL_LAYERS[args.model]} layers; "
                f"the master refuses {args.workers} workers (one layer each, minimum)")
    if not args.shard_timeout:
        args.shard_timeout = max(900, 240 * args.workers)

    os.makedirs(args.outdir, exist_ok=True)
    stats = {"boot_s": {}, "register_s": {}, "shard_s": {}, "faults": [],
             "adversaries": [],
             "result": "FAIL (did not start)"}
    nodes, switch, rc = [], None, 1
    try:
        build_all(args, stats)

        print("[sim] starting host mcast switch (weight server on the segment)...",
              flush=True)
        switch = subprocess.Popen([VENV_PY, os.path.join(HERE, "mcast_switch.py")],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                  start_new_session=True)
        time.sleep(2)

        boot_all(args, stats, nodes)
        start_master(args, nodes, stats)
        workers = register_serially(args, nodes, stats)
        await_layers(args, nodes, workers, stats)
        await_shards(args, nodes, workers, stats)

        t0 = time.time()
        generate(args, nodes, workers, stats)
        stats["generate_s"] = time.time() - t0

        master = nodes[0]
        collect(master.buf, stats)

        # "master: done" prints even after a clean abort, so PASS additionally
        # requires real token text -- otherwise a stalled ring would masquerade
        # as success.
        tokens = extract_tokens(master.buf)
        stats["generated"] = tokens
        print("\n[sim] ==== generated ====")
        print(tokens or "(could not recover token stream)")
        print("[sim] ===================")

        if not tokens:
            stats["result"] = "FAIL -- pipeline stalled or produced no tokens"
        elif args.strict and not stats["faults"] and not stats["adversaries"] \
                and (stats.get("restarts") or stats.get("expired")):
            # Only a loss nobody asked for. An adversary refused at registration
            # leaves a PENDING slot that ages out on its own, which is the
            # refusal working, not a second failure.
            stats["result"] = "FAIL -- unexpected fault under --strict"
        else:
            recovered = (f" (recovered from {len(stats['faults'])} fault(s))"
                         if stats["faults"] else "")
            stats["result"] = "PASS" + recovered
            rc = 0
    except SimError as e:
        stats["result"] = f"FAIL -- {e}"
        print(f"[sim] {stats['result']}", flush=True)
        if nodes:
            collect(nodes[0].buf, stats)
    finally:
        print_summary(args, stats)
        if args.json:
            with open(args.json, "w") as f:
                json.dump(stats, f, indent=2)
        for n in nodes:
            n.close()
        if switch:
            try:
                os.killpg(os.getpgid(switch.pid), signal.SIGKILL)
            except Exception:
                pass
    return rc


if __name__ == "__main__":
    sys.exit(main())
