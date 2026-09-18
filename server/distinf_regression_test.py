#!/usr/bin/env python3
"""
distinf_regression_test.py -- L3 correctness gate for the distributed inference pipeline.

The fourth gate, after L1 (kernel_regression_test.py), L2 (net_regression_test.py) and
the weight-fetch gate. Where those assert a node's behaviour, this one asserts the
*cluster's*: that sharding a model across nodes produces the same tokens as running it
whole, and that losing a node degrades cleanly instead of hanging.

It drives server/distinf_sim.py rather than re-implementing the bring-up.

    case                    what is exercised                     expected outcome
    ---------------------   -----------------------------------   ------------------------
    ring_generates          master + N workers, layers split,     the ring produces the
                            per-token traversal                   reference token stream
    matches_single_node     distributed vs. single-node output    identical, temperature 0
    survives_worker_loss    5 workers, one killed mid-token;      ring reforms over the
                            re-stitch, reassign, restart          survivors, same tokens
    capability_lie_         claims 1024 MB while able to back     refused: the probe asks
      is_refused            16 MB, under the probe ceiling        for more than it has
    capability_lie_above_   claims 1024 MB while able to back     accepted -- a bounded
      probe_ceiling_        the usual 512 MB                      probe can only prove
      is_accepted                                                 "at least the ceiling"
    corrupted_output_       a registered node computes a real     accepted and believed;
      is_not_detected       forward pass, then tampers with it    output diverges

The last three cover the node that misbehaves while alive, as opposed to the one that
stops, and they map onto README threat-model items 1 and 3. They deliberately do not all
assert a defence. Item 1 has one, but only within `CAP_PROBE_CEILING_BYTES`: a claim backed
by a budget above that ceiling is accepted however large the claim, so both sides of that
boundary are pinned. Item 3 has no defence at all -- nothing in the pipeline inspects
payload content, only shape and provenance -- so the corruption must be shown to land.
Asserting that either is caught would assert a defence that does not exist.

Why identity is the right assertion rather than a tolerance: both paths execute the same
llama_core kernels -- including dot_product_unrolled's 8-way accumulation, whose summation
order differs from a naive loop -- so a sharded run is bit-identical to a whole-model run,
and that equivalence was proven directly when the kernels were extracted (see README).
A host reference implementation would need a tolerance; this comparison does not.

Root-free: uses QEMU multicast socket networking, so no tap bridge and no sudo.

    .venv/bin/python -m pytest server/distinf_regression_test.py -v --noconftest
"""

import os
import sys
import re
import shutil
import subprocess

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
PROJ = os.path.dirname(HERE)
XV6 = os.path.join(PROJ, "xv6-riscv")
VENV_PY = sys.executable   # interpreter running this script; activate .venv first

PROMPT = "Once upon a time"
STEPS = 32

# The single-node golden reference: `llama -t 0 -n 32 -i "Once upon a time"` on
# stories15M.bin. Greedy sampling makes it deterministic.
GOLDEN = ("Once upon a time, there was a little girl named Lily. She loved to play "
          "outside in the sunshine. One day, she saw a big")


# Root-free: the simulation uses QEMU multicast socket networking (no tap, no
# bridge, no sudo). Skipped only if QEMU itself is missing.
pytestmark = pytest.mark.skipif(
    shutil.which("qemu-system-riscv64") is None,
    reason="qemu-system-riscv64 not found")


@pytest.fixture(scope="module")
def sim_output():
    """Run the ring once; both cases read the same run."""
    proc = subprocess.run(
        [VENV_PY, os.path.join(HERE, "distinf_sim.py"),
         "--workers", "2", "--model", "1", "--steps", str(STEPS), "--prompt", PROMPT],
        cwd=PROJ, capture_output=True, text=True, timeout=2400)
    return proc


def test_ring_generates(sim_output):
    """
    The ring forms and completes a generation.

    Checks performed:
      1. The simulation reports PASS, meaning every milestone was observed in order:
         registration -> layer assignment -> shards resident -> tokens -> done.
      2. The process exits zero, so a milestone timeout fails the gate rather than
         being reported as a successful run with missing output.
    """
    assert sim_output.returncode == 0, (
        f"simulation failed:\n{sim_output.stdout[-3000:]}\n{sim_output.stderr[-1000:]}")
    assert "[sim] PASS" in sim_output.stdout


def generated_text(out):
    """The token block the simulation printed between its two banner lines."""
    start = out.find("==== generated ====")
    end = out.find("===================")
    assert start >= 0 and end > start, f"no generated text in:\n{out[-2000:]}"

    # The end marker is printed as a full line ("[sim] ==================="), so the
    # bare "===" match lands mid-line, after its "[sim] " prefix; back up to the
    # newline that ends the token block so that prefix is not captured as a token.
    end = out.rfind("\n", start, end)
    return out[out.find("\n", start) + 1:end].strip()


def compact(s):
    """
    Whitespace-insensitive form for comparison.

    The token pieces share the serial console with the kernel's own logging, so a
    piece boundary can fall inside a stripped log line, adding or dropping a
    space. The token *content* must still be identical.
    """
    return re.sub(r"\s+", "", s)


def test_matches_single_node(sim_output):
    """
    The distributed token stream equals the single-node golden reference.

    Checks performed:
      1. The generated text is recoverable from the master's console.
      2. It matches the reference exactly -- not approximately. A mismatch means the
         sharded path diverged from the whole-model path: wrong layer range, wrong KV
         cache indexing, or an activation corrupted in transit.
    """
    generated = generated_text(sim_output.stdout)
    assert compact(generated) == compact(GOLDEN), (
        "distributed output diverged from the single-node reference\n"
        f"  distributed: {generated!r}\n"
        f"  reference:   {GOLDEN!r}")


# The scale + fault cases boot six QEMU machines and re-fetch every shard after
# the kill, so each is a ~40-minute run. Opt in explicitly rather than making the
# default gate an hour longer.
@pytest.mark.skipif(not os.environ.get("DISTINF_SCALE"),
                    reason="long run; set DISTINF_SCALE=1")
@pytest.mark.parametrize("victim", [3, 5], ids=["mid_ring", "tail"])
def test_survives_worker_loss(victim):
    """
    Five workers, one killed mid-generation: the ring reforms and still produces
    the reference token stream.

    Both positions are exercised because they fail differently. Killing a
    mid-ring worker orphans its predecessor's `next`; killing the *tail* also
    leaves no worker whose `next` is the master, so `master_ring_tail()` cannot
    resolve and every returning activation is dropped as "not ring tail". Both
    are only survivable because `discovery_restitch_ring()` recomputes the
    survivors' neighbours before each generation attempt -- expiry alone changes
    a worker's state, not the topology around it.

    Checks performed:
      1. The run exits zero and reports PASS, so recovery completed rather than
         the master exhausting its four attempts.
      2. At least one restart was actually observed. Without this the case could
         pass by the kill never landing, proving nothing.
      3. The recovered ring is smaller than the one it started with -- the
         survivors really did take over the dead node's layers.
      4. The token stream still equals the single-node golden reference. Layers
         are redistributed and generation replays from pos 0, so a 4-worker
         completion computes the identical model; a mismatch here is a real
         divergence, not fault noise.
    """
    proc = subprocess.run(
        [VENV_PY, os.path.join(HERE, "distinf_sim.py"),
         "--workers", "5", "--model", "1", "--steps", str(STEPS), "--prompt", PROMPT,
         "--kill-worker", str(victim), "--kill-at-token", "4", "--strict"],
        cwd=PROJ, capture_output=True, text=True, timeout=4800)
    out = proc.stdout

    assert proc.returncode == 0, (
        f"simulation failed:\n{out[-4000:]}\n{proc.stderr[-1000:]}")
    assert "[sim] PASS" in out

    assert re.search(r"restarts (\d+)", out), f"no restart line in summary:\n{out[-2000:]}"
    restarts = int(re.search(r"restarts (\d+)", out).group(1))
    assert restarts >= 1, "the injected kill never forced a restart, so nothing was proven"

    width = re.search(r"final ring\s+(\d+)/5 worker\(s\)", out)
    assert width and int(width.group(1)) < 5, (
        f"ring did not shrink after the kill:\n{out[-2000:]}")

    generated = generated_text(out)
    assert compact(generated) == compact(GOLDEN), (
        "output after fault recovery diverged from the single-node reference\n"
        f"  recovered: {generated!r}\n"
        f"  reference: {GOLDEN!r}")


def run_sim(*extra, timeout=4800):
    """Drive distinf_sim.py with the standard prompt/steps plus `extra` flags."""
    return subprocess.run(
        [VENV_PY, os.path.join(HERE, "distinf_sim.py"),
         "--workers", "5", "--model", "1", "--steps", str(STEPS),
         "--prompt", PROMPT, *extra],
        cwd=PROJ, capture_output=True, text=True, timeout=timeout)


@pytest.mark.skipif(not os.environ.get("DISTINF_SCALE"),
                    reason="long run; set DISTINF_SCALE=1")
def test_capability_lie_is_refused():
    """
    A node advertises 1024 MB while it can genuinely back only 16 MB. The sized
    probe asks for more than it has, the allocation fails for real, and it never
    joins the ring.

    The lie is real rather than simulated at the protocol level: the worker
    advertises the inflated figure but pins its own RLIMIT_AS to the budget it
    can actually back, so `cap_probe_run`'s eager allocation fails on its own
    merits. A node that instead fabricated the checksum arithmetically is
    explicitly out of scope without attestation (`discovery.h`), and testing it
    would prove nothing either way.

    16 MB is chosen because it is below `CAP_PROBE_CEILING_BYTES` (32 MB). The
    probe verifies "has at least min(claim, ceiling)", so a claim backed by any
    budget *above* the ceiling is accepted no matter how large the claim -- see
    test_capability_lie_above_probe_ceiling_is_accepted, which pins that limit.

    Checks performed:
      1. The claim was actually made -- the worker's console shows it. Without
         this the case would pass on a run where the flag did nothing, which is
         exactly how the previous framework failed silently.
      2. The worker could not satisfy the probe, so the refusal traces to the
         capability check rather than to an unrelated timeout.
      3. The liar never appears in an `assigned layers` line: it has to be kept
         out before any shard is committed to it, not removed afterwards.
      4. The run still exits zero and PASSes on the remaining four workers and
         reproduces the golden stream -- refusing a liar must not cost the
         cluster its ability to do the work.
    """
    proc = run_sim("--adversary", "3:lie-ram:1024/16", "--strict")
    out, logs = proc.stdout, "/tmp/distinf_sim"

    assert proc.returncode == 0, (
        f"simulation failed:\n{out[-4000:]}\n{proc.stderr[-1000:]}")
    assert "[sim] PASS" in out

    worker_log = open(os.path.join(logs, "worker3.log"), errors="replace").read()
    assert "claiming 1024 MB RAM" in worker_log, (
        "worker 3 never made the claim, so nothing was tested")
    assert "cannot back RAM claim" in worker_log, (
        f"the probe was satisfied despite a 16 MB budget:\n{worker_log[-2000:]}")

    master_log = open(os.path.join(logs, "master.log"), errors="replace").read()
    assert not re.search(r"master: worker 3 assigned layers", master_log), (
        "the liar was assigned layers despite failing the probe")

    generated = generated_text(out)
    assert compact(generated) == compact(GOLDEN), (
        "the honest ring's output changed when a liar was refused\n"
        f"  got:       {generated!r}\n"
        f"  reference: {GOLDEN!r}")


@pytest.mark.skipif(not os.environ.get("DISTINF_SCALE"),
                    reason="long run; set DISTINF_SCALE=1")
@pytest.mark.parametrize("mode", ["signflip", "zero"])
def test_corrupted_output_is_not_detected(mode):
    """
    A registered node computes a real forward pass and then tampers with it.
    The ring believes it.

    This asserts a *limitation*, deliberately. Threat-model item 3 names
    redundant assignment and cross-node consensus as the mitigation and neither
    is implemented: the pipeline validates a hop's shape, session, sequence and
    provenance, and never its content. Sign-flipped and zeroed activations are
    finite and in range, so no bounds check would catch them either -- the gap is
    real rather than an artifact of a missing screen.

    Pinning it here means the gap cannot quietly regress, and the day consensus
    lands this case inverts into an assertion that the corruption is caught.

    Checks performed:
      1. The corruption was actually applied -- the worker's console says so.
         This is the check that keeps the case honest: without it, a run where
         the flag silently did nothing would produce a "diverged" verdict for
         entirely the wrong reason.
      2. The run completes rather than stalling: a dishonest node is not a
         crashed one, so the ring keeps traversing and the master keeps sampling.
      3. The output *differs* from the golden reference, which is what "the ring
         believed it" means in observable terms.
      4. No RPC drop counter moved and no worker was evicted -- nothing anywhere
         noticed. If a future change starts catching this, the assertion fails
         and the docstring above needs rewriting, which is the intended signal.
    """
    proc = run_sim("--adversary", f"3:{mode}")
    out, logs = proc.stdout, "/tmp/distinf_sim"

    assert proc.returncode == 0, (
        f"simulation failed:\n{out[-4000:]}\n{proc.stderr[-1000:]}")

    worker_log = open(os.path.join(logs, "worker3.log"), errors="replace").read()
    marker = "sign-flipped" if mode == "signflip" else "zeroed"
    assert marker in worker_log, (
        f"worker 3 never corrupted anything ({mode}), so nothing was tested")

    generated = generated_text(out)
    assert generated, f"no token stream recovered:\n{out[-2000:]}"
    assert compact(generated) != compact(GOLDEN), (
        "corrupting a worker's output did not change the result -- either the "
        "corruption never reached the master, or it was silently discarded")

    master_log = open(os.path.join(logs, "master.log"), errors="replace").read()
    assert not re.search(r"master: worker \d+ evicted", master_log), (
        "a worker was evicted; corruption is now detected and this case should "
        "become a positive assertion")
    drops = re.search(r"rpc drops -- malformed (\d+), rate-limited (\d+), "
                      r"bad-prog (\d+), unknown-proc (\d+)", master_log)
    if drops:
        assert all(int(g) == 0 for g in drops.groups()), (
            f"a drop counter moved on a corruption run: {drops.group(0)}")


@pytest.mark.skipif(not os.environ.get("DISTINF_SCALE"),
                    reason="long run; set DISTINF_SCALE=1")
def test_capability_lie_above_probe_ceiling_is_accepted():
    """
    A node claims 1024 MB while backing the ordinary 512 MB, and is ACCEPTED.

    This asserts a limitation, deliberately, and it is the more realistic shape
    of the threat: a node with plenty of memory that simply overstates it to win
    a larger shard. The probe is bounded by `CAP_PROBE_CEILING_BYTES` (32 MB) so
    that a claim cannot be turned into an unbounded allocation demand, which
    means it can only ever establish "has at least min(claim, 32 MB)". A node
    with 512 MB satisfies a 32 MB probe effortlessly no matter what it claimed.

    `discovery.h` documents this ("validated only up to the ceiling"), but it is
    worth a test rather than only a comment, because README threat-model item 1
    reads as though capability lying is closed, and this is the case that shows
    what "closed" does and does not cover. Closing it properly needs the claim to
    be checked against something other than a probe the claimant can pass --
    measured throughput under real assignment, or attestation.

    Checks performed:
      1. The inflated claim was actually made.
      2. The node was accepted -- it appears in an `assigned layers` line, so the
         master committed a shard to a claim it could not verify.
      3. The run still produces the golden stream: the node was overstating, not
         malfunctioning, so the cluster works. The exposure is the assignment it
         won, not a wrong answer.
    """
    proc = run_sim("--adversary", "3:lie-ram:1024")
    out, logs = proc.stdout, "/tmp/distinf_sim"

    assert proc.returncode == 0, (
        f"simulation failed:\n{out[-4000:]}\n{proc.stderr[-1000:]}")

    worker_log = open(os.path.join(logs, "worker3.log"), errors="replace").read()
    assert "claiming 1024 MB RAM" in worker_log, (
        "worker 3 never made the claim, so nothing was tested")

    master_log = open(os.path.join(logs, "master.log"), errors="replace").read()
    assert re.search(r"master: worker 3 assigned layers", master_log), (
        "the overstated claim was refused -- the probe now catches lies above "
        "its ceiling, and this case should become a positive assertion")

    generated = generated_text(out)
    assert compact(generated) == compact(GOLDEN), (
        "a node that merely overstated its RAM changed the output\n"
        f"  got:       {generated!r}\n"
        f"  reference: {GOLDEN!r}")
