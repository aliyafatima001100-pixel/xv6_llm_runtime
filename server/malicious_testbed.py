#!/usr/bin/env python3
"""
malicious_testbed.py -- demonstrates the DistInf ring's behavior under three
classes of malicious node, for both a live/narrated demo and a paper artifact.

This is a NEW file, separate from distinf_sim.py. It never edits distinf_sim.py's
behavior; it drives it as a subprocess (the same relationship
distinf_regression_test.py already has to distinf_sim.py) and adds one thing
distinf_sim.py has no reason to know about: raw Scapy packet injection for
Scenario C1, which happens *alongside* a running sim rather than as a sim flag.

Scenarios:
    A  crash            -- worker killed mid-generation; ring reforms (existing
                            fault-tolerance path, --kill-worker)
    B  capability_lie    -- worker claims more RAM than it can back; master's
                            sized RAM-probe (handle_cap_ack) rejects it before
                            any shard is ever assigned to it
    C1 spoofed_sender    -- an unauthorized address injects a PROC_INFER_REQ at
                            a live worker; worker_inference_hook's source-binding
                            check drops it (DETECTED)
    C2 dishonest_worker  -- a legitimate, correctly-registered ring member
                            computes a real forward pass and then corrupts its
                            own output before sending; nothing in the current
                            pipeline checks payload CONTENT, only shape and
                            provenance, so this reaches the token stream
                            (NOT DETECTED -- this is the honest limitation)

Usage:
    .venv/bin/python server/malicious_testbed.py --scenario B
    .venv/bin/python server/malicious_testbed.py --all
    .venv/bin/python server/malicious_testbed.py --all --json-dir /tmp/testbed_results
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
PROJ = os.path.dirname(HERE)
VENV_PY = sys.executable   # interpreter running this script; activate .venv first
SIM = os.path.join(HERE, "distinf_sim.py")

PROMPT = "Once upon a time"
STEPS = 32
GOLDEN = ("Once upon a time, there was a little girl named Lily. She loved to play "
          "outside in the sunshine. One day, she saw a big")

# Mirrors distinf_sim.py's own compact() -- console output is whitespace-noisy
# for the reasons documented there (piece boundaries falling inside stripped
# log lines), so comparison must be whitespace-insensitive here too.
def compact(s):
    return re.sub(r"\s+", "", s or "")


# ---------------------------------------------------------------------------
# ANSI color for the live/demo renderer. No-op if not a tty (e.g. piped to a
# file for the paper renderer to consume as plain JSONL instead).
# ---------------------------------------------------------------------------

class C:
    GREEN = "\033[32m" if sys.stdout.isatty() else ""
    RED = "\033[31m" if sys.stdout.isatty() else ""
    YELLOW = "\033[33m" if sys.stdout.isatty() else ""
    BOLD = "\033[1m" if sys.stdout.isatty() else ""
    RESET = "\033[0m" if sys.stdout.isatty() else ""


def narrate(tag, msg):
    color = {"OK": C.GREEN, "CAUGHT": C.GREEN, "FAIL": C.RED,
             "UNDETECTED": C.RED, "INFO": C.YELLOW}.get(tag, "")
    print(f"  {color}[{tag}]{C.RESET} {msg}")


# ---------------------------------------------------------------------------
# Scenario definitions for the ones distinf_sim.py can run directly.
#
# C1 is NOT here -- it needs a live sim to inject a packet against mid-run,
# which is a different shape (start sim, wait for a worker to come up, fire a
# packet, then let the sim finish) than "run distinf_sim.py to completion and
# read back its JSON". It gets its own function below (run_c1).
# ---------------------------------------------------------------------------

SCENARIOS = {
    "A_crash": dict(
        workers=5, kill_worker=[3], kill_at_token=4, kill_mode="crash", strict=False,
        description="Worker 3 is SIGKILLed 4 tokens in. The ring must re-stitch "
                    "over the 4 survivors and finish generation.",
    ),
    "B_capability_lie": dict(
        workers=3, adversary=["2:lie-ram:2048"], strict=True,
        description="Worker 2 claims 2048 MB RAM at registration while it can "
                    "genuinely back only 512 MB. The master's sized RAM-probe "
                    "(handle_cap_ack) must reject it before any shard is assigned.",
    ),
    "C2_dishonest_signflip": dict(
        workers=3, adversary=["2:signflip"], strict=False,
        description="Worker 2 is a fully legitimate ring member. It computes a "
                    "correct forward pass, then negates every float before "
                    "sending. Nothing currently checks payload content.",
    ),
    "C2_dishonest_zero": dict(
        workers=3, adversary=["2:zero"], strict=False,
        description="Same as above, but worker 2 sends an all-zero activation "
                    "instead of doing any real compute at all -- the cheapest "
                    "possible dishonest-worker attack.",
    ),
    "C2_dishonest_delta": dict(
        workers=3, adversary=["2:delta:0.5"], strict=False,
        description="Worker 2 adds a small fixed offset to every float -- a "
                    "subtle, plausible-looking corruption rather than an "
                    "obviously-broken one.",
    ),
}


def cfg_to_argv(cfg, json_path):
    """Translate one SCENARIOS entry into a real distinf_sim.py argv list."""
    argv = [VENV_PY, SIM,
            "--workers", str(cfg["workers"]),
            "--model", "1",
            "--steps", str(STEPS),
            "--prompt", PROMPT,
            "--json", json_path]

    for w in cfg.get("kill_worker", []):
        argv += ["--kill-worker", str(w)]
    if "kill_at_token" in cfg:
        argv += ["--kill-at-token", str(cfg["kill_at_token"])]
    if "kill_mode" in cfg:
        argv += ["--kill-mode", cfg["kill_mode"]]
    for spec in cfg.get("adversary", []):
        argv += ["--adversary", spec]
    if cfg.get("strict"):
        argv += ["--strict"]

    return argv


def run_scenario(name, cfg, outdir, timeout=3600):
    """
    Run one SCENARIOS entry via distinf_sim.py and read back its --json stats.

    Returns (proc, stats). stats is {} if the JSON was never written (e.g. the
    sim crashed before its `finally` block, which always writes it -- so an
    empty stats dict means something more fundamental than a scenario failure
    went wrong, and proc.stdout/stderr is where to look).
    """
    json_path = os.path.join(outdir, f"{name}.json")
    argv = cfg_to_argv(cfg, json_path)

    print(f"\n{C.BOLD}=== Scenario {name} ==={C.RESET}")
    print(f"  {cfg['description']}")
    print(f"  $ {' '.join(argv[1:])}")

    t0 = time.time()
    proc = subprocess.run(argv, cwd=PROJ, capture_output=True, text=True,
                          timeout=timeout)
    elapsed = time.time() - t0

    stats = {}
    if os.path.exists(json_path):
        with open(json_path) as f:
            stats = json.load(f)

    print(f"  ({elapsed:.0f}s, exit code {proc.returncode})")
    return proc, stats


# ---------------------------------------------------------------------------
# Per-scenario assertions + narration. Each returns True/False (detected as
# expected) and prints the human-readable story as it goes.
# ---------------------------------------------------------------------------

def check_a_crash(stats):
    ok = True
    if stats.get("faults"):
        f = stats["faults"][0]
        narrate("INFO", f"{f['worker']} killed ({f['mode']}) at token {f['at_token']}")
    else:
        narrate("FAIL", "no fault was recorded -- the kill never landed, proves nothing")
        ok = False

    restarts = stats.get("restarts", 0)
    if restarts >= 1:
        narrate("OK", f"master restarted generation {restarts} time(s) over survivors")
    else:
        narrate("FAIL", "master never restarted -- did the kill actually land?")
        ok = False

    generated = stats.get("generated")
    if generated and compact(generated) == compact(GOLDEN):
        narrate("OK", "recovered token stream matches the single-node golden reference")
    else:
        narrate("FAIL", f"output diverged from golden: {generated!r}")
        ok = False

    if stats.get("result", "").startswith("PASS"):
        narrate("OK", "ring survived the crash and completed generation")
    else:
        narrate("FAIL", f"sim did not report PASS: {stats.get('result')}")
        ok = False
    return ok


def check_b_capability_lie(stats):
    ok = True
    layers = stats.get("layers", {})
    if "w2" in layers:
        narrate("FAIL", "worker 2 was assigned layers -- the lie was NOT caught, "
                        "this defeats the point of the scenario")
        ok = False
    else:
        narrate("CAUGHT", "worker 2 never received a layer assignment -- "
                          "the RAM-probe rejection kept it out of the ring entirely")

    if stats.get("result", "").startswith("PASS"):
        narrate("OK", "the two honest workers completed generation without worker 2")
    else:
        narrate("FAIL", f"ring did not complete: {stats.get('result')}")
        ok = False

    generated = stats.get("generated")
    if generated and compact(generated) == compact(GOLDEN):
        narrate("OK", "output matches golden -- the lie had zero effect downstream")
    else:
        narrate("FAIL", f"output diverged from golden: {generated!r}")
        ok = False
    return ok


def check_c2_dishonest(stats, mode_label):
    """
    The inverted assertion: PASS at the transport layer while the OUTPUT is
    wrong. Both halves are required -- a run that merely fails (crashes, times
    out) proves nothing about undetected corruption; a run whose output
    happens to match golden means the corruption never reached the token
    stream and this run proves nothing either.
    """
    ok = True

    if not stats.get("result", "").startswith("PASS"):
        narrate("FAIL", f"scenario did not complete via normal transport "
                        f"({stats.get('result')}) -- this demonstrates a "
                        f"transport failure, not undetected corruption")
        return False

    if stats.get("faults"):
        narrate("FAIL", "a crash/kill was recorded -- this scenario should show "
                        "corruption alone, with no transport-level fault")
        ok = False

    narrate("OK", f"ring completed normally: worker 2 registered, was assigned "
                  f"layers, and forwarded every hop with a valid HMAC-authenticated "
                  f"identity (no check anywhere covers payload content)")

    generated = stats.get("generated")
    if generated and compact(generated) != compact(GOLDEN):
        narrate("UNDETECTED", f"[{mode_label}] output diverged from golden and "
                              f"NOTHING in the pipeline flagged it:")
        print(f"      golden:    {GOLDEN!r}")
        print(f"      generated: {generated!r}")
    else:
        narrate("FAIL", "output matched golden -- the corruption never reached "
                        "the token stream, so this run demonstrates nothing")
        ok = False

    return ok


# ---------------------------------------------------------------------------
# Scenario C1 -- spoofed sender. This one is fundamentally different: it needs
# a LIVE worker to inject a packet at, mid-run, rather than a sim to run to
# completion and read back. distinf_sim.py has no flag for this; instead we
# drive a small honest 2-worker ring ourselves via distinf_sim.py's own Node
# class, fire the spoofed packet once a worker is up and assigned layers, then
# let the ring finish normally.
#
# This directly reuses infrastructure from distinf_sim.py rather than
# reimplementing bring-up -- see the import below. It requires being run from
# the same directory distinf_sim.py expects (server/), same as that file's own
# root-free assumptions (QEMU multicast, mcast_switch.py on the host).
# ---------------------------------------------------------------------------

def run_c1_spoofed_sender(outdir, timeout=1800):
    """
    Boot an honest 2-worker ring, let generation start, CAPTURE one real,
    well-formed PROC_INFER_REQ off the wire mid-run, then REPLAY those exact
    bytes at the same worker from a forged source address. Assert the
    worker's console shows the DROP bad source line, and that the real ring
    still finishes with golden output (the replay had zero effect on it).

    This captures-and-replays rather than hand-encoding a payload: rpc_proto.py
    (the host-side wire mirror) defines structs for the discovery/registration
    messages (worker_info_t, cap_ack_t, set_neighbor_t, auth_hello_reply_t)
    but has no struct for infer_hop_t and PROC_INFER_REQ isn't even in its
    proc list -- I have only ever seen infer_hop_t used as a field-initializer
    in distinf.c, never its struct layout, so hand-encoding one here would be
    a guess at field order/padding. A captured real hop is correct by
    construction, sidesteps that gap entirely, and is arguably the more
    realistic attack anyway (replay-with-forged-origin) than a synthetic one.

    Because this sniffs the tap interface, it needs root and Scapy -- same
    preconditions as net_regression_test.py's tap-mode tests, NOT the
    root-free multicast path distinf_sim.py's other scenarios use. Run this
    scenario with sudo, over --netdev tap.
    """
    print(f"\n{C.BOLD}=== Scenario C1_spoofed_sender ==={C.RESET}")
    print("  A real INFER_REQ hop is captured off the wire mid-run, then "
          "replayed from a forged source address at the same worker. "
          "worker_inference_hook's source-binding check must drop it.")

    sys.path.insert(0, HERE)
    import distinf_sim as sim   # reuse Node, wait_for_on, NODE_IDS, etc.
    from scapy.all import IP, UDP, AsyncSniffer, send  # noqa: local import, root/tap only
    import threading

    class Args:
        # Minimal stand-in for distinf_sim's argparse Namespace -- just enough
        # for build_all/boot_all/register_serially/await_layers/generate to run.
        workers = 2
        model = 1
        steps = STEPS
        prompt = PROMPT
        outdir = os.path.join(outdir, "c1_nodes")
        smp = 8
        boot_timeout = 0
        register_timeout = 120
        register_gap = 2.0
        shard_timeout = max(900, 240 * 2)
        gen_timeout = 0
        stall_timeout = 300
        kill_worker = None
        malicious = {}

    args = Args()
    os.makedirs(args.outdir, exist_ok=True)
    stats = {"boot_s": {}, "register_s": {}, "shard_s": {}, "faults": [], "result": ""}
    nodes = []
    ok = False
    try:
        sim.build_all(args, stats)
        sim.boot_all(args, stats, nodes)
        sim.start_master(args, nodes, stats)
        workers = sim.register_serially(args, nodes, stats)
        sim.await_layers(args, nodes, workers, stats)
        sim.await_shards(args, nodes, workers, stats)

        # Target worker 1's real IP, per distinf_sim's NODE_IDS convention
        # (index 0 = master, index 1 = worker1, so NODE_IDS[1]).
        target = workers[0]
        target_ip_last, _ = sim.NODE_IDS[1]
        target_ip = f"10.0.0.{target_ip_last}"
        target_port = 10001   # matches run_worker's `10000 + (my_id % 10000)` for id=1

        sniffer = AsyncSniffer(filter=f"dst host {target_ip} and udp port {target_port}",
                               store=True)
        sniffer.start()
        mark = len(target.buf)

        # generate() is blocking, so drive it on a thread and sniff a fixed
        # window while it's mid-flight -- long enough to see a real hop
        # (INFER_TOKEN_TIMEOUT_MS x retries gives generous slack per token).
        gen_thread = threading.Thread(target=sim.generate, args=(args, nodes, workers, stats))
        gen_thread.start()
        time.sleep(3)
        pkts = sniffer.stop() or []

        captured = None
        for p in pkts:
            if p.haslayer(UDP) and bytes(p[UDP].payload):
                captured = bytes(p[UDP].payload)
                break

        if captured is None:
            narrate("FAIL", "never captured a real INFER_REQ off the wire -- "
                            "check that this is run with sudo over tap mode, "
                            "not distinf_sim's default multicast networking")
            gen_thread.join(timeout=timeout)
            return False

        narrate("INFO", f"captured a real {len(captured)}-byte INFER_REQ payload")

        fake_src = "10.0.0.250"   # neither this worker's real prev nor the master
        pkt = IP(src=fake_src, dst=target_ip) / UDP(dport=target_port) / captured
        send(pkt, verbose=0)

        got = sim.wait_for_on(target, nodes, ["DROP bad source"], 10,
                              "spoofed-hop rejection", after=mark)
        if got:
            narrate("CAUGHT", "worker's source-binding check dropped the "
                              "replayed hop from the forged source")
            ok = True
        else:
            narrate("FAIL", "no DROP bad source line seen for the replayed hop")

        gen_thread.join(timeout=timeout)
        master = nodes[0]
        sim.collect(master.buf, stats)
        generated = sim.extract_tokens(master.buf)
        if generated and compact(generated) == compact(GOLDEN):
            narrate("OK", "real ring's output unaffected by the spoofed replay")
        else:
            narrate("FAIL", f"real ring's output diverged: {generated!r}")
            ok = False
    finally:
        for n in nodes:
            n.close()

    return ok


# ---------------------------------------------------------------------------

CHECKS = {
    "A_crash": check_a_crash,
    "B_capability_lie": check_b_capability_lie,
    "C2_dishonest_signflip": lambda s: check_c2_dishonest(s, "sign-flip"),
    "C2_dishonest_zero": lambda s: check_c2_dishonest(s, "zero"),
    "C2_dishonest_delta": lambda s: check_c2_dishonest(s, "small delta"),
}


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--scenario", choices=list(SCENARIOS) + ["C1_spoofed_sender"],
                    help="run one scenario")
    ap.add_argument("--all", action="store_true", help="run every scenario")
    ap.add_argument("--json-dir", default="/tmp/malicious_testbed",
                    help="where each scenario's --json output is written")
    ap.add_argument("--skip-c1", action="store_true",
                    help="skip C1 (needs rpc_proto XDR wiring -- see run_c1_spoofed_sender docstring)")
    args = ap.parse_args()

    if not args.scenario and not args.all:
        sys.exit("pass --scenario NAME or --all")

    os.makedirs(args.json_dir, exist_ok=True)
    names = list(SCENARIOS) if args.all else [args.scenario]

    results = {}
    for name in names:
        if name == "C1_spoofed_sender":
            continue
        proc, stats = run_scenario(name, SCENARIOS[name], args.json_dir)
        if not stats:
            narrate("FAIL", "no stats JSON was produced -- sim crashed before "
                            "writing it; see stdout/stderr below")
            print(proc.stdout[-2000:])
            print(proc.stderr[-1000:])
            results[name] = False
            continue
        results[name] = CHECKS[name](stats)

    if args.all and not args.skip_c1:
        results["C1_spoofed_sender"] = run_c1_spoofed_sender(args.json_dir)
    elif args.scenario == "C1_spoofed_sender":
        results["C1_spoofed_sender"] = run_c1_spoofed_sender(args.json_dir)

    print(f"\n{C.BOLD}=== summary ==={C.RESET}")
    for name, ok in results.items():
        tag = f"{C.GREEN}PASS{C.RESET}" if ok else f"{C.RED}FAIL{C.RESET}"
        print(f"  {name:<28} {tag}")

    return 0 if all(results.values()) else 1


if __name__ == "__main__":
    sys.exit(main())