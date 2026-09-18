# Securing Distributed xv6

A ground-level security research project on xv6-riscv, building a four-layer defense stack against real-world distributed system threats. The xv6 context is a deliberate scientific choice — every layer of the OS is visible, every attack and defense is fully attributable, and results generalize upward to real minimal OSes (satellite firmware, PLC controllers, embedded systems) in a way that Linux experiments cannot.

---

## Architecture Overview

The project implements a four-layer vertical security stack:

```
L3  Distributed Security
L2  Communication Security
L1  Kernel Security  
L0  Assembly / Hardware+Software Security
```

Each layer addresses a distinct threat class, and the layers compose: L2 enforces isolation decisions made at L3, L1 prevents processes from evading L2, and L0 closes side channels that bypass L1.

---

## Layer Breakdown

### L0 — Assembly Security / Hardware+Software

**Threat:** Side-channel attacks that leak secrets across process or VM boundaries without any software vulnerability.

**Attack classes under investigation:**

- **PRIME+PROBE** (access-driven) — attacker primes cache sets, waits, probes to detect victim access patterns. No shared memory required, works cross-core and cross-VM.
- **EVICT+RELOAD** (time-driven) — attacker evicts cache lines, measures total execution time to infer access patterns. Slower but requires no special instructions.
- **Cache trace correlation** (trace-driven) — correlates cache hit/miss traces with known inputs to reconstruct secret keys. Originally demonstrated on AES S-box lookups.

**Defenses:**

- **Cache coloring** against PRIME+PROBE — divide cache sets between processes via physical page coloring so attacker and victim never share sets.
- **Shared memory policy** against EVICT+RELOAD — disabling shared memory between untrusted processes removes the shared address requirement the attack depends on.
- **Constant-time execution** against time-driven attacks — ongoing exploration of RISC-V ISA extensions for hardware-guaranteed constant-time memory access.

*Research/exploratory layer — no automated gate.*

---

### L1 — Kernel Security

**Threat:** Malicious processes on a node crash the OS or escalate privileges before the node can participate in the distributed system.

**Hardening implemented, relative to Linux equivalents:**

| Feature | Linux Equivalent | Attack Closed |
|---|---|---|
| Stack canaries (SSP/StackGuard) | `-fstack-protector` | Stack buffer overflow exploitation |
| Real entropy source (`getentropy`) | `/dev/urandom` | Guessable canaries/keys |
| Per-process memory quota (`RLIMIT_AS`) | cgroups | Memory exhaustion crash |
| Per-process CPU quota (`RLIMIT_CPU`) | cgroups / CFS | CPU starvation |
| `setrlimit`/`getrlimit` syscalls | — | Resource-limit enforcement |
| ASLR (stack-base) | Kernel ASLR | Predictable memory layout exploitation |
| W^X enforcement | NX bit / mprotect | Injected shellcode execution |
| Fine-grained privileges (uid + capabilities) | Capabilities / seccomp | Privilege escalation via resource limits |
| Syscall argument validation | Thorough pointer checks | Kernel memory corruption |

All nine items above are implemented. Canaries are randomized from a real boot-time entropy pool (kernel side) and a per-exec entropy call (user side), so neither is a guessable constant. Resource limits are a genuine confinement boundary: raising a hard limit requires a capability that a parent process can permanently drop before running untrusted code. Privilege is unified around POSIX uid semantics — dropping root clears capabilities, in line with the Linux model.

**Deliberately out of scope:** file ownership/mode bits and `chown`/`chmod` (would need an on-disk inode redesign nothing in xv6 currently uses), group semantics, full POSIX.1e capability sets (a single effective bitmask suffices for the one capability in use), and syscall-filtering sandboxes like `pledge`/`seccomp` (a separate milestone). PIE and mmap-layout ASLR were also considered and deferred — xv6 has no shared libraries or `mmap`, so neither would add meaningful entropy over the stack-base randomization already in place.

**Gate:** `server/kernel_regression_test.py` boots xv6 under QEMU (no root needed) and drives in-guest test programs covering canary tripping, memory/CPU limit enforcement, limit inheritance across `fork()`, capability-drop enforcement, and thread-stack safety, plus a full `usertests` regression pass.

```bash
.venv/bin/python -m pytest server/kernel_regression_test.py -v --noconftest
```

---

### L2 — Communication Security

**Threat:** External packets (including from malicious cluster nodes) crash or exploit the node at the network layer.

**ARP:** Static entries for known nodes, dynamic ARP inspection against a trusted IP/MAC binding table, rate limiting per source, gratuitous ARP monitoring, and dynamic resolution (RFC 826) for unknown peers — a cache miss broadcasts a request and blocks until a validated reply is learned, with the static table remaining the trust anchor throughout.

**IP:** Ingress filtering (BCP38), bogon filtering, fragment offset validation (teardrop defense), reassembly session limits.

**ICMP:** Rate limiting per source, size validation (ping of death defense), directed broadcast blocking (smurf defense), type filtering.

**UDP:** Rate limiting per source IP (with a per-flow bulk-transfer exemption for declared, expected traffic), port filtering, payload length validation, checksum validation.

**RPC / Application layer:** Input sanitization on every handler, HMAC-based identity verification, per-node request rate limiting, timeout/retry limits, and privilege separation across handlers.

All items across all four sublayers are implemented and covered by automated differential testing: xv6's reaction to a fixed corpus of crafted packets is compared against RFC-derived expected outcomes, with a subset also checked live against a Linux ground truth over loopback.

**Gate:** `server/net_regression_test.py` (pytest + Scapy) fires ARP, IP, ICMP, and UDP test cases — including fragmentation edge cases, ingress/bogon filtering, and rate limiting — at xv6 over a tap interface. 60+ cases, all passing.

```bash
# host setup (once per boot):
sudo ip tuntap add dev tap0 mode tap 2>/dev/null || true
sudo ip addr add 10.0.0.1/24 dev tap0 2>/dev/null || true
sudo ip link set tap0 up

# terminal 1: boot xv6 with the echo responder running inside
make qemu-tap LAB=net NETDEV=tap
# xv6$ netecho 2000

# terminal 2: run the gate
sudo .venv/bin/python -m pytest server/net_regression_test.py -v

# optional: compare against live Linux over loopback
sudo .venv/bin/python -m pytest server/net_regression_test.py -v --differential
```

---

### L3 — Distributed Application Security (DistInf)

**Threat:** A malicious participant node lies — about its capabilities, about whether it completed work, or about the result it returns — in a cluster that uses the lower layers to run a real distributed workload.

**The application:** DistInf is a distributed LLM inference system, sharding a transformer's layers pipeline-parallel across xv6-riscv nodes in a ring topology. A master node holds the embedding table and classifier; each worker holds a contiguous range of transformer layers. A token's activation is passed hop-by-hop around the ring — master → worker 1 → ... → worker N → master — with the master sampling the next token and repeating.

Inference was chosen as the L3 workload because it's the first application that actually exercises the lower layers under real load: payloads larger than a single packet, timing constraints, and a topology where trust decisions have real consequences. The closest prior art (Exo) runs a similar pipeline-parallel design but has no authentication on peer discovery, no encryption, and no input validation on incoming tensors — precisely the gaps this stack is designed to close.

**Threat model:**

1. **Capability lying** — a node claims more memory/throughput than it has to win a favorable shard assignment. Addressed by validating claims with a sized memory probe rather than trusting self-reported specs — but only up to the probe's ceiling, which bounds what it can prove; see *What running them exposed* below.
2. **Identity spoofing** — a node impersonates another to hijack shard assignment or intercept activations. Closed with PSK/HMAC-based registration, extending the ARP-layer trust model up to the discovery/RPC layer.
3. **Result corruption** — a node executes correctly but reports a tampered result. RPC message integrity proves a result wasn't altered in transit, but not that the computation was honest; this is only partially addressed and is a natural next target (redundant assignment, cross-node consensus).
4. **Resource exhaustion via oversized/malformed payloads** — covered by the same `RLIMIT_AS`/`RLIMIT_CPU` enforcement from L1 and payload-length validation from L2, applied to inference-sized tensor payloads.

**What's implemented:** the full transport and lifecycle layer — ONC RPC over UDP with XDR encoding, two-phase authenticated worker registration (PSK/HMAC identity + sized capability probe), heartbeat-driven soft-state lifecycle with eviction and re-registration, and ring topology stitching that stays consistent across joins and losses. The inference pipeline itself — shard loading, layer assignment, and the per-hop activation forward pass — is implemented and runs correctly end to end: a distributed run reproduces a single-node reference token stream bit-for-bit at small model scale, and a larger model generates coherently across a multi-worker ring. Fault tolerance for a worker lost mid-generation is also implemented: a lost node is detected, the ring re-stitches around it, and the run either recovers or aborts cleanly within a bounded retry budget, rather than hanging. The adversarial cases run against the live ring rather than being argued on paper: a node that goes down, one that lies about its capabilities, and one that corrupts its own output are each injected at runtime and the cluster's actual response is asserted.

**What running them exposed.** Three defects, all found by making the tests real rather than by reading the code. **(1) The capability probe is weaker than threat-model item 1 claims.** It asks the node to back `min(claim, CAP_PROBE_CEILING_BYTES)` — 32 MB — so it can only ever establish "has at least the ceiling". A node with an ordinary 512 MB budget that advertises 1 GB satisfies the probe effortlessly and is accepted; only a node whose real budget falls *below* the ceiling is refused. The ceiling exists so a claim cannot be turned into an unbounded allocation demand, so this is a limit on what a bounded probe can mean rather than a coding error, but "closed by a sized probe" overstates it. Both sides of the boundary are now pinned by tests. Closing it properly needs a check the claimant cannot simply pass: measured throughput under real assignment, or attestation. **(2) A claim of 4096 MB silently became a claim of zero.** `worker_info_t.RAM` is a `uint32` and 4096 MB is exactly 2^32, so the multiply wrapped — turning the strongest possible lie into the weakest possible honest statement, which then sailed through a probe sized from it. The conversion now saturates. **(3) Result corruption is undetected, and that is not an artifact of a missing bounds check.** Sign-flipped, zeroed and slightly-offset activations are all finite and in range; nothing in the pipeline inspects payload *content*, only shape and provenance, so a registered node that computes a correct forward pass and then tampers with the result reaches the token stream unchallenged. This is item 3's gap, now regression-locked so it cannot close or widen unnoticed.

**Gates:**

- `server/rpc_regression_test.py` — drives the RPC/discovery wire protocol against a single live xv6 node (handshake, ring stitching, heartbeat/expiry, re-registration), from both the master and worker side.
- `server/distinf_regression_test.py` — boots a full multi-node ring (`server/distinf_sim.py`, root-free via QEMU multicast) and asserts the pipeline runs end to end and matches the single-node golden reference exactly. Behind `DISTINF_SCALE=1` it also drives the adversarial cases at five workers: a node killed mid-generation (mid-ring and tail, which fail through different mechanisms), a node that claims RAM it cannot back, and a node that corrupts its own output. Each pins what the cluster actually does, including where it has no defence.
- `server/malicious_testbed.py` — the narrated demo of the same adversarial scenarios, for walking through live or capturing as an artifact. Separate from the gate because it narrates rather than asserts, and because its source-spoofing scenario injects raw packets alongside a running sim rather than through a sim flag.
- `server/weightfetch_regression_test.py` — verifies the weight-fetch transport delivers byte-exact ranges of a model checkpoint, and that unmetered bulk transfer requires explicit declaration.

```bash
# full ring simulation, root-free:
.venv/bin/python server/distinf_sim.py --workers 2 --model 1 --steps 32 \
    --prompt "Once upon a time"

# adversarial node, refused before it is assigned a shard:
.venv/bin/python server/distinf_sim.py --workers 5 --adversary 3:lie-ram:1024/16

# regression gates:
.venv/bin/python -m pytest server/distinf_regression_test.py -v
.venv/bin/python -m pytest server/weightfetch_regression_test.py -v --noconftest
XV6_ROLE=master .venv/bin/python -m pytest server/rpc_regression_test.py -v --noconftest

# the adversarial cases (long: five workers, one ring per case):
DISTINF_SCALE=1 .venv/bin/python -m pytest server/distinf_regression_test.py -v
```

**v1 scope:** single user/prompt at a time, static layer assignment decided once at registration, sequential per-token pipeline (no batching), pipeline parallelism only (no tensor parallelism). Multi-user concurrency, tensor parallelism, dynamic mid-session reassignment, and a formal cross-group protocol spec are explicitly deferred.

---

## Repository Structure

```
kernel/         xv6 kernel source — net.c, e1000.c, security additions
user/           userspace — nettest.c, rpc.c/h, xdr.c/h, discovery.c/h, distinf.c,
                ftpclient.c/h (LLM-RFTP client), shardspike.c (weight-fetch probe),
                llama_core.c/h (transformer kernels, shared by the single-node
                runtime and the DistInf shards), llama.c (single-node driver:
                weight fetch, generate/chat loops, CLI)
server/         test infrastructure — net_regression_test.py (L2), kernel_regression_test.py (L1),
                rpc_regression_test.py + rpc_proto.py (L3), fuzz.py,
                distinf_sim.py (boots and drives the ring), distinf_regression_test.py,
                malicious_testbed.py (narrated adversarial-node demo),
                weightfetch_regression_test.py
server/models/  checkpoints served over LLM-RFTP — NOT in the tree (495 MB total,
                and stories110M.bin exceeds GitHub's 100 MB per-file limit).
                Run ./fetch-models.sh once to download and verify all three:
                tokenizer.bin (433,869 B), stories15M.bin (60,816,028 B),
                stories110M.bin (438,381,596 B)
```

## Branches

- `main` — upstream xv6-riscv, user-mode networking, `nettest grade` passing
- `tap-mode` — tap networking setup for differential testing, Scapy fuzzing infrastructure
- `distributed-inference` — L3 DistInf layer on top of `tap-mode`: RPC over UDP, worker discovery, registration, ring topology, heartbeat/re-registration, the L3 regression gate, and the full inference pipeline

## Setup

**User-mode (for running existing xv6 network tests):**
```bash
cd xv6-riscv
make qemu LAB=net
# in another terminal:
python3 nettest.py grade
```

**Weight server (LLM-RFTP, needed by `llama` and by any shard fetch):**
```bash
.venv/bin/python -m pip install scapy pytest coloredlogs
.venv/bin/python server/server.py    # serves file ids 1/2/3 on UDP 9999
```
`server.py` serves `stories15M.bin` (id 1), `tokenizer.bin` (id 2), and `stories110M.bin` (id 3). Run `./fetch-models.sh` once to populate `server/models/`; a correct start-up then logs three `Loaded file` lines and nothing else:

```
INFO Loaded file 1: 60816028 bytes, 118782 chunks, SHA-256=cd590644d963867a...
INFO Loaded file 2: 433869 bytes, 848 chunks, SHA-256=50a52ef822ee9e83...
INFO Loaded file 3: 438381596 bytes, 856215 chunks, SHA-256=515267168726a1ed...
INFO Server listening on 0.0.0.0:9999 (UDP)
```

Ids 1 and 2 are required: without them `server.py` refuses to start and names the file it wants. Any `ERROR` or missing-file line means a checkpoint is absent or was truncated; `./fetch-models.sh` re-downloads only what is missing or fails its checksum.

**Root-free single-node networking** (used by the weight-fetch spike and the L1 gate). QEMU's user-mode networking can be placed on the same prefix the kernel expects, avoiding a tap/bridge for anything that only talks to the host:
```bash
qemu-system-riscv64 ... -netdev user,id=net0,net=10.0.0.0/24,host=10.0.0.1 \
                        -device e1000,netdev=net0,bus=pcie.0
# guest stays 10.0.0.2, host is 10.0.0.1 — both inside the /24 the
# BCP38 ingress filter already accepts, so no filtering rules need relaxing.
```

**Tap mode (for differential testing and Scapy fuzzing):**
```bash
sudo ip tuntap add dev tap0 mode tap 2>/dev/null || true
sudo ip addr add 10.0.0.1/24 dev tap0 2>/dev/null || true
sudo ip link set tap0 up

cd xv6-riscv
make qemu-tap LAB=net NETDEV=tap

sudo python3 server/fuzz.py
sudo tcpdump -i tap0 -n -v
```

**Multi-node bridge (for DistInf).** `make bridge-setup` creates `br0` + `tap1..tap4` owned by the invoking user — the only step needing sudo. Prefer `server/distinf_sim.py` over driving nodes by hand (it's root-free via QEMU multicast); the manual recipe below is kept for debugging a single pair of nodes:
```bash
sudo ip link add br0 type bridge
sudo ip tuntap add dev tap1 mode tap && sudo ip link set tap1 master br0
sudo ip tuntap add dev tap2 mode tap && sudo ip link set tap2 master br0
sudo ip link set br0 up && sudo ip link set tap1 up && sudo ip link set tap2 up

# terminal 1 — master node (10.0.0.2):
make qemu-tap LAB=net NETDEV=tap TAPDEV=tap1
# xv6$ distinf --master 499

# terminal 2 — worker node (10.0.0.3):
make qemu-tap LAB=net NETDEV=tap TAPDEV=tap2
# xv6$ distinf --worker 10.0.0.2 499 1
```