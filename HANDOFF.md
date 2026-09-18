# Milestone 1 starter (prebuilt)

This is the system you characterise in Milestone 1. It boots and runs, but the
kernel is shipped as a **prebuilt binary, not source**. You study it through its
disassembly and the debugger, the same way you would study any binary you did not
write. That is deliberate: in Milestone 2 you repair a version of this kernel that
we break on purpose, and holding the correct source now would let you skip the work
by diffing.

## What ships, and what does not

| Component | Form |
|---|---|
| `xv6-riscv/kernel/kernel`, `xv6-riscv/fs.img` | prebuilt, ready to boot |
| `xv6-riscv/kernel/*.h`, `xv6-riscv/kernel/kernel.sym` | headers + symbol table (your map into the binary) |
| `xv6-riscv/user/*.c`, `xv6-riscv/user/*.h` | source (read normally) |
| `server/` | source (host tooling: weight server, ring simulator, regression suites) |
| `server/models/` | empty — run `./fetch-models.sh` to populate it |
| `warmup/` | a tiny call-graph tracing exercise; see `warmup/README.md` |
| kernel `.c` source, `user/crt0.c`, the build `Makefile` | **not included** (kept by staff) |

There is no `kernel/kernel.asm`: a source-annotated dump would defeat the point.
Generate your own with `objdump -d` (no source lines, which is the exercise).

## Prerequisites

```
# System tools: QEMU to run it, the RISC-V toolchain to study it.
sudo apt update
sudo apt install git build-essential gdb-multiarch qemu-system-misc \
     gcc-riscv64-linux-gnu binutils-riscv64-unknown-elf

# Python tools, in a virtual environment.
python3 -m venv .venv
source .venv/bin/activate      # activate it in every new terminal
pip install scapy pytest coloredlogs
```

## Running it

With `.venv` activated, `python` and `pytest` use it.

```
# single node: weight server first, then boot
python server/server.py                      # terminal 1
./boot.sh                                     # terminal 2, then at the xv6 prompt:
                                              #   llama -t 0 -n 32 -i "Once upon a time"

# the distributed ring (uses the prebuilt per-node images under server/prebuilt/)
python server/distinf_sim.py --workers 2 --model 1 --steps 32 --prompt "Once upon a time"

# under the debugger
./boot-gdb.sh                                 # halts on gdb port 26000
```

The three model checkpoints are **not** in this tree: together they are 495 MB, and
`stories110M.bin` alone is past GitHub's 100 MB per-file limit. Fetch them once, from
the repository root, before you start:

```
./fetch-models.sh            # downloads all three, verifies size + SHA-256 (~90 s)
./fetch-models.sh --check    # verify only, download nothing
```

A healthy weight server then logs three `Loaded file` lines and no errors. Ids 1 and 2
are required, so until you fetch them `server/server.py` refuses to start and names the
file it is missing. See `server/models/README.md` for the sizes and hashes.

## Studying the kernel binary

```
cd xv6-riscv
riscv64-unknown-elf-nm kernel/kernel | grep -E ' [tT] '        # functions + addresses
riscv64-unknown-elf-objdump -d kernel/kernel                   # full disassembly
riscv64-unknown-elf-objdump -d --disassemble=sys_exec kernel/kernel
```

The symbol table is intact, so every function has a name; follow the `jal`/`call`
targets to reconstruct what the code does.
