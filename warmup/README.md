# Warm-up: reconstruct a call graph from a binary

You get one compiled program, `build/challenge`, and one header, `include/api.h`.
The header declares a single function, `compute`. Everything `compute` calls
internally, how many helpers there are, which one recurses, which one is called
from more than one place, is **not** in the header and **not** shipped as source.
Working that out from the binary alone is the exercise.

This is the same skill you use on the kernel in the rest of Milestone 1, and again
in Milestone 3, practised where the answer is small enough to check by hand.

Target architecture: RISC-V, 64-bit. The binary carries no debug info, so there
are no source paths or line numbers; the **symbol table is intact**, so every
function still has a name.

## Static reconstruction (no execution needed)

Everything you need for the graded deliverable comes from static inspection:

```
riscv64-unknown-elf-nm build/challenge | grep -E ' [tT] '     # every function name
riscv64-unknown-elf-objdump -d build/challenge                # full disassembly
riscv64-unknown-elf-objdump -d --disassemble=compute build/challenge
```

In the disassembly, each `jal <target>` (jump-and-link) is a call. Follow them out
from `compute` and you have the graph: which functions it reaches, which function
jumps to itself (recursion), and which function is the target of a `jal` from two
different callers.

## Optional: under the debugger

If your environment can execute or single-step the binary, the same facts show up
dynamically:

```
riscv64-unknown-elf-gdb build/challenge      # or gdb-multiarch
(gdb) info functions
(gdb) disas compute
(gdb) break fib
(gdb) info registers ra a0
```

## What to hand in

A small Mermaid `flowchart` of the call graph rooted at `compute`, plus one
paragraph saying how you established, from the binary alone:

1. every function `compute` reaches,
2. which function is recursive, and
3. the function that is called from two different places.
