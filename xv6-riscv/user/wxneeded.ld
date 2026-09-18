/*
 * Link script for binaries that need a writable+executable (OMAGIC) segment and must
 * therefore be exempted from the kernel's W^X enforcement (kernel/exec.c).
 *
 * It does two things:
 *   1. merges text + read-only + data + bss into ONE segment (FLAGS(7) = R+W+X), the
 *      OMAGIC layout that keeps the binary tiny -- forktest is built this way so enough
 *      copies fit to fill the proc table; and
 *   2. emits a PT_OPENBSD_WXNEEDED (0x65a3dbe7) program header -- the OpenBSD link-time
 *      "wxneeded" tag. exec() scans for this header and, only when present, allows the
 *      W+X segment above; every other binary is held to write-xor-execute.
 *
 * Without this tag the merged RWX segment would be refused by exec (POSIX [EACCES]).
 */

OUTPUT_ARCH( "riscv" )
ENTRY( main )

PHDRS
{
  text     PT_LOAD    FLAGS(7);   /* one R+W+X (OMAGIC) load segment */
  wxneeded 0x65a3dbe7;            /* PT_OPENBSD_WXNEEDED: the W^X exemption marker */
}

SECTIONS
{
  . = 0x0;

  .text : {
    *(.text .text.*)
    *(.srodata .srodata.*)
    *(.rodata .rodata.*)
    *(.eh_frame .eh_frame.*)
    *(.sdata .sdata.*)
    *(.data .data.*)
    *(.sbss .sbss.*)
    *(.bss .bss.*)
  } :text

  /* One-byte section assigned to the wxneeded header so ld actually emits the phdr. */
  .wxneeded : { . += 1; } :wxneeded

  PROVIDE(end = .);
}
