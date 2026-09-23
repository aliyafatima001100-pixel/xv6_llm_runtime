#!/usr/bin/env bash
# Boot the prebuilt kernel halted, waiting for a debugger on TCP port 26000.
# In another terminal:
#   gdb-multiarch xv6-riscv/kernel/kernel      # or riscv64-unknown-elf-gdb
#   (gdb) target remote localhost:26000
#   (gdb) break exec
#   (gdb) continue
# Exit QEMU with:  Ctrl-A  then  x
# Networking: QEMU's user-mode (SLIRP) network is placed on 10.0.0.0/24 with the
# host at 10.0.0.1 -- the prefix this kernel is built for. The guest's IP is the
# compile-time constant 10.0.0.2 (kernel/net.h XV6_IP_D) and the weight server is
# 10.0.0.1:9999 (user/ftpclient.h FTP_SERVER_IP), so both sit inside the /24 that
# the BCP38 ingress filter already accepts and no filtering rule needs relaxing.
# Without net=/host= SLIRP defaults to 10.0.2.0/24, nothing answers ARP for
# 10.0.0.1, and every fetch dies with "arp_lookup: resolution timed out".
# See README.md, "Root-free single-node networking".
set -euo pipefail
cd "$(dirname "$0")/xv6-riscv"
exec qemu-system-riscv64 -machine virt -bios none -kernel kernel/kernel \
  -m 256M -smp "${XV6_CPUS:-1}" -nographic -global virtio-mmio.force-legacy=false \
  -drive file=fs.img,if=none,format=raw,id=x0 \
  -device virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0 \
  -netdev user,id=net0,net=10.0.0.0/24,host=10.0.0.1 \
  -device e1000,netdev=net0,bus=pcie.0,romfile= \
  -gdb tcp::26000 -S
