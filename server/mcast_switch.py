#!/usr/bin/env python3
"""
mcast_switch.py -- put the host weight server onto a QEMU multicast L2 segment,
without root.

Several QEMU instances that share `-netdev socket,mcast=ADDR:PORT` form one
Ethernet segment carried over a UDP multicast group -- no tap, no bridge, no
privilege. That segment connects the guests to each other, but not to the host,
so a guest cannot reach the LLM-RFTP weight server running here.

This program joins the same multicast group and becomes a node on that segment:
it answers ARP for the server's IP (RFC 826) and speaks IPv4/UDP, handing each
datagram to the *unmodified* server.py logic. The result is a fully root-free
multi-node DistInf simulation -- the alternative to the tap bridge, which needs
sudo.

How server.py is reused without modification: LLMRFTPServer sends replies through
`self.socket.sendto(payload, addr)`. We replace that socket with an adapter whose
sendto() wraps the payload in Ethernet/IPv4/UDP and emits it on the segment, so
every META/DATA/RETRANS path in server.py works untouched.

Performance -- why this is hand-rolled rather than scapy. A model-weight fetch is
hundreds of thousands of 512-byte chunks; the switch sees every one of them, plus
its own replies echoed back by multicast loopback, plus all guest-to-guest
traffic. Dissecting and building each frame with scapy served under ~66 KB/s --
too slow to deliver the 110M master's 93 MB embedding before the fetch timed out.
This module therefore works directly on frame bytes: a cheap pre-filter drops the
frames that are not for the weight server before any parsing, requests are parsed
by fixed header offset, and replies are built with struct + hand-computed IPv4
(RFC 791) and UDP (RFC 768) checksums. No scapy, no per-frame object graph.

Frame format on the wire: QEMU's mcast socket carries one raw Ethernet frame per
UDP datagram, no length prefix (confirmed by capture). Guests emit standard
Ethernet II + IPv4 (no options) + UDP, so a 42-byte fixed header precedes the
payload.
"""

import os
import socket
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import server as rftp   # noqa: E402  (the unmodified weight server)

SERVER_IP = "10.0.0.1"
SERVER_MAC = "52:54:00:aa:bb:cc"     # synthetic; only this segment ever sees it
RFTP_PORT = 9999

# Receive buffer for the multicast socket. The default (~200 KB) overflows while
# the switch is busy serving one range, so the kernel silently drops the guest's
# next requests and the transfer cannot converge. 16 MB gives the switch room to
# fall behind briefly without losing requests.
RCVBUF_BYTES = 16 * 1024 * 1024

# Wire constants
ETH_HDR = 14
IP_HDR = 20                          # IPv4 without options (what the guests send)
UDP_HDR = 8
L2L3L4 = ETH_HDR + IP_HDR + UDP_HDR  # 42-byte fixed header before any payload
ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_ARP = 0x0806
IPPROTO_UDP = 17

SERVER_MAC_BYTES = bytes.fromhex(SERVER_MAC.replace(":", ""))
SERVER_IP_BYTES = socket.inet_aton(SERVER_IP)


def inet_checksum(data):
    """
    16-bit one's-complement checksum (RFC 1071), used for the IPv4 and UDP
    headers. @data is padded to an even length internally.

    Returns the checksum as an int in host order (callers pack it big-endian).
    """
    if len(data) & 1:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    total = (total & 0xffff) + (total >> 16)
    total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def build_frame(dst_mac, src_mac, src_ip, dst_ip, sport, dport, payload):
    """
    Assemble one Ethernet II + IPv4 + UDP frame around @payload.

    Replaces scapy's frame assembly on the hot path (one call per DATA_PACKET,
    hundreds of thousands per fetch). The UDP checksum is mandatory here, not
    optional: xv6's hardened receive path validates it (RFC 768) and drops a
    datagram whose checksum is wrong, so a hand-built frame with a bad checksum
    would be silently discarded by the guest.

    Checks performed (by construction, not at runtime):
      1. IPv4 total length and UDP length are set from the actual payload size.
      2. The IPv4 header checksum covers the 20-byte header (RFC 791 §3.1).
      3. The UDP checksum covers the pseudo-header + UDP header + payload
         (RFC 768); a computed value of 0 is sent as 0xFFFF per the RFC.
    """
    udp_len = UDP_HDR + len(payload)
    ip_len = IP_HDR + udp_len

    # UDP checksum over the IPv4 pseudo-header + UDP header (checksum field 0) + data
    pseudo = src_ip + dst_ip + struct.pack("!BBH", 0, IPPROTO_UDP, udp_len)
    udp_no_ck = struct.pack("!HHHH", sport, dport, udp_len, 0)
    udp_ck = inet_checksum(pseudo + udp_no_ck + payload) or 0xffff
    udp = struct.pack("!HHHH", sport, dport, udp_len, udp_ck) + payload

    # IPv4 header: ver/IHL, DSCP, total len, id, flags/frag, TTL, proto, ck, addrs
    ip_no_ck = struct.pack("!BBHHHBBH", 0x45, 0, ip_len, 0, 0, 64, IPPROTO_UDP, 0) \
        + src_ip + dst_ip
    ip_ck = inet_checksum(ip_no_ck)
    ip = struct.pack("!BBHHHBBH", 0x45, 0, ip_len, 0, 0, 64, IPPROTO_UDP, ip_ck) \
        + src_ip + dst_ip

    eth = dst_mac + src_mac + struct.pack("!H", ETHERTYPE_IPV4)
    return eth + ip + udp


class FrameSocket:
    """
    Adapter presented to LLMRFTPServer as its `self.socket`.

    Only sendto() is used by the server's handlers, and only for replies to a
    known client. Each call becomes one Ethernet/IPv4/UDP frame addressed to that
    client's learned MAC and multicast onto the segment.

    Checks performed:
      1. The destination must be a client we have already seen a frame from, so
         its MAC is known; an unknown destination is dropped rather than
         broadcast (the server only ever replies to a caller).
    """

    def __init__(self, switch):
        self.switch = switch

    def sendto(self, payload, addr):
        ip, port = addr
        mac = self.switch.arp_table.get(ip)
        if mac is None:
            return 0
        frame = build_frame(mac, SERVER_MAC_BYTES, SERVER_IP_BYTES,
                            socket.inet_aton(ip), RFTP_PORT, port, payload)
        self.switch.tx(frame)
        return len(payload)


class McastSwitch:
    """The host's presence on the QEMU multicast Ethernet segment."""

    def __init__(self, group, port, verbose=False):
        self.group = group
        self.port = port
        self.verbose = verbose
        self.arp_table = {}   # guest IP (str) -> guest MAC (bytes), learned from traffic

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # A large receive buffer so a burst of requests is not dropped while the
        # switch is busy sending an earlier range's data. The kernel may clamp the
        # request (net.core.rmem_max); log what was actually granted.
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, RCVBUF_BYTES)
        self.granted_rcvbuf = self.sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
        self.sock.bind(("", port))
        mreq = struct.pack("4sl", socket.inet_aton(group), socket.INADDR_ANY)
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        # Loopback must stay on: on a single host, multicast reaches the QEMU
        # guests only if the sender enables it. It also echoes our own frames back
        # to us, which the pre-filter in handle() discards cheaply.
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)

        # The weight server, with its socket replaced by our frame adapter. None
        # of its handler code changes.
        self.rftp = rftp.LLMRFTPServer(port=RFTP_PORT)
        self.rftp.socket = FrameSocket(self)

    def tx(self, frame_bytes):
        self.sock.sendto(frame_bytes, (self.group, self.port))

    def _log(self, *a):
        if self.verbose:
            print("[switch]", *a, flush=True)

    def _send_arp_reply(self, dst_mac, target_ip_bytes, target_mac_bytes):
        """Emit an ARP reply (RFC 826, op=2): SERVER_IP is at SERVER_MAC."""
        arp = struct.pack("!HHBBH", 1, ETHERTYPE_IPV4, 6, 4, 2) \
            + SERVER_MAC_BYTES + SERVER_IP_BYTES \
            + target_mac_bytes + target_ip_bytes
        frame = dst_mac + SERVER_MAC_BYTES + struct.pack("!H", ETHERTYPE_ARP) + arp
        self.tx(frame)

    def handle(self, raw):
        """
        Dispatch one Ethernet frame off the segment, working on raw bytes.

        A pre-filter runs before any parsing so the common frames -- our own
        replies echoed back by multicast loopback, and traffic between guests --
        are dropped in a few byte comparisons rather than parsed.

        Checks performed:
          1. Frame is long enough to hold an Ethernet header.
          2. Frames sourced by us (src MAC == SERVER_MAC) are our own loopback
             echoes and are skipped -- this is the bulk of the traffic during a
             fetch and must never be parsed.
          3. ARP request (op=1) for SERVER_IP -> reply with SERVER_MAC and learn
             the sender's IP->MAC binding (RFC 826).
          4. IPv4/UDP unicast to SERVER_MAC and RFTP_PORT -> learn the sender's
             binding, then hand the UDP payload (fixed 42-byte header offset, no
             IP options) to the unchanged server logic; send any reply back.
          5. Anything else (guest-to-guest, other protocols) is ignored.
        """
        if len(raw) < ETH_HDR:
            return

        src_mac = raw[6:12]
        if src_mac == SERVER_MAC_BYTES:          # our own loopback echo
            return

        ethertype = (raw[12] << 8) | raw[13]
        dst_mac = raw[0:6]

        if ethertype == ETHERTYPE_ARP:
            # ARP is small and rare (once per guest); parse the fixed fields.
            arp = raw[ETH_HDR:ETH_HDR + 28]
            if len(arp) < 28:
                return
            op = (arp[6] << 8) | arp[7]
            sender_mac = arp[8:14]
            sender_ip = arp[14:18]
            target_ip = arp[24:28]
            if op == 1 and target_ip == SERVER_IP_BYTES:
                self.arp_table[socket.inet_ntoa(sender_ip)] = sender_mac
                self._send_arp_reply(sender_mac, sender_ip, sender_mac)
                self._log("ARP: told", socket.inet_ntoa(sender_ip), "->", SERVER_IP)
            return

        if ethertype != ETHERTYPE_IPV4 or dst_mac != SERVER_MAC_BYTES:
            return                                # not addressed to the weight server

        if len(raw) < L2L3L4:
            return
        if raw[ETH_HDR + 9] != IPPROTO_UDP:       # IPv4 protocol field
            return
        dst_ip = raw[ETH_HDR + 16:ETH_HDR + 20]
        if dst_ip != SERVER_IP_BYTES:
            return

        src_ip = raw[ETH_HDR + 12:ETH_HDR + 16]
        udp = ETH_HDR + IP_HDR
        sport = (raw[udp] << 8) | raw[udp + 1]
        dport = (raw[udp + 2] << 8) | raw[udp + 3]
        if dport != RFTP_PORT:
            return
        udp_len = (raw[udp + 4] << 8) | raw[udp + 5]
        payload = raw[L2L3L4:L2L3L4 + (udp_len - UDP_HDR)]

        src_ip_str = socket.inet_ntoa(src_ip)
        self.arp_table[src_ip_str] = src_mac
        resp = self.rftp.handle_message(payload, (src_ip_str, sport))
        if resp:
            self.rftp.socket.sendto(resp, (src_ip_str, sport))

    def run(self):
        print(f"[switch] on {self.group}:{self.port}, serving LLM-RFTP as "
              f"{SERVER_IP} ({SERVER_MAC}); SO_RCVBUF={self.granted_rcvbuf}", flush=True)
        while True:
            raw, _ = self.sock.recvfrom(65535)
            try:
                self.handle(raw)
            except Exception as e:      # a malformed frame must not kill the switch
                self._log("frame error:", e)


def main():
    import argparse
    ap = argparse.ArgumentParser(description="Host presence on a QEMU mcast L2 segment")
    ap.add_argument("--group", default="230.0.0.1")
    ap.add_argument("--port", type=int, default=5678)
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()
    McastSwitch(args.group, args.port, args.verbose).run()


if __name__ == "__main__":
    main()
