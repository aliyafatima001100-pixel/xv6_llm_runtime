"""
Differential regression gate for the xv6 UDP receive path (kernel/net.c: ip_rx).

A fixed corpus of crafted UDP/IPv4 datagrams is injected over the tap interface;
xv6's observable reaction must match the expected outcome, which is Linux's
ground-truth behavior per RFC 768 / 791 / 1122. Each future hardening check should
land with a new row here.

Run (xv6 booted in tap mode with `netecho 2000`, tap0 up, as root):
    sudo pytest server/net_regression_test.py -v
    sudo pytest server/net_regression_test.py -v --differential   # also vs host Linux
"""

import time

import pytest
from scapy.all import Ether, IP, UDP, ICMP, ARP, Raw, IPOption, AsyncSniffer, sendp

from conftest import (probe, linux_probe, xv6_target,
                      ECHO_PORT, CLOSED_PORT, DELIVERED, DROP, ICMP_UNREACH, ECHO_REPLY,
                      IFACE, XV6_IP, XV6_MAC, HOST_IP, TIMEOUT, ARP_REPLY)


def _frame(t, ip_kwargs, udp_kwargs, payload=b"hello123"):
    return (Ether(dst=t.mac)
            / IP(src=t.src, dst=t.ip, **ip_kwargs)
            / UDP(sport=12345, **udp_kwargs)
            / Raw(payload))


# id -> (builder(target) -> frame, expected outcome).
# chksum=0 on the length-focused cases tells xv6 "no checksum" (RFC 768), isolating
# the length logic from the checksum path so a drop is attributable to length alone.
CASES = {
    # --- well-formed datagrams to the bound port -> delivered ---
    "valid":             (lambda t: _frame(t, {}, {"dport": ECHO_PORT}), DELIVERED),
    "empty_payload":     (lambda t: _frame(t, {}, {"dport": ECHO_PORT}, b""), DELIVERED),
    "ip_options":        (lambda t: _frame(t, {"options": [IPOption(b"\x94\x04\x00\x00")]},
                                           {"dport": ECHO_PORT, "chksum": 0}), DELIVERED),
    "trailing_octets":   (lambda t: _frame(t, {}, {"dport": ECHO_PORT, "len": 12, "chksum": 0},
                                           b"0123456789abcdef"), DELIVERED),

    # --- malformed datagrams to the bound port -> silent drop ---
    "bad_checksum":      (lambda t: _frame(t, {}, {"dport": ECHO_PORT, "chksum": 0xdead}), DROP),
    "length_too_long":   (lambda t: _frame(t, {}, {"dport": ECHO_PORT, "len": 100, "chksum": 0}), DROP),
    "ip_total_overclaim":(lambda t: _frame(t, {"len": 4000}, {"dport": ECHO_PORT, "chksum": 0}), DROP),
    "ip_version_not_4":  (lambda t: _frame(t, {"version": 6}, {"dport": ECHO_PORT, "chksum": 0}), DROP),
    "ihl_too_small":     (lambda t: _frame(t, {"ihl": 4}, {"dport": ECHO_PORT, "chksum": 0}), DROP),

    # --- closed port: well-formed -> ICMP, malformed -> silent drop ---
    # (length/checksum validation runs before the port check, so a malformed
    #  datagram to a closed port is dropped silently with no ICMP)
    "closed_wellformed": (lambda t: _frame(t, {}, {"dport": CLOSED_PORT}), ICMP_UNREACH),
    "closed_bad_length": (lambda t: _frame(t, {}, {"dport": CLOSED_PORT, "len": 100, "chksum": 0}), DROP),
    "closed_bad_cksum":  (lambda t: _frame(t, {}, {"dport": CLOSED_PORT, "chksum": 0xdead}), DROP),
    
}
_LOOPBACK_SKIP = {
    "valid": (
        "linux_probe sends from LINUX_SRC (10.0.0.50) to HOST_IP (10.0.0.1) via loopback; "
        "Linux lo does not enforce BCP38 ingress filtering, so the result is not a "
        "faithful RFC reference for this path — covered by test_xv6_matches_expected"
    ),
    "empty_payload": (
        "same loopback / ingress-filter divergence as 'valid'; "
        "covered by test_xv6_matches_expected"
    ),
    "ip_options": (
        "same loopback / ingress-filter divergence as 'valid'; "
        "covered by test_xv6_matches_expected"
    ),
    "trailing_octets": (
        "same loopback / ingress-filter divergence as 'valid'; "
        "covered by test_xv6_matches_expected"
    ),
    "closed_wellformed": (
        "Linux lo does not send ICMP port-unreachable for unbound UDP ports in the "
        "same way xv6 does (no userspace listener on CLOSED_PORT on the host); "
        "covered by test_xv6_matches_expected"
    ),
}

@pytest.mark.parametrize("name", list(CASES), ids=list(CASES))
def test_xv6_matches_expected(name):
    build, expected = CASES[name]
    observed = probe(build(xv6_target()))
    assert observed == expected, f"{name}: expected {expected}, got {observed}"


@pytest.mark.parametrize("name", list(CASES), ids=list(CASES))
def test_xv6_matches_linux(name, differential):
    if not differential:
        pytest.skip("pass --differential to compare against the live host Linux stack")
    if name in _LOOPBACK_SKIP:
        pytest.skip(f"{name}: {_LOOPBACK_SKIP[name]}; "
                    "not comparable via lo (covered by test_xv6_matches_expected)")
    build, _ = CASES[name]
    xv6 = probe(build(xv6_target()))
    linux = linux_probe(build)
    assert xv6 == linux, f"{name}: xv6={xv6} linux={linux}"


# ---------------------------------------------------------------------------
# ICMP defenses (kernel/net.c: icmp_rx). A hardened Echo responder answers a ping
# addressed to our unicast IP (RFC 1122 3.2.2.6) but only after four guards. Each
# case below exercises one check in icmp_rx's chain and asserts the wire reaction:
#
#   case                      check exercised                          expected
#   ------------------------  ---------------------------------------  ----------
#   icmp_echo_valid           happy path: Echo Request to our IP       ECHO_REPLY
#   icmp_oversized            size: icmp_len > ICMP_MAX_LEN (RFC 791)  DROP
#   icmp_bad_checksum         ICMP checksum != 0 (RFC 792)             DROP
#   icmp_timestamp_type       type filtering: non-Echo (RFC 1122 3.2.2) DROP
#   icmp_limited_broadcast    smurf: dst 255.255.255.255 (RFC 1122/2644) DROP
#   icmp_directed_broadcast   smurf: dst 10.0.0.255                    DROP
#   (test_icmp_rate_limit)    generation rate limit (RFC 1812 4.3.2.8) <= burst
#
# Kept in a separate corpus so the UDP gate and the UDP-only --differential path
# above are untouched.
# ---------------------------------------------------------------------------

def _icmp(t, ip_kwargs=None, icmp_kwargs=None, payload=b"ping-payload"):
    ipargs = {"src": t.src, "dst": t.ip}
    ipargs.update(ip_kwargs or {})
    icmpargs = {"type": 8, "id": 0x1234, "seq": 1}   # Echo Request by default
    icmpargs.update(icmp_kwargs or {})
    return (Ether(dst=t.mac)
            / IP(**ipargs)
            / ICMP(**icmpargs)
            / Raw(payload))


ICMP_CASES = {
    # well-formed ping to our unicast IP -> Echo Reply
    "icmp_echo_valid":       (lambda t: _icmp(t), ECHO_REPLY),

    # size validation: ICMP message > ICMP_MAX_LEN (1024) -> drop (ping-of-death guard)
    "icmp_oversized":        (lambda t: _icmp(t, payload=b"A" * 1100), DROP),

    # checksum: a corrupted ICMP checksum -> drop (RFC 792)
    "icmp_bad_checksum":     (lambda t: _icmp(t, icmp_kwargs={"chksum": 0xdead}), DROP),

    # type filtering: a non-Echo type (13 = Timestamp) -> silent drop (RFC 1122 3.2.2)
    "icmp_timestamp_type":   (lambda t: _icmp(t, icmp_kwargs={"type": 13}), DROP),

    # smurf / directed-broadcast: echo to a broadcast dst -> no reply (we are not an amplifier)
    "icmp_limited_broadcast":  (lambda t: _icmp(t, ip_kwargs={"dst": "255.255.255.255"}), DROP),
    "icmp_directed_broadcast": (lambda t: _icmp(t, ip_kwargs={"dst": "10.0.0.255"}), DROP),
}


@pytest.mark.parametrize("name", list(ICMP_CASES), ids=list(ICMP_CASES))
def test_xv6_icmp_defenses(name):
    build, expected = ICMP_CASES[name]
    observed = probe(build(xv6_target()))
    assert observed == expected, f"{name}: expected {expected}, got {observed}"


def test_icmp_rate_limit():
    """A tight burst of pings from one source yields at most ICMP_RL_BURST (8) replies;
    the rest are dropped by the generation rate limiter (RFC 1812 4.3.2.8). A fresh
    source IP is used so the test owns a full token bucket regardless of prior cases."""
    burst = 8          # must match ICMP_RL_BURST in kernel/net.c
    n = 20
    src = "10.0.0.77"  # fresh source -> fresh bucket
    sniffer = AsyncSniffer(iface=IFACE, filter=f"src host {XV6_IP} and icmp", store=True)
    sniffer.start()
    time.sleep(0.1)
    # Build list first, then send in one sendp() call so Scapy holds the socket
    # open for the whole batch — individual per-packet calls are slow enough that
    # xv6 ticks (10 Hz) pass mid-loop, refilling tokens and inflating the reply count.
    pkts = [Ether(dst=XV6_MAC) / IP(src=src, dst=XV6_IP)
            / ICMP(type=8, id=0x55, seq=i) / Raw(b"flood")
            for i in range(n)]
    sendp(pkts, iface=IFACE, verbose=0)
    time.sleep(TIMEOUT)
    replies = [r for r in (sniffer.stop() or [])
               if r.haslayer(ICMP) and int(r[ICMP].type) == 0]
    assert 1 <= len(replies) <= burst, \
        f"rate limit: expected 1..{burst} echo replies for {n} pings, got {len(replies)}"

def test_udp_rate_limit():
    """A tight burst of UDP datagrams from one source yields at most UDP_RL_BURST (8)
    delivered packets; the rest are dropped by the rate limiter. A fresh source IP is
    used so the test owns a full token bucket regardless of prior cases."""
    burst = 8          # must match UDP_RL_BURST in kernel/net.c
    n = 20
    src = "10.0.0.78"  # fresh source -> fresh bucket (distinct from ICMP rate limit test)
    sniffer = AsyncSniffer(iface=IFACE, filter=f"src host {XV6_IP} and udp", store=True)
    sniffer.start()
    time.sleep(0.1)
    # Build list first, then send in one sendp() call so Scapy holds the socket
    # open for the whole batch — individual per-packet calls are slow enough that
    # xv6 ticks (10 Hz) pass mid-loop, refilling tokens and inflating the reply count.
    pkts = [Ether(dst=XV6_MAC) / IP(src=src, dst=XV6_IP)
            / UDP(sport=12345, dport=ECHO_PORT) / Raw(b"flood")
            for i in range(n)]
    sendp(pkts, iface=IFACE, verbose=0)
    time.sleep(TIMEOUT)
    replies = [r for r in (sniffer.stop() or [])
               if r.haslayer(UDP) and r[IP].src == XV6_IP]
    assert 1 <= len(replies) <= burst, \
        f"rate limit: expected 1..{burst} echo replies for {n} datagrams, got {len(replies)}"
    
# ---------------------------------------------------------------------------
# Ingress filtering tests (BCP38 / RFC 2827 + RFC 3704)
# Validates that packets arriving on the tap interface with source IPs that
# cannot legitimately originate from that interface are silently dropped.
#
# xv6 is on 10.0.2.0/24 (qemu user-net default). Any source outside that
# prefix arriving on the single NIC is a BCP38 violation and must be dropped.
#
#   case                        source IP           expected
#   --------------------------  ------------------  ----------
#   ingress_valid               10.0.0.50           DELIVERED   (in-prefix — legitimate)
#   ingress_rfc1918_10          10.1.0.1            DROP        (different /8 block)
#   ingress_rfc1918_172         172.16.0.1          DROP        (RFC 1918 — wrong net)
#   ingress_rfc1918_192         192.168.1.1         DROP        (RFC 1918 — wrong net)
#   ingress_loopback            127.0.0.1           DROP        (loopback — RFC 1122)
#   ingress_link_local          169.254.0.1         DROP        (link-local — RFC 3927)
#   ingress_public_routable     8.8.8.8             DROP        (public IP, wrong net)
#   ingress_multicast           224.0.0.1           DROP        (multicast src — RFC 1112)
#   ingress_this_network        0.0.0.1             DROP        (0.x.x.x — RFC 1122)
#   ingress_broadcast_src       255.255.255.255     DROP        (broadcast src — invalid)
#   ingress_documentation       192.0.2.1           DROP        (TEST-NET-1 — RFC 5737)
#   ingress_cgnat               100.64.0.1          DROP        (CGNAT — RFC 6598)
#   ingress_spoofed_own_ip      10.0.0.2            DROP        (xv6's own IP as src — land attack)
# ---------------------------------------------------------------------------

def _ingress_frame(t, src_ip, dport=ECHO_PORT):
    """Build a well-formed UDP frame with an arbitrary source IP.
    The UDP checksum is zeroed (RFC 768 allows it) so a drop is attributable
    solely to the ingress filter, not a checksum mismatch."""
    return (Ether(dst=t.mac)
            / IP(src=src_ip, dst=t.ip)
            / UDP(sport=12345, dport=dport, chksum=0)
            / Raw(b"bcp38test"))


INGRESS_CASES = {
    "ingress_valid":            (lambda t: _ingress_frame(t, "10.0.0.50"),       DELIVERED),
    "ingress_rfc1918_10":       (lambda t: _ingress_frame(t, "10.1.0.1"),        DROP),
    "ingress_rfc1918_172":      (lambda t: _ingress_frame(t, "172.16.0.1"),      DROP),
    "ingress_rfc1918_192":      (lambda t: _ingress_frame(t, "192.168.1.1"),     DROP),
    "ingress_loopback":         (lambda t: _ingress_frame(t, "127.0.0.1"),       DROP),
    "ingress_link_local":       (lambda t: _ingress_frame(t, "169.254.0.1"),     DROP),
    "ingress_multicast":        (lambda t: _ingress_frame(t, "224.0.0.1"),       DROP),
    "ingress_this_network":     (lambda t: _ingress_frame(t, "0.0.0.1"),         DROP),
    "ingress_broadcast_src":    (lambda t: _ingress_frame(t, "255.255.255.255"), DROP),
    "ingress_documentation":    (lambda t: _ingress_frame(t, "192.0.2.1"),       DROP),
    "ingress_cgnat":            (lambda t: _ingress_frame(t, "100.64.0.1"),      DROP),
    "ingress_public_routable":  (lambda t: _ingress_frame(t, "8.8.8.8"),         DROP),
    "ingress_spoofed_own_ip":   (lambda t: _ingress_frame(t, XV6_IP),            DROP),
}

# The loopback skip rationale does not apply here: ingress filtering happens
# before the stack, so the CHECKSUM_UNNECESSARY quirk is irrelevant. All
# ingress cases are valid --differential comparisons EXCEPT the valid case
# (Linux lo delivers it fine) and spoofed_own_ip (Linux lo accepts it —
# lo does not run ingress RPF, so this is an expected divergence).
_INGRESS_LOOPBACK_SKIP = {
    "ingress_valid":            "xv6 ip is forbidded range, so linux drops",
    # "ingress_spoofed_own_ip":   "Linux lo does not enforce RPF for locally-addressed src; "
    #                             "xv6 drops per BCP38 (RFC 2827 §3)",
    # "ingress_rfc1918_10":       "Linux lo performs no ingress filtering; delivers any src IP",
    # "ingress_rfc1918_172":      "Linux lo performs no ingress filtering; delivers any src IP",
    # "ingress_rfc1918_192":      "Linux lo performs no ingress filtering; delivers any src IP",
    # "ingress_loopback":         "Linux lo performs no ingress filtering; delivers any src IP",
    # "ingress_link_local":       "Linux lo performs no ingress filtering; delivers any src IP",
    # "ingress_multicast":        "Linux lo performs no ingress filtering; delivers any src IP",
    # "ingress_this_network":     "Linux lo performs no ingress filtering; delivers any src IP",
    # "ingress_broadcast_src":    "Linux lo performs no ingress filtering; delivers any src IP",
    # "ingress_documentation":    "Linux lo performs no ingress filtering; delivers any src IP",
    # "ingress_cgnat":            "Linux lo performs no ingress filtering; delivers any src IP",
    # "ingress_public_routable":  "Linux lo performs no ingress filtering; delivers any src IP",
}


@pytest.mark.parametrize("name", list(INGRESS_CASES), ids=list(INGRESS_CASES))
def test_xv6_ingress_filter(name):
    """BCP38 / RFC 2827: source address must be within the expected prefix
    for the arriving interface. Spoofed or misrouted sources are silently dropped."""
    build, expected = INGRESS_CASES[name]
    observed = probe(build(xv6_target()))
    assert observed == expected, f"{name}: expected {expected}, got {observed}"


@pytest.mark.parametrize("name", list(INGRESS_CASES), ids=list(INGRESS_CASES))
def test_xv6_ingress_filter_vs_linux(name, differential):
    """Cross-check xv6 ingress filter behavior against the live Linux stack.
    Skip cases where Linux lo is not a faithful RFC reference."""
    if not differential:
        pytest.skip("pass --differential to compare against the live host Linux stack")
    if name in _INGRESS_LOOPBACK_SKIP:
        pytest.skip(f"{name}: {_INGRESS_LOOPBACK_SKIP[name]}; "
                    "not comparable via lo (covered by test_xv6_ingress_filter)")
    build, _ = INGRESS_CASES[name]
    xv6 = probe(build(xv6_target()))
    linux = linux_probe(build)
    assert xv6 == linux, f"{name}: xv6={xv6} linux={linux}"

# ---------------------------------------------------------------------------
# Bogon tests (BCP38 / RFC 2827 + RFC 3704)
# Validates that packets arriving on the tap interface with source IPs that
# should never appear on the wire (RFC 1122, RFC 1918, RFC 3927, RFC 5737, RFC 6598)
# are silently dropped. This is a stricter filter than the ingress filter above,
# which only drops packets with out-of-prefix source IPs; the bogon filter also
# drops in-prefix but reserved/forbidden source IPs. Each case below exercises one 
# of the bogon checks in ip_rx's chain and asserts the wire reaction:
#
#   case                        source IP           expected
#   --------------------------  ------------------  ----------
#   bogon_rfc1122               0.0.0.0             DROP        (RFC 1122: "This Network")
#   bogon_rfc6598               100.64.0.3          DROP        (RFC 6598: CGNAT space)
#   bogon_rfc1918_172           172.16.1.4          DROP        (RFC 1918: private net, wrong net)
#   bogon_rfc1918_192           192.168.14.4        DROP        (RFC 1918: private net, wrong net)
#   bogon_rfc3927               169.254.9.25        DROP        (RFC 3927: link-local)
#   bogon_rfc5737               192.0.2.1           DROP        (RFC 5737: TEST-NET)
#   bogon_rfc5771               224.0.0.1           DROP        (RFC 5771: multicast)
#  bogon_broadcast_src          255.255.255.255     DROP        (invalid broadcast source)
# ---------------------------------------------------------------------------

def _bogon_frame(t, src_ip, dport=ECHO_PORT):
    """Build a well-formed UDP frame with an arbitrary source IP."""
    return (Ether(dst=t.mac)
            / IP(src=src_ip, dst=t.ip)
            / UDP(sport=12346, dport=dport)
            / Raw(b"bogontest"))

BOGON_CASES = {
    "bogon_rfc1122":     (lambda t: _bogon_frame(t, "0.0.0.0"), DROP),
    "bogon_rfc6598":     (lambda t: _bogon_frame(t, "100.64.0.3"), DROP),
    "bogon_rfc1918_172": (lambda t: _bogon_frame(t, "172.16.1.4"), DROP),
    "bogon_rfc1918_192": (lambda t: _bogon_frame(t, "192.168.14.4"), DROP),
    "bogon_rfc3927":     (lambda t: _bogon_frame(t, "169.254.9.25"), DROP),
    "bogon_rfc5737":     (lambda t: _bogon_frame(t, "192.0.2.1"), DROP),
    "bogon_rfc5771":     (lambda t: _bogon_frame(t, "224.0.0.1"), DROP),
    "bogon_broadcast_src": (lambda t: _bogon_frame(t, "255.255.255.255"), DROP)
}

_BOGON_LOOPBACK_SKIP = {
    # "bogon_rfc1122":     "Linux lo performs no ingress filtering; delivers any src IP",
    # "bogon_rfc6598":     "Linux lo performs no ingress filtering; delivers any src IP",
    # "bogon_rfc1918_172": "Linux lo performs no ingress filtering; delivers any src IP",
    # "bogon_rfc1918_192": "Linux lo performs no ingress filtering; delivers any src IP",
    # "bogon_rfc3927":     "Linux lo performs no ingress filtering; delivers any src IP",
    # "bogon_rfc5737":     "Linux lo performs no ingress filtering; delivers any src IP",
    # "bogon_rfc5771":     "Linux lo performs no ingress filtering; delivers any src IP",
    # "bogon_broadcast_src": "Linux lo performs no ingress filtering; delivers any src IP"
}

@pytest.mark.parametrize("name", list(BOGON_CASES), ids=list(BOGON_CASES))
def test_xv6_bogon_filter(name):
    """BCP38 / RFC 2827: source address must not be a bogon address (RFC 1122, RFC 1918,
    RFC 3927, RFC 5737, RFC 6598). Packets with bogon source IPs are silently dropped."""
    build = BOGON_CASES[name][0]
    expected = DROP
    observed = probe(build(xv6_target()))
    assert observed == expected, f"{name}: expected {expected}, got {observed}"

@pytest.mark.parametrize("name", list(BOGON_CASES), ids=list(BOGON_CASES))
def test_xv6_bogon_filter_vs_linux(name, differential):
    """Cross-check xv6 bogon filter behavior against the live Linux stack.
    Skip cases where Linux lo is not a faithful RFC reference."""
    if not differential:
        pytest.skip("pass --differential to compare against the live host Linux stack")
    if name in _BOGON_LOOPBACK_SKIP:  # loopback skip rationale applies here too
        pytest.skip(f"{name}: {_BOGON_LOOPBACK_SKIP[name]}; "
                    "not comparable via lo (covered by test_xv6_bogon_filter)")
    build = BOGON_CASES[name][0]
    xv6 = probe(build(xv6_target()))
    linux = linux_probe(build)
    assert xv6 == linux, f"{name}: xv6={xv6} linux={linux}"

# ---------------------------------------------------------------------------
# IP fragmentation tests (RFC 791 §3.2, RFC 1122 §3.3.2, RFC 1858)
# Validates that xv6 correctly reassembles well-formed fragment streams and
# drops malformed ones (teardrop, ping-of-death, partial timeout, etc.)
#
#   case                          check                                expected
#   --------------------------    ---------------------------------    ----------
#   frag_two_parts                happy path: two ordered fragments    DELIVERED
#   frag_max_frags                eight fragments reassembled          DELIVERED
#   frag_out_of_order             fragment 1 before fragment 0         DELIVERED
#   frag_non_8byte_aligned_last   last fragment need not be aligned    DELIVERED
#   frag_offset_not_aligned       non-last frag offset % 8 != 0        DROP
#   frag_total_len_exceeds_max    reassembled size > 65535             DROP
#   frag_overlap_conflict         teardrop: same offset, diff data     DROP
#   frag_zero_len_non_last        MF=1 fragment with zero data         DROP
#   frag_timeout_incomplete       first frag only, wait for timeout    DROP
#   frag_id_collision             unfragmented packet poisons queue    DROP
#   frag_mf_and_df_set            DF=1 and MF=1 simultaneously         DROP
#   frag_too_many_fragments       fragment count > FRAG_MAX            DROP
#   frag_closed_port_wellformed   valid frags -> closed port           ICMP_UNREACH
#   frag_closed_port_overlap      overlap frags -> closed port         DROP
# ---------------------------------------------------------------------------

import struct

FRAG_TIMEOUT = 8   # seconds; must exceed xv6's reassembly timeout
FRAG_MAX     = 64  # must match kernel/net.c FRAG_MAX_FRAGMENTS


def _frag(t, payload, frag_offset_bytes, mf, ip_id=0xBEEF,
          df=False, extra_ip_kwargs=None, udp_dport=ECHO_PORT):
    """Build a single IPv4 fragment. frag_offset_bytes must be a multiple of 8
    for non-final fragments; the IP stack encodes it as offset/8."""
    flags = 0
    if mf:
        flags |= 1   # More Fragments
    if df:
        flags |= 2   # Don't Fragment
    ip_kw = dict(id=ip_id, flags=flags, frag=frag_offset_bytes // 8)
    if extra_ip_kwargs:
        ip_kw.update(extra_ip_kwargs)
    return (Ether(dst=t.mac)
            / IP(src=t.src, dst=t.ip, **ip_kw)
            / Raw(payload))


def _udp_payload(dport=ECHO_PORT, sport=12345, body=b"fragtest"):
    """Pre-built UDP header + body bytes ready to be split across fragments."""
    length = 8 + len(body)
    pseudo = struct.pack("!4s4sBBH",
                         bytes([int(x) for x in "10.0.0.1".split(".")]),
                         bytes([int(x) for x in "10.0.0.2".split(".")]),
                         0, 17, length)
    hdr = struct.pack("!HHH", sport, dport, length) + b"\x00\x00"
    data = hdr + body
    chksum = 0
    for i in range(0, len(pseudo + data) - 1, 2):
        chksum += struct.unpack("!H", (pseudo + data)[i:i+2])[0]
    if len((pseudo + data)) % 2:
        chksum += (pseudo + data)[-1] << 8
    chksum = (~((chksum >> 16) + (chksum & 0xFFFF)) & 0xFFFF)
    return struct.pack("!HHHH", sport, dport, length, chksum) + body


def _send_frags(frags):
    """Send a list of pre-built frames in sequence with a small inter-frame gap."""
    for f in frags:
        sendp(f, iface=IFACE, verbose=0)
        time.sleep(0.02)


# ---------------------------------------------------------------------------
# Fragment corpus
# ---------------------------------------------------------------------------

def _case_frag_two_parts(t):
    udp = _udp_payload(dport=ECHO_PORT)  # 8-byte header + 8-byte body = 16 bytes
    return [_frag(t, udp[:8], frag_offset_bytes=0, mf=True,  extra_ip_kwargs={'proto': 17}),
            _frag(t, udp[8:], frag_offset_bytes=8, mf=False, extra_ip_kwargs={'proto': 17})]


def _case_frag_out_of_order(t):
    udp = _udp_payload(dport=ECHO_PORT)
    return [_frag(t, udp[8:],  frag_offset_bytes=8,  mf=False, extra_ip_kwargs={'proto': 17}),
            _frag(t, udp[:8],  frag_offset_bytes=0,  mf=True, extra_ip_kwargs={'proto': 17})]


def _case_frag_max_frags(t):
    body = b"X" * 64
    udp = _udp_payload(dport=ECHO_PORT, body=body)
    # 8-byte UDP header + 64-byte body = 72 bytes; split into 9 × 8-byte fragments
    return [_frag(t, udp[i:i+8], frag_offset_bytes=i, mf=(i + 8 < len(udp)), extra_ip_kwargs={'proto': 17})
            for i in range(0, len(udp), 8)]


def _case_frag_non_8byte_aligned_last(t):
    udp = _udp_payload(dport=ECHO_PORT, body=b"AB")  # 10 bytes total
    return [_frag(t, udp[:8],   frag_offset_bytes=0,  mf=True,  extra_ip_kwargs={'proto': 17}),   # aligned
            _frag(t, udp[8:],   frag_offset_bytes=8,  mf=False, extra_ip_kwargs={'proto': 17})]  # 2 bytes, fine


def _case_frag_offset_not_aligned(t):
    udp = _udp_payload(dport=ECHO_PORT)
    # offset=5 is not divisible by 8; non-last fragment -> invalid
    return [_frag(t, udp[:8],  frag_offset_bytes=0,  mf=True, extra_ip_kwargs={'proto': 17}),
            _frag(t, udp[3:],  frag_offset_bytes=3,  mf=False, extra_ip_kwargs={'proto': 17})]  # force frag field to bad value via scapy


def _case_frag_total_len_exceeds_max(t):
    # Last fragment at offset 65528 would push reassembled size to 65528 + 8 = 65536 > 65535
    return [_frag(t, b"\x00" * 8, frag_offset_bytes=0,     mf=True, extra_ip_kwargs={'proto': 17}),
            _frag(t, b"\x00" * 8, frag_offset_bytes=65528, mf=False, extra_ip_kwargs={'proto': 17})]


def _case_frag_overlap_conflict(t):
    udp = _udp_payload(dport=ECHO_PORT)
    frag0 = _frag(t, udp[:16], frag_offset_bytes=0, mf=True, extra_ip_kwargs={'proto': 17})
    # second fragment covers same bytes with different content
    frag0b = _frag(t, b"\xff" * 16, frag_offset_bytes=0, mf=True, extra_ip_kwargs={'proto': 17})
    frag1  = _frag(t, udp[16:], frag_offset_bytes=16, mf=False, extra_ip_kwargs={'proto': 17})
    return [frag0, frag0b, frag1]


def _case_frag_zero_len_non_last(t):
    # IP total length == IHL * 4 means zero data — invalid for MF=1
    return [_frag(t, b"", frag_offset_bytes=0, mf=True,
                  extra_ip_kwargs={"len": 20, "proto": 17})]


def _case_frag_timeout_incomplete(t):
    # Only the first fragment; the second is never sent
    udp = _udp_payload(dport=ECHO_PORT)
    return [_frag(t, udp[:8], frag_offset_bytes=0, mf=True, extra_ip_kwargs={'proto': 17})]


def _case_frag_id_collision(t):
    udp = _udp_payload(dport=ECHO_PORT)
    ip_id = 0xDEAD
    frag0 = _frag(t, udp[:8], frag_offset_bytes=0, mf=True,  ip_id=ip_id, extra_ip_kwargs={'proto': 17})
    # unfragmented datagram with same ID — must not be grafted onto pending queue
    unfrag = _frag(t, udp,    frag_offset_bytes=0, mf=False, ip_id=ip_id, extra_ip_kwargs={'proto': 17})
    frag1  = _frag(t, udp[8:],frag_offset_bytes=8, mf=False, ip_id=ip_id, extra_ip_kwargs={'proto': 17})
    return [frag0, unfrag, frag1]


def _case_frag_mf_and_df_set(t):
    udp = _udp_payload(dport=ECHO_PORT)
    return [_frag(t, udp[:8], frag_offset_bytes=0, mf=True, df=True, extra_ip_kwargs={'proto': 17})]


def _case_frag_too_many_fragments(t):
    # FRAG_MAX + 1 fragments without a terminal (MF=1 throughout)
    return [_frag(t, b"\x00" * 8, frag_offset_bytes=i * 8, mf=True, extra_ip_kwargs={'proto': 17})
            for i in range(FRAG_MAX + 1)]


def _case_frag_closed_port_wellformed(t):
    udp = _udp_payload(dport=CLOSED_PORT)
    return [_frag(t, udp[:8],  frag_offset_bytes=0,  mf=True, extra_ip_kwargs={'proto': 17}),
            _frag(t, udp[8:],  frag_offset_bytes=8,  mf=False, extra_ip_kwargs={'proto': 17})]


def _case_frag_closed_port_overlap(t):
    udp = _udp_payload(dport=CLOSED_PORT)
    frag0  = _frag(t, udp[:16], frag_offset_bytes=0,  mf=True, extra_ip_kwargs={'proto': 17})
    frag0b = _frag(t, b"\xff" * 16, frag_offset_bytes=0, mf=True, extra_ip_kwargs={'proto': 17})
    frag1  = _frag(t, udp[16:], frag_offset_bytes=16, mf=False, extra_ip_kwargs={'proto': 17})
    return [frag0, frag0b, frag1]


# ---------------------------------------------------------------------------
# Probe helper for multi-packet cases
# ---------------------------------------------------------------------------

def probe_frags(frames, expected):
    """Send a list of frames and observe xv6's reaction using the same
    logic as conftest.probe(), but pre-built frames instead of a single frame."""
    sniffer = AsyncSniffer(
        iface=IFACE,
        filter=f"src host {XV6_IP}",
        store=True,
    )
    sniffer.start()
    time.sleep(0.05)
    _send_frags(frames)
    wait = FRAG_TIMEOUT + 1 if expected == DROP else TIMEOUT
    time.sleep(wait)
    pkts = sniffer.stop() or []
    if any(p.haslayer(UDP) and p[IP].src == XV6_IP for p in pkts):
        return DELIVERED
    if any(p.haslayer(ICMP) and int(p[ICMP].type) == 3 for p in pkts):
        return ICMP_UNREACH
    return DROP


# ---------------------------------------------------------------------------
# Test parametrization
# ---------------------------------------------------------------------------

FRAG_CASES = {
    "frag_zero_len_non_last":       (_case_frag_zero_len_non_last,      DROP),
    "frag_timeout_incomplete":      (_case_frag_timeout_incomplete,     DROP),
    "frag_id_collision":            (_case_frag_id_collision,           DROP),
    "frag_mf_and_df_set":           (_case_frag_mf_and_df_set,          DROP),
    "frag_too_many_fragments":      (_case_frag_too_many_fragments,     DROP),
    "frag_closed_port_wellformed":  (_case_frag_closed_port_wellformed, ICMP_UNREACH),
    "frag_closed_port_overlap":     (_case_frag_closed_port_overlap,    DROP),
    "frag_two_parts":               (_case_frag_two_parts,              DELIVERED),
    "frag_out_of_order":            (_case_frag_out_of_order,           DELIVERED),
    "frag_max_frags":               (_case_frag_max_frags,              DELIVERED),
    "frag_non_8byte_aligned_last":  (_case_frag_non_8byte_aligned_last, DELIVERED),
    "frag_offset_not_aligned":      (_case_frag_offset_not_aligned,     DROP),
    "frag_total_len_exceeds_max":   (_case_frag_total_len_exceeds_max,  DROP),
    "frag_overlap_conflict":        (_case_frag_overlap_conflict,       DROP),
}


@pytest.mark.parametrize("name", list(FRAG_CASES), ids=list(FRAG_CASES))
def test_xv6_fragmentation(name):
    """RFC 791 §3.2 / RFC 1122 §3.3.2: xv6 must correctly reassemble
    well-formed fragment streams and drop malformed or abusive ones."""
    build, expected = FRAG_CASES[name]
    t = xv6_target()
    frames = build(t)
    observed = probe_frags(frames, expected)
    assert observed == expected, f"{name}: expected {expected}, got {observed}"


# ---------------------------------------------------------------------------
# ARP security tests
#
# Validates all four ARP hardening features added to arp_rx():
#   1. Static entries for known nodes  - arp_static_table in kernel/net.c
#   2. Dynamic ARP inspection (DAI)    - arp_dai_ok()
#   3. Rate limiting per source MAC    - arp_rate_ok()
#   4. Gratuitous ARP monitoring/drop  - sip == tip check
#
# Constants must match arp_static_table[] and ARP_RL_BURST in kernel/net.c.
# ---------------------------------------------------------------------------
ARP_SENTINEL_IP  = "10.0.0.99"      # DAI test sentinel in arp_static_table with MAC below
ARP_SENTINEL_MAC = "aa:bb:cc:dd:ee:ff"
ARP_RL_BURST_VAL = 8                 # must match ARP_RL_BURST in net.c


def _arp_req(hwsrc, psrc, pdst=XV6_IP):
    """Build an ARP REQUEST frame."""
    return (Ether(src=hwsrc, dst="ff:ff:ff:ff:ff:ff")
            / ARP(op=1, hwsrc=hwsrc, psrc=psrc,
                  hwdst="00:00:00:00:00:00", pdst=pdst))


ARP_CASES = {
    # Valid request from an unknown host -> xv6 replies
    "arp_valid": (lambda t: _arp_req("de:ad:be:ef:01:00", "10.0.0.50"), ARP_REPLY),

    # Static-table sentinel with CORRECT MAC -> reply (static entry works)
    "arp_static_correct_mac": (lambda t: _arp_req(ARP_SENTINEL_MAC, ARP_SENTINEL_IP), ARP_REPLY),

    # DAI: sentinel IP with WRONG MAC -> drop (ARP spoofing blocked)
    "arp_dai_spoof": (lambda t: _arp_req("de:ad:be:ef:02:00", ARP_SENTINEL_IP), DROP),

    # Gratuitous ARP (psrc == pdst) -> drop (unsolicited cache-update attack)
    "arp_gratuitous": 
        (lambda t: (Ether(src="de:ad:be:ef:03:00", dst="ff:ff:ff:ff:ff:ff")
                    / ARP(op=1, hwsrc="de:ad:be:ef:03:00", psrc="10.0.0.60",
                          hwdst="00:00:00:00:00:00", pdst="10.0.0.60")), DROP),

    # ARP request not targeting xv6's IP -> no reply
    "arp_not_for_us": (lambda t: _arp_req("de:ad:be:ef:04:00", "10.0.0.50", pdst="10.0.0.1"), DROP),
}


def arp_probe(packet, timeout=TIMEOUT):
    """Like probe() but scoped to ARP-only replies - avoids false positives from
    spontaneous host ARP requests bleeding into unrelated test sniffers."""
    sniffer = AsyncSniffer(iface=IFACE, filter=f"src host {XV6_IP} and arp", store=True)
    sniffer.start()
    time.sleep(0.1)
    sendp(packet, iface=IFACE, verbose=0)
    time.sleep(timeout)
    pkts = sniffer.stop() or []
    for r in pkts:
        if r.haslayer(ARP) and int(r[ARP].op) == 2:
            return ARP_REPLY
    return DROP


@pytest.mark.parametrize("name", list(ARP_CASES), ids=list(ARP_CASES))
def test_arp_security(name):
    build, expected = ARP_CASES[name]
    observed = arp_probe(build(xv6_target()))
    assert observed == expected, f"{name}: expected {expected}, got {observed}"


def test_arp_rate_limit():
    """A tight burst of ARP requests from one MAC should be throttled to at most
    ARP_RL_BURST replies; the rest are dropped by the rate limiter."""
    n = 20
    hwsrc = "de:ad:be:ef:05:00"  # fresh MAC → fresh token bucket
    sniffer = AsyncSniffer(iface=IFACE, filter=f"src host {XV6_IP} and arp", store=True)
    sniffer.start()
    time.sleep(0.1)
    pkts = [_arp_req(hwsrc, "10.0.0.80") for _ in range(n)]
    sendp(pkts, iface=IFACE, verbose=0)
    time.sleep(TIMEOUT)
    replies = [r for r in (sniffer.stop() or [])
               if r.haslayer(ARP) and int(r[ARP].op) == 2]
    assert 1 <= len(replies) <= ARP_RL_BURST_VAL, \
        f"arp rate limit: expected 1..{ARP_RL_BURST_VAL} replies for {n} requests, got {len(replies)}"


# ---------------------------------------------------------------------------
# Dynamic ARP resolution (RFC 826) — the outbound arp_lookup() path.
#
# These drive xv6's *transmit* side rather than injecting frames at it. netecho
# echoes each datagram back to its source IP, so a UDP datagram sourced from an
# unresolved in-prefix address forces sys_send() -> arp_lookup() to broadcast an
# ARP request for that address (a cache miss). We observe that request on the wire.
#
#   test                                 checks                                    expected
#   -----------------------------------  ----------------------------------------  --------
#   test_arp_dynamic_request_on_miss     cache miss -> broadcast ARP request       op=1 seen
#   test_arp_unresolvable_does_not_hang  timeout/retry fails closed, node survives  DELIVERED after
#
# End-to-end resolution + reply-learning between two live nodes is validated in
# the two-node bridge setup (see README "Dynamic ARP resolution" / verification),
# which this single-node injection harness cannot trigger on its own.
# ---------------------------------------------------------------------------

def _udp_from(src_ip, dport=ECHO_PORT, payload=b"arpdisc"):
    """A well-formed UDP datagram from an arbitrary in-prefix source. Delivered to
    netecho, whose echo reply drives arp_lookup(src_ip). Checksum zeroed (RFC 768)
    so delivery is never blocked by a checksum mismatch."""
    return (Ether(dst=XV6_MAC) / IP(src=src_ip, dst=XV6_IP)
            / UDP(sport=40001, dport=dport, chksum=0) / Raw(payload))


def test_arp_dynamic_request_on_miss():
    """RFC 826: a send to an unresolved peer broadcasts an ARP request. A datagram
    from an in-prefix but unowned source (10.0.0.51) is echoed by netecho, forcing
    arp_lookup(10.0.0.51) to miss and emit a broadcast request (op=1) for it. Nothing
    on the bridge owns .51, so no reply arrives and the request stays observable."""
    target = "10.0.0.51"
    sniffer = AsyncSniffer(iface=IFACE, filter=f"src host {XV6_IP} and arp", store=True)
    sniffer.start()
    time.sleep(0.1)
    sendp(_udp_from(target), iface=IFACE, verbose=0)
    time.sleep(TIMEOUT + 0.5)
    reqs = [r for r in (sniffer.stop() or [])
            if r.haslayer(ARP) and int(r[ARP].op) == 1 and r[ARP].pdst == target]
    assert len(reqs) >= 1, \
        f"expected >=1 broadcast ARP request for {target} on cache miss, got {len(reqs)}"


def test_arp_unresolvable_does_not_hang():
    """The blocking arp_lookup() must fail closed after ARP_REQ_RETRIES timeouts
    (~3s) without wedging the kernel. After forcing an unresolvable resolution, a
    normal echo to the real host must still come back."""
    sendp(_udp_from("10.0.0.52"), iface=IFACE, verbose=0)
    time.sleep(4)   # let the kernel exhaust ARP_REQ_RETRIES x ARP_REQ_TIMEOUT (~3s)
    valid = (Ether(dst=XV6_MAC) / IP(src=HOST_IP, dst=XV6_IP)
             / UDP(sport=40002, dport=ECHO_PORT) / Raw(b"alive?"))
    assert probe(valid) == DELIVERED, "node stopped echoing after an unresolvable ARP lookup"