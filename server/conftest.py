"""
Shared fixtures and helpers for the xv6 UDP receive-path regression harness.

The harness injects crafted Ethernet/IP/UDP frames onto the tap interface and
observes how the target stack reacts. Two on-the-wire reactions plus silence let
us classify every datagram:

    DELIVERED     the bound app echoed the payload back (UDP from the echo port)
    ICMP_UNREACH  the stack answered with ICMP type 3 / code 3
    DROP          nothing came back within the timeout

Requires root (raw sockets) and a tap setup as documented in the project README.
Configuration is overridable via environment variables (XV6_IFACE, XV6_IP, ...).
"""

import os
import time
from collections import namedtuple

import pytest
from scapy.all import (Ether, IP, UDP, ICMP, ARP, Raw,
                       AsyncSniffer, sendp, get_if_hwaddr, conf)

conf.verb = 0

IFACE       = os.environ.get("XV6_IFACE", "tap0")
LO_IFACE    = "lo"
XV6_IP      = os.environ.get("XV6_IP", "10.0.0.2")
HOST_IP     = os.environ.get("XV6_HOST_IP", "10.0.0.1")
XV6_MAC     = os.environ.get("XV6_MAC", "52:54:00:12:34:56")
LINUX_SRC   = os.environ.get("XV6_LINUX_SRC", "10.0.0.50")
ECHO_PORT   = int(os.environ.get("XV6_ECHO_PORT", "2000"))
CLOSED_PORT = int(os.environ.get("XV6_CLOSED_PORT", "9999"))
TIMEOUT     = float(os.environ.get("XV6_TIMEOUT", "1.0"))

# Observable outcomes.
DELIVERED    = "DELIVERED"
DROP         = "DROP"
ICMP_UNREACH = "ICMP_UNREACH"
ECHO_REPLY   = "ECHO_REPLY"   # the stack answered a ping with ICMP type 0 (Echo Reply)
ARP_REPLY    = "ARP_REPLY"    # the stack answered an ARP request with an ARP reply (op=2)

# A probe destination: the IP/MAC to address and the source IP to put in the frame.
Target = namedtuple("Target", ["ip", "mac", "src"])


def xv6_target():
    return Target(XV6_IP, XV6_MAC, HOST_IP)


def _classify(pkts):
    # ICMP first: a port-unreachable error embeds the original UDP header, so it
    # would also match the UDP check below.
    for r in pkts:
        if r.haslayer(ICMP) and int(r[ICMP].type) == 3 and int(r[ICMP].code) == 3:
            return ICMP_UNREACH
    # Echo Reply (type 0): xv6 answered a ping.
    for r in pkts:
        if r.haslayer(ICMP) and int(r[ICMP].type) == 0:
            return ECHO_REPLY
    for r in pkts:
        if r.haslayer(UDP) and not r.haslayer(ICMP) and int(r[UDP].sport) == ECHO_PORT:
            return DELIVERED
    return DROP


def probe(packet, timeout=TIMEOUT):
    """Inject one frame toward xv6 and classify what xv6 sends back."""
    sniffer = AsyncSniffer(iface=IFACE, filter=f"src host {XV6_IP}", store=True)
    sniffer.start()
    time.sleep(0.1)  # let the sniffer attach before we transmit
    sendp(packet, iface=IFACE, verbose=0)
    time.sleep(timeout)
    return _classify(sniffer.stop() or [])


def linux_probe(build, timeout=TIMEOUT):
    linux_target = Target("10.0.0.1", get_if_hwaddr(IFACE), LINUX_SRC)

    pkt = build(linux_target)

    sniffer = AsyncSniffer(
        iface=LO_IFACE,
        filter=f"src host {HOST_IP}",
        store=True
    )

    sniffer.start()
    time.sleep(0.05)

    sendp(pkt, iface=IFACE, verbose=0)

    time.sleep(timeout)

    return _classify(sniffer.stop() or [])


def _arp_warmup():
    """Teach xv6 the host's MAC (via arp_rx) so its replies are addressed to us."""
    try:
        hwsrc = get_if_hwaddr(IFACE)
    except Exception:
        hwsrc = None
    arp = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, psrc=HOST_IP, pdst=XV6_IP)
    if hwsrc:
        arp[Ether].src = hwsrc
        arp[ARP].hwsrc = hwsrc
    sendp(arp, iface=IFACE, verbose=0)
    time.sleep(0.2)


def pytest_addoption(parser):
    parser.addoption("--differential", action="store_true", default=False,
                     help="also probe the host Linux stack and assert xv6 == Linux")


@pytest.fixture(scope="session")
def differential(request):
    return request.config.getoption("--differential")


@pytest.fixture(scope="session", autouse=True)
def environment():
    """Fail fast if the test environment is not ready."""
    if os.geteuid() != 0:
        pytest.exit("regression harness needs root (raw sockets); run with sudo", returncode=2)

    _arp_warmup()

    valid = (Ether(dst=XV6_MAC) / IP(src=HOST_IP, dst=XV6_IP)
             / UDP(sport=40000, dport=ECHO_PORT) / Raw(b"warmup!!"))
    if probe(valid) != DELIVERED:
        pytest.exit(
            f"no echo from {XV6_IP}:{ECHO_PORT} — boot xv6 in tap mode with "
            f"'netecho {ECHO_PORT}' running and {IFACE} up", returncode=3)
    yield
