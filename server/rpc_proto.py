"""
Host-side wire mirror of the DistInf RPC layer (L3) — RFC 5531 over UDP.

The L3 regression gate (rpc_regression_test.py) plays the counterparty to a live
xv6 node: a synthetic *worker* when xv6 runs `distinf --master`, or a synthetic
*master* when xv6 runs `distinf --worker`. This module is the on-the-wire mirror
of user/rpc.c + user/discovery.{c,h} it needs to do that.

Two encodings coexist on the wire, and mixing them up breaks every payload
assertion — so they are kept deliberately separate here:

  * The ONC RPC *header* (RFC 5531 §9) is XDR (RFC 4506): a run of 4-byte
    BIG-endian unsigned ints. See user/xdr.c:xdrmem_putlong (network byte order)
    and user/rpc.c:rpc_encode_call / rpc_encode_reply for the exact field order.

  * The procedure *payloads* (worker_info_t, cap_ack_t, ...) are NOT XDR. xv6
    memcpy's the raw C struct into the datagram (user/discovery.c:
    `memcpy(req.payload, self, sizeof(worker_info_t))`), so on the wire they are
    the native RISC-V (LITTLE-endian) struct layout, including C padding. The
    struct.Struct formats below reproduce that byte-exact layout.

Transport is a plain UDP socket on the tap subnet (no raw sockets / Scapy): the
RPC content is what we are validating, and the IP/UDP framing is already covered
by the L2 gate (net_regression_test.py).
"""

import hashlib
import hmac
import socket
import struct

# Node identity pre-shared key — must match DISTINF_PSK in user/discovery.h.
DISTINF_PSK = b"distinf-shared-psk-v1"


def psk_commitment():
    """SHA-256(PSK): the identity commitment carried in worker_info_t.psk_hash."""
    return hashlib.sha256(DISTINF_PSK).digest()


def cap_identity(nonce):
    """HMAC-SHA256(PSK, <4 LE nonce bytes>): the proof of PSK possession carried
    in cap_ack_t.identity. Mirrors discovery.c:cap_identity exactly (RFC 2104)."""
    return hmac.new(DISTINF_PSK, struct.pack("<I", nonce & 0xFFFFFFFF),
                    hashlib.sha256).digest()

# -----------------------------------------------------------------------
# RFC 5531 §9 / user/rpc.h — fixed constants (mirrored, keep in sync)
# -----------------------------------------------------------------------
RPC_VERSION    = 2
INFERENCE_PROG = 0x20000001      # local-administrator block (RFC 5531 §8.3)
INFERENCE_VERS = 1

# rpc_proc_t
PROC_NULL          = 0
PROC_AUTH_HELLO    = 1
PROC_CAP_ACK       = 2
PROC_CAP_PROBE     = 3
PROC_INFER_REQ     = 4
PROC_HEARTBEAT     = 5
PROC_SET_NEIGHBOR  = 6
PROC_EVICT         = 7
PROC_CAP_ADVERTISE = 8

# msg_type_t
MSG_CALL  = 0
MSG_REPLY = 1

# reply_stat_t
MSG_ACCEPTED = 0
MSG_DENIED   = 1

# accept_stat_t (RFC 5531 §9)
SUCCESS       = 0
PROG_UNAVAIL  = 1
PROG_MISMATCH = 2
PROC_UNAVAIL  = 3
GARBAGE_ARGS  = 4
SYSTEM_ERR    = 5

ACCEPT_STAT_NAME = {
    SUCCESS: "SUCCESS", PROG_UNAVAIL: "PROG_UNAVAIL",
    PROG_MISMATCH: "PROG_MISMATCH", PROC_UNAVAIL: "PROC_UNAVAIL",
    GARBAGE_ARGS: "GARBAGE_ARGS", SYSTEM_ERR: "SYSTEM_ERR",
}

# auth_flavor_t
AUTH_NONE = 0

# discovery.h — worker states
WORKER_PENDING   = 0
WORKER_ACTIVE    = 1
WORKER_SUSPECTED = 2
WORKER_EXPIRED   = 3

# -----------------------------------------------------------------------
# Payload struct layouts — native little-endian, C padding preserved.
# Sizes are asserted so a struct change on the C side trips the harness
# instead of silently skewing every field.
# -----------------------------------------------------------------------
# worker_info_t: u32 worker_id, u32 ip, u16 port, <2 pad>, u32 RAM,
#                u8 psk_hash[32], u32 next_ip, u32 prev_ip   => 56 bytes
_WORKER_INFO = struct.Struct("<IIH2xI32sII")
# cap_ack_t: u32 probe_nonce, u32 checksum, u8 identity[32]  => 40 bytes
_CAP_ACK = struct.Struct("<II32s")
# auth_hello_reply_t: u32 status, u32 probe_data,
#                     u32 probe_seed, u32 probe_pages        => 16 bytes
_AUTH_HELLO_REPLY = struct.Struct("<IIII")
# set_neighbor_t: u32 prev_ip, u16 prev_port, <2 pad>,
#                 u32 next_ip, u16 next_port, <2 pad>        => 16 bytes
_SET_NEIGHBOR = struct.Struct("<IH2xIH2x")

assert _WORKER_INFO.size == 56
assert _CAP_ACK.size == 40
assert _AUTH_HELLO_REPLY.size == 16
assert _SET_NEIGHBOR.size == 16


def pack_worker_info(worker_id, ip, port, ram, psk_hash=None, next_ip=0, prev_ip=0):
    # Default to the real PSK commitment so a conforming peer registers; a test
    # that wants to be rejected passes a wrong psk_hash explicitly.
    if psk_hash is None:
        psk_hash = psk_commitment()
    return _WORKER_INFO.pack(worker_id, ip, port, ram,
                             psk_hash[:32].ljust(32, b"\x00"), next_ip, prev_ip)


def cap_probe_checksum(seed, pages):
    """The RAM sized-probe checksum, mirroring discovery.c:cap_probe_checksum
    exactly (glibc LCG, one word per page, 32-bit wrap). A host peer proving
    protocol conformance computes it directly; only a real xv6 worker also has
    to allocate the pages."""
    x = seed & 0xFFFFFFFF
    s = 0
    for _ in range(pages):
        x = (x * 1103515245 + 12345) & 0xFFFFFFFF
        s = (s + x) & 0xFFFFFFFF
    return s


def pack_cap_ack(probe_nonce, checksum=0, identity=None):
    # Default identity to the correct HMAC over the nonce so a conforming peer
    # passes; a test wanting rejection passes a wrong identity explicitly.
    if identity is None:
        identity = cap_identity(probe_nonce)
    return _CAP_ACK.pack(probe_nonce, checksum & 0xFFFFFFFF, identity[:32].ljust(32, b"\x00"))


def unpack_auth_hello_reply(payload):
    status, probe_data, probe_seed, probe_pages = _AUTH_HELLO_REPLY.unpack_from(payload, 0)
    return {"status": status, "probe_data": probe_data,
            "probe_seed": probe_seed, "probe_pages": probe_pages}


def pack_auth_hello_reply(status, probe_data, probe_seed=0, probe_pages=0):
    return _AUTH_HELLO_REPLY.pack(status, probe_data, probe_seed, probe_pages)


def unpack_set_neighbor(payload):
    prev_ip, prev_port, next_ip, next_port = _SET_NEIGHBOR.unpack_from(payload, 0)
    return {"prev_ip": prev_ip, "prev_port": prev_port,
            "next_ip": next_ip, "next_port": next_port}


def pack_set_neighbor(prev_ip, prev_port, next_ip, next_port):
    return _SET_NEIGHBOR.pack(prev_ip, prev_port, next_ip, next_port)


# -----------------------------------------------------------------------
# RPC header codec — XDR, big-endian (RFC 5531 §9, field order per rpc.c)
# -----------------------------------------------------------------------
def encode_call(xid, proc, payload=b"",
                prog=INFERENCE_PROG, vers=INFERENCE_VERS, rpcvers=RPC_VERSION):
    """CALL: xid, mtype, rpcvers, prog, vers, proc, cred(AUTH_NONE),
    verf(AUTH_NONE), then the raw payload (rpc.c:rpc_encode_call)."""
    hdr = struct.pack(">IIIIII", xid, MSG_CALL, rpcvers, prog, vers, proc)
    cred = struct.pack(">II", AUTH_NONE, 0)
    verf = struct.pack(">II", AUTH_NONE, 0)
    return hdr + cred + verf + payload


def encode_reply(xid, accept_stat, payload=b""):
    """Accepted REPLY: xid, mtype, reply_stat(ACCEPTED), verf(AUTH_NONE),
    accept_stat, then the raw payload (rpc.c:rpc_encode_reply)."""
    hdr = struct.pack(">III", xid, MSG_REPLY, MSG_ACCEPTED)
    verf = struct.pack(">II", AUTH_NONE, 0)
    return hdr + verf + struct.pack(">I", accept_stat) + payload


def _skip_opaque_auth(buf, off):
    """opaque_auth = flavor(u32), body_len(u32)[, body]. AUTH_NONE => len 0.
    Mirrors xdr_decode_opaque_auth: a non-zero body is 4-byte aligned."""
    (_flavor, body_len) = struct.unpack_from(">II", buf, off)
    off += 8
    if body_len:
        off += (body_len + 3) & ~3
    return off


def decode(buf):
    """Decode a CALL or REPLY datagram into a dict (mirrors rpc_decode_msg).
    Returns fields plus the trailing raw `payload` bytes. Raises ValueError on
    a malformed header (the host analog of RPC_ERR_DECODE)."""
    if len(buf) < 8:
        raise ValueError("short datagram")
    xid, mtype = struct.unpack_from(">II", buf, 0)
    off = 8
    out = {"xid": xid, "mtype": mtype}

    if mtype == MSG_CALL:
        rpcvers, prog, vers, proc = struct.unpack_from(">IIII", buf, off)
        off += 16
        off = _skip_opaque_auth(buf, off)   # cred
        off = _skip_opaque_auth(buf, off)   # verf
        out.update(rpcvers=rpcvers, prog=prog, vers=vers, proc=proc)
    elif mtype == MSG_REPLY:
        (reply_stat,) = struct.unpack_from(">I", buf, off)
        off += 4
        out["reply_stat"] = reply_stat
        if reply_stat == MSG_ACCEPTED:
            off = _skip_opaque_auth(buf, off)   # verf
            (accept_stat,) = struct.unpack_from(">I", buf, off)
            off += 4
            out["accept_stat"] = accept_stat
            if accept_stat == PROG_MISMATCH:
                off += 8   # mismatch_info{low, high}
        else:
            (reject_stat,) = struct.unpack_from(">I", buf, off)
            off += 4
            out["reject_stat"] = reject_stat
            off += 8   # mismatch_info / auth_stat (whichever variant)
    else:
        raise ValueError("unknown mtype %d" % mtype)

    out["payload"] = buf[off:]
    return out


# -----------------------------------------------------------------------
# UDP peer — a synthetic worker or master on the tap subnet
# -----------------------------------------------------------------------
class RpcPeer:
    """A UDP endpoint that speaks the DistInf RPC wire format.

    We rely on the host kernel to answer xv6's ARP for our tap IP (10.0.0.1)
    and to route datagrams addressed to it into this bound socket — no raw
    sockets needed. Binding also suppresses the kernel's ICMP port-unreachable,
    so xv6's rpc_call sees a clean reply path.
    """

    def __init__(self, local_port=0, bind_ip=""):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((bind_ip, local_port))
        self._xid = 1

    @property
    def port(self):
        return self.sock.getsockname()[1]

    def next_xid(self):
        x = self._xid
        self._xid += 1
        return x

    def sendto(self, data, addr):
        self.sock.sendto(data, addr)

    def recv(self, timeout=2.0):
        """Return (decoded_dict, src_addr) or (None, None) on timeout."""
        self.sock.settimeout(timeout)
        try:
            data, src = self.sock.recvfrom(65535)
        except socket.timeout:
            return None, None
        return decode(data), src

    def call(self, addr, proc, payload=b"", timeout=2.0, **hdr):
        """Send a CALL and wait for the matching-xid REPLY."""
        xid = self.next_xid()
        self.sendto(encode_call(xid, proc, payload, **hdr), addr)
        deadline_msgs = 0
        while deadline_msgs < 8:
            msg, _src = self.recv(timeout=timeout)
            if msg is None:
                return None
            if msg.get("mtype") == MSG_REPLY and msg.get("xid") == xid:
                return msg
            deadline_msgs += 1   # drain a stray datagram, keep waiting
        return None

    def close(self):
        self.sock.close()


def ip_to_u32(dotted):
    """'10.0.0.2' -> 0x0A000002 (host byte order int), matching MAKE_IP_ADDR."""
    a, b, c, d = (int(x) for x in dotted.split("."))
    return (a << 24) | (b << 16) | (c << 8) | d
