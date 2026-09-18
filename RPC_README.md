## `rpc.c` Function Reference

| Function | Role | Returns |
|---|---|---|
| `rpc_init(port)` | Binds UDP socket on `port`, sets `g_port` | `RPC_OK` or `RPC_ERR_NET` |
| `rpc_next_xid()` | Returns next monotonic transaction ID | `uint32` xid |
| `rpc_encode_call(buf, buflen, msg)` | Serializes a CALL message to wire format via XDR | bytes written or `RPC_ERR_ENCODE` |
| `rpc_encode_reply(buf, buflen, xid, stat, payload, len)` | Serializes an accepted REPLY to wire format | bytes written or `RPC_ERR_ENCODE` |
| `rpc_decode_msg(buf, buflen, out)` | Deserializes either CALL or REPLY; remaining bytes go to `out->payload` | `RPC_OK` or `RPC_ERR_DECODE` |
| `rpc_send_call(dst, msg)` | Encodes + sends a CALL over UDP | `RPC_OK` or `RPC_ERR_*` |
| `rpc_send_reply(dst, xid, stat, payload, len)` | Encodes + sends a REPLY over UDP | `RPC_OK` or `RPC_ERR_NET` |
| `rpc_recv(out_msg, out_src, timeout_ms)` | Blocking receive with timeout; decodes wire bytes into `rpc_msg_t` | `RPC_OK`, `RPC_ERR_TIMEOUT`, or `RPC_ERR_*` |
| `rpc_call(dst, req, out_reply)` | Full round-trip: send CALL → drain for matching xid → return REPLY; retries up to `RPC_MAX_RETRIES` | `RPC_OK` or `RPC_ERR_*` |

---

## Internal UDP Shim

| Function | Role |
|---|---|
| `_udp_bind(port)` | Calls `bind()`, tracks port in `g_port`, unbinds previous if any |
| `_udp_send(dst_ip, dst_port, buf, len)` | Calls `send(g_port, ...)` |
| `_udp_recv(buf, maxlen, src_ip, src_port, timeout_ms)` | Calls `recvtimeo()`; converts `-2` → `RPC_ERR_TIMEOUT` |

---

## Error Codes

| Code | Meaning | Typically from |
|---|---|---|
| `RPC_OK` (0) | Success | Any function |
| `RPC_ERR_NET` | UDP send/recv/bind failed | `_udp_*`, `rpc_send_*`, `rpc_init` |
| `RPC_ERR_TIMEOUT` | No reply within timeout window | `rpc_recv`, `rpc_call` |
| `RPC_ERR_ENCODE` | XDR serialization failed, or payload/rpcvers invalid | `rpc_encode_call`, `rpc_encode_reply` |
| `RPC_ERR_DECODE` | XDR deserialization failed, unknown mtype, or rpcvers != 2 | `rpc_decode_msg`, `rpc_recv` |
| `RPC_ERR_PROG` | `PROG_UNAVAIL` or `PROG_MISMATCH` in reply | `rpc_call` |
| `RPC_ERR_PROC` | `PROC_UNAVAIL` in reply — procedure not registered | `rpc_call` |
| `RPC_ERR_GARBAGE` | `GARBAGE_ARGS` in reply — server couldn't decode args | `rpc_call` |
| `RPC_ERR_DENIED` | `MSG_DENIED` reply — auth failure or RPC version mismatch | `rpc_call` |

---

## A Few Design Notes Worth Remembering

- **`g_port` is global/singleton** — one bound port per node at a time. `rpc_init` unbinds the previous one if called twice.
- **xid matching in `rpc_call`** — stale replies from prior timed-out calls are silently drained; `remaining_ms -= 10` is a rough approximation
- **Payload is opaque to this layer** — `rpc_decode_msg` dumps remaining bytes verbatim into `msg->payload`; upper layers (discovery, inference) own the interpretation.
- **No retransmission backoff** — flat `RPC_TIMEOUT_MS` per attempt, `RPC_MAX_RETRIES` total.