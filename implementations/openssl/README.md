# OpenSSL adapter

OpenSSL 4.1.0 (released 2026-10-23), built from the GitHub release tarball with a pinned SHA-256.
`build.sh` configures `no-shared no-docs no-tests`, installs into `.build/openssl/install/` and links `adapter.c` statically against `libssl.a`/`libcrypto.a` into `.build/openssl/bin/dtls-adapter`.
The library is rebuilt only when version, checksum or configure flags change; the adapter is recompiled on every run.
`.built` holds `openssl 4.1.0` on its first line and the configure flags on the second.
`run` execs the adapter binary, which stays in the caller's process group; the server exits after serving one connection (two with `--resume=ticket`).

The adapter is a small C program on libssl rather than `s_client`/`s_server`, because the listener's address validation, the MTU and reliable `group`/`hrr` reporting need API-level control.
It calls `OPENSSL_init_ssl(OPENSSL_INIT_NO_LOAD_CONFIG)`, so no system `openssl.cnf` can change behaviour.
Both roles pin the protocol to version 1.3 of the chosen transport, see Transport.

## Variants

| Variant | Server code path |
|---|---|
| `default` | DTLS listener API: `SSL_new_listener(ctx, SSL_LISTENER_FLAG_SINGLE_THREAD)`, `SSL_listen`, `SSL_accept_connection`, `SSL_accept`, all on one unconnected UDP socket |
| `accept` | Waits for the first datagram (`recvfrom` with `MSG_PEEK`), `connect`s the socket to that peer and runs a plain `SSL_new` + `SSL_accept` on it; DTLS only |

The listener is what OpenSSL documents for DTLS 1.3 servers.
`accept` is the pattern of applications that demultiplex peers themselves and give each peer a connected socket; it uses different code for address validation, sending (`BIO_write` instead of `BIO_sendmmsg`) and the default MTU.
`DTLSv1_listen()` is not a variant because it does not support DTLS 1.3 (DTLSv1_listen(3) in 4.1.0).
`accept` is a connected-UDP-socket code path, so with `--transport=tls` it exits 2 (unsupported) with a result line; the TLS server has a single code path, the `default` variant.
`variants` lists `accept` for the server role only; the client has a single code path (`SSL_connect` on a connected socket), so it accepts only `--variant=default` and exits 64 otherwise.

## Option mapping

Every option of the role is required, accepted as `--opt=value` or `--opt value` with the exact name (no abbreviations).
A missing, unknown, repeated or other-role option and a malformed value exit 64.

| Option | OpenSSL mapping |
|---|---|
| `--port` | Server: binds it (`0` = any free port) and prints the bound port in the ready line; client: connects to it |
| `--transport` | See Transport |
| `--resume` | See Resumption |
| `--groups` (client) | `SSL_CTX_set1_groups_list("G1:G2")`, the supported_groups order |
| `--groups` (server) | `SSL_CTX_set1_groups_list("G1:G2")`, one tuple, plus `SSL_OP_SERVER_PREFERENCE`, see Groups |
| `--key-share=GROUP` | `*` prefix on that group in the client list, e.g. `X25519MLKEM768:*X25519`, so exactly that share is sent; GROUP must be in `--groups` (else exit 64) |
| `--key-share=default` | No `*` prefix: OpenSSL sends a share for the first group |
| `--key-share=empty` | Unsupported, exit 2 (see below) |
| `--mtu=N` | `SSL_OP_NO_QUERY_MTU` + `SSL_set_mtu(N - 48)`, see MTU |
| `--mtu=default` | Nothing is called, so OpenSSL's own MTU logic applies; the only valid value with `--transport=tls` (a number exits 64) |
| `--validate=cookie` | DTLS `default`: the listener's built-in stateless HRR cookie; `accept`: `SSL_OP_COOKIE_EXCHANGE` with `SSL_CTX_set_stateless_cookie_generate/verify_cb` (HMAC-SHA256 of the peer address under a random key); TLS: `SSL_stateless()` with the same callbacks, see Transport |
| `--validate=off` | DTLS `default`: `SSL_LISTENER_FLAG_NO_VALIDATE`; `accept`: no cookie option; TLS: plain `SSL_accept` |
| `--cert/--key` | `SSL_CTX_use_certificate_chain_file`, `SSL_CTX_use_PrivateKey_file` |
| `--ca` | Client: `SSL_CTX_load_verify_locations`, `SSL_VERIFY_PEER`, `SSL_set1_dnsname("localhost")`, SNI `localhost`; server: required but unused (no client authentication) |

### Transport

| `--transport` | Method and version pin | Sockets |
|---|---|---|
| `dtls` | `DTLS_client_method()` / `DTLS_server_method()`, `SSL_CTX_set_min/max_proto_version(DTLS1_3_VERSION)` | Client: connected UDP socket, `BIO_new_dgram`; server: see Variants |
| `tls` | `TLS_client_method()` / `TLS_server_method()`, `SSL_CTX_set_min/max_proto_version(TLS1_3_VERSION)` | Client: connected TCP socket, `BIO_new_socket`; server: `BIO_listen` (prints `ready` once listening), `accept()` per connection |

With `--transport=tls --validate=cookie` the server calls `SSL_stateless()` on each accepted TCP connection before `SSL_accept()`, so every first ClientHello gets a HelloRetryRequest with a cookie (RFC 9846 sec 4.2.4, 4.3.2).
`SSL_CTX_set_stateless_cookie_generate/verify_cb` put an HMAC of the peer address into the cookie, as for the `accept` variant.
`SSL_OP_COOKIE_EXCHANGE` does nothing for TLS: `tls_hrr_cookie_required()` (ssl/statem/extensions.c) only honours it for DTLS and otherwise requires the `TLS1_FLAGS_STATELESS` flag that only `SSL_stateless()` sets.
`SSL_stateless()` returns 0 after sending the HRR, -1 with an empty error queue for the middlebox-compatibility ChangeCipherSpec that OpenSSL clients send before CH2 (`tls_get_message_header()` in ssl/statem/statem_lib.c), and 1 once a CH2 with a valid cookie arrived.
The adapter calls it at most four times, stops at a second HRR or at any queued error, and logs every return value (`SSL_stateless: N`).
TLS sockets get no datagram callback, so no `>> datagram` lines appear.
With `--transport=tls` a TCP connection is closed after the close_notify exchange.

### Resumption

| `--resume` | Client | Server |
|---|---|---|
| `off` | One connection | One connection |
| `ticket` | Connection 1, then `SSL_get1_session()` after reading `pong`; it must pass `SSL_SESSION_is_resumable()`, else exit 1 with `connection 1: no session ticket received`; connection 2 on a new socket with `SSL_set_session()` | `ready` once, then two connections from the same `SSL_CTX` (and, for DTLS `default`, the same listener) |

A TLS 1.3 client replaces its session with a fresh copy for every NewSessionTicket (`tls_process_new_session_ticket()` in ssl/statem/statem_clnt.c), so the session read after `pong` holds the latest ticket.
The client opens the socket for connection 2 before it frees connection 1, so the kernel cannot hand out the same source port again.
psk_key_exchange_modes (RFC 9846 sec 4.3.9) stays at the library default (`psk_dhe_ke` only), and no early data is sent.
Ticket issuance is left at the library default: `SSL_CTX_get_num_tickets()` is 2, so the server sends two NewSessionTickets (RFC 9846 sec 4.7.1) after a full handshake and one after a resumption (`ossl_statem_server_write_transition()`, `TLS_ST_SW_SESSION_TICKET`, in ssl/statem/statem_srvr.c), for both transports.
The ticket is encrypted under the `SSL_CTX`'s random ticket key, which is why both connections must come from the same context.
Every error is prefixed `connection N: ` with `--resume=ticket`, including errors before connection 1 starts.

The `accept` variant needs a second socket for connection 2, because its first socket stays connected to the first peer and a connected UDP socket only receives that peer's datagrams.
Disconnecting it (`connect(AF_UNSPEC)`) is not an option: Linux releases the local port of a socket bound to port 0 on disconnect (`__udp_disconnect()` without `SOCK_BINDPORT_LOCK`).
So with `--resume=ticket` both sockets are bound with `SO_REUSEADDR`, and the second one is bound to the same address and port right after the first one is connected.
Linux then delivers the first peer's datagrams to the connected socket, which stays open until exit, and every other peer's datagrams to the second one, so late datagrams from connection 1 never reach connection 2.

### Groups

The server puts all `--groups` into one tuple with `SSL_OP_SERVER_PREFERENCE`.
Per SSL_CTX_set1_curves(3) it then selects its highest-ranked group among the client's key shares (ServerHello), otherwise sends an HRR for its highest-ranked group the client supports, otherwise fails.
This is the contract's "key share first" rule; the tests cover all three cases.

### MTU

`--mtu=N` is the IP path MTU, and no UDP payload may exceed N - 48 bytes (IPv6 40 + UDP 8), whatever the address family.
`SSL_set_mtu()` takes exactly that unit: the largest datagram payload, from which OpenSSL subtracts its own record overhead.
`DTLS_set_link_mtu()` is not used because it subtracts the overhead of the actual socket family, only 28 bytes on IPv4.
`SSL_OP_NO_QUERY_MTU` stops OpenSSL from replacing the value with a kernel `IP_MTU` query or shrinking it after retransmissions.
Listener connections are created inside `SSL_accept_connection`, so the server applies the value in its ClientHello callback; the listener's receive limit is raised when N - 48 exceeds its 2000-byte default.
Every sent datagram is logged to stderr (`>> datagram (N bytes)`, via a BIO callback), and the tests check all of them against N - 48; at `--mtu=1500` the ServerHello flight fills exactly 1452 bytes.
An `--mtu` below 256 exits 2, because `SSL_set_mtu` rejects payloads under 208 bytes (OpenSSL's 256-byte link minimum less 48).

## Result fields

- `version`: `SSL_get_version()`, i.e. `DTLSv1.3` or `TLSv1.3`; also reported when a failure happens after the handshake completed (`SSL_is_init_finished()`).
- `group`: `SSL_get0_group_name()`, mapped to IANA spelling (OpenSSL reports `x25519` in lower case).
- `hrr`, `hrr_cookie`, `hrr_group`: a message callback sees each sent or received handshake message; a ServerHello with the HRR random is the HRR, and its extensions are scanned for cookie (44) and key_share (51, the selected_group).
libssl has no public getter for any of these.
The callback gets every handshake message reassembled, with its 12-byte DTLS or 4-byte TLS header, so TCP segmentation and record coalescing do not matter.
The listener creates its connections from the same `SSL_CTX`, so the callback also sees the cookie HRR sent before `SSL_accept_connection` returns.
- `resumed`: `SSL_session_reused()`, i.e. the server accepted the client's PSK (RFC 9846 sec 4.3.11).
- `error`: the last OpenSSL reason string, e.g. `handshake: certificate verify failed`.

stderr logs every handshake message, ACK and alert with its size, every sent datagram, each plaintext (epoch 0) record header (which shows how ClientHello and ServerHello were fragmented) and the teardown.

## Teardown

The client sends close_notify after `pong` and waits up to 2 s for the server's (`SSL_shutdown` until it returns 1).
The server waits up to 2 s for the client's close_notify (`SSL_read` until `SSL_ERROR_ZERO_RETURN`) and only then sends its own.
The order matters: after an endpoint has sent close_notify, OpenSSL's DTLS record layer silently discards non-alert records, and a server that exits early makes the client's ticket ACKs hit a closed port, whose ICMP error Linux reports before the queued `pong`.
Errors after `pong` only go to stderr.
The client logs the local port of every socket it opens (`socket: local port N`), and both roles log `resumed=0|1` with each completed handshake.

## Unsupported

- `--key-share=empty` on the client: `tls_construct_ctos_key_share()` fails with `SSL_R_NO_SUITABLE_KEY_SHARE` unless it adds at least one share, and no public API or group-list syntax produces an empty `key_share`.
An OpenSSL server does accept an empty `key_share` from other clients.
- Groups that OpenSSL 4.1.0 does not implement, notably `MLKEM512X25519` (draft-rosomakho-tls-ecdhe-mlkem512); any such group in `--groups` makes either role exit 2.
- `--mtu` below 256 (exit 2).
- `--variant=accept` with `--transport=tls` (exit 2).

## Observed OpenSSL behaviour

- The listener's DTLS 1.3 cookie is OpenSSL's TLS 1.3 stateless cookie (CH1 transcript hash, group, cipher, timestamp, the listener's 40-byte timestamp+HMAC, outer HMAC) and is 140 bytes.
With X25519MLKEM768, the CH1 record is 1422 bytes and fits one datagram at `--mtu=1500` (1452-byte payload), but CH2 grows to 1555 bytes of handshake message and is fragmented; at `--mtu=1280` both are fragmented.
- `--mtu=default` differs by server variant: the listener's socket is unconnected, `IP_MTU` cannot be queried, and OpenSSL falls back to its 256-byte link minimum (228-byte datagrams, the ServerHello alone in six records).
With `accept` the connected socket reports the interface MTU, which on loopback is 65536, so the whole server flight goes out in one 1881-byte datagram.
- A cookie HRR that also has to fix the key share carries both extensions, so one HRR reports `hrr_cookie` and `hrr_group`.
- DTLS 1.3 servers send their NewSessionTickets only after the ACK for the client's Finished (RFC 9147 sec 7), still inside `SSL_accept()`, so they always precede `pong`.
- Resumption after a cookie HRR works with DTLS in both variants: the listener and `SSL_OP_COOKIE_EXCHANGE` keep the connection's state between CH1 and CH2, so the PSK binder covers CH1 and the HRR (RFC 9846 sec 4.3.11.2).
- Resumption after a TLS cookie HRR fails on the server with `binder does not verify`.
`SSL_stateless()` calls `SSL_clear()`, which resets `hello_retry_request` to `SSL_HRR_NONE`.
On CH2, `tls_early_post_process_client_hello()` (ssl/statem/statem_srvr.c) verifies the binder in `ssl_get_prev_session()` before `tls_parse_all_extensions()` reaches `tls_parse_ctos_cookie()`, which rebuilds the CH1 + HRR transcript and sets `SSL_HRR_PENDING` again.
So `tls_psk_do_binder()` (ssl/statem/extensions.c) hashes CH2 alone, while the client hashed CH1 + HRR + CH2.
A stateful TLS HRR (wrong key share guess) followed by resumption works, and the same order is still in OpenSSL master; the test is a strict xfail.
