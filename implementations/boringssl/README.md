# BoringSSL adapter

BoringSSL has no releases, so `build.sh` pins commit `f3ba8e447de666b3820ab613f050b3bd6d1cb333` (2026-11-24, the tip of `main` when this adapter was written, `BORINGSSL_API_VERSION` 45).
It fetches exactly that commit from https://boringssl.googlesource.com/boringssl, checks that `git rev-parse HEAD` matches the pin, and builds `libssl.a` and `libcrypto.a` with CMake (`-DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DBUILD_TESTING=OFF`).
Go and Perl are not needed, because the checkout ships pregenerated sources in `gen/`.
Headers and libraries go to `.build/boringssl/install/`; the source tree is deleted after the build.
The library is rebuilt only when the commit or the CMake flags change; `adapter.c` is recompiled on every run into `.build/boringssl/bin/dtls-adapter`.
`.built` holds `boringssl <commit>` on its first line, then the commit date, the repository URL and the CMake flags.
No extra apt packages are needed: `git`, `cmake` and a C/C++ compiler are on the stock `ubuntu-24.04` runner.

The `bssl` tool has no DTLS mode, so the adapter is a small C program on libssl.
Both roles pin the protocol to version 1.3: `DTLS1_3_VERSION` on `DTLS_method()`, or `TLS1_3_VERSION` on `TLS_method()` with `--transport=tls`.
`transports` declares `dtls` and `tls`.

## Variants

None.
BoringSSL has no DTLS listener, no `DTLSv1_listen()` for DTLS 1.3 and no datagram BIO, so there is one code path per role and no `variants` file.
Only `--variant=default` is accepted; anything else exits 64.

## Transport

The adapter supplies its own `BIO_METHOD` on a non-blocking socket and logs every datagram (`>> datagram (N bytes)`) or TCP write/read (`>> tcp (N bytes)`).
The DTLS client uses a connected UDP socket.
The DTLS server waits for the first datagram from a new source (`recvfrom(MSG_PEEK)`), then exchanges datagrams with that peer only (`sendto`/`recvfrom`, other sources are logged and ignored) and runs `SSL_accept`.
Its socket stays unconnected, so with `--resume=ticket` the second connection's first datagram, from a new source port, is never refused.
With `--transport=tls` the server `listen`s, `accept`s one TCP connection per TLS connection and closes it after the teardown; the client connects a new TCP socket per connection.
BoringSSL leaves DTLS timers to the caller: the adapter polls until `DTLSv1_get_timeout` expires and then calls `DTLSv1_handle_timeout` (first timeout 400 ms, doubling).
A handshake that makes no progress for 60 s fails with exit 1.

## Option mapping

Every option of the role is required, accepted as `--opt=value` or `--opt value`.
A missing, unknown, repeated or other-role option, a malformed value, a group listed twice and a `--key-share` group not in `--groups` exit 64.
Option names must match exactly: `getopt_long` would accept an abbreviation such as `--group`, so the adapter first rejects any `--name` that is not a full option name.

| Option | BoringSSL mapping |
|---|---|
| `--port` | Server: binds it (`0` = any free port) and prints the bound port in the ready line; client: connects to it |
| `--transport dtls` / `tls` | `DTLS_method()` over UDP / `TLS_method()` over TCP |
| `--resume off` | One connection |
| `--resume ticket` | Client: `SSL_CTX_set_session_cache_mode(SSL_SESS_CACHE_CLIENT \| SSL_SESS_CACHE_NO_INTERNAL)` and `SSL_CTX_sess_set_new_cb` keep the latest resumable session from a NewSessionTicket; connection 2 offers it with `SSL_set_session`. Server: serves two connections from one `SSL_CTX`, which issues tickets by default (two per handshake) |
| `--groups` | IANA names mapped to code points, then `SSL_CTX_set1_group_ids`; the supported_groups order on the client, the preference order on the server |
| `--key-share GROUP` | `SSL_set1_client_key_shares(ssl, &id, 1)` |
| `--key-share empty` | `SSL_set1_client_key_shares(ssl, NULL, 0)`, the documented way to send an empty key_share |
| `--key-share default` | No call: BoringSSL shares the first group plus the first later group of the other kind, post-quantum or classical (`ssl/extensions.cc`) |
| `--mtu N` | `SSL_set_options(SSL_OP_NO_QUERY_MTU)` and `SSL_set_mtu(ssl, N - 48)`; see below |
| `--mtu default` | No call, see below; the only valid value with `--transport=tls` |
| `--validate off` | Nothing to do: a BoringSSL server never validates addresses |
| `--validate cookie` | Unsupported, exit 2 (see below) |
| `--cert`, `--key` | `SSL_CTX_use_certificate_chain_file`, `SSL_CTX_use_PrivateKey_file` (PEM) |
| `--ca` | Client: `SSL_CTX_load_verify_locations`, `SSL_VERIFY_PEER`, `SSL_set1_host("localhost")` and SNI `localhost`; the server accepts it but does not load it |

The result line takes `version` from `SSL_get_version`, `group` from `SSL_get_group_id`, mapped back to the IANA name, and `resumed` from `SSL_session_reused`.
With `--resume=ticket` it describes the last connection attempted, and every error is prefixed `connection N: `.
A client that has no resumable ticket when it has read `pong` on connection 1 fails with `connection 1: no session ticket received`.
`hrr` is `SSL_used_hello_retry_request` or an observed HelloRetryRequest; `hrr_cookie` and `hrr_group` are parsed from the HelloRetryRequest in the message callback (`SSL_CTX_set_msg_callback`).

### Group selection

BoringSSL natively selects in strict server preference: it takes the first server group the client supports (`tls1_get_shared_group` in `ssl/extensions.cc`) and sends a HelloRetryRequest if the client sent no share for it (`ssl/tls13_server.cc`).
The contract requires "key share first" (ADR 0002, ADR 0006), so the server's `select_certificate_cb` reads the ClientHello's key_share, moves the highest-ranked server group the client sent a share for to the front and calls `SSL_set1_group_ids` for this connection.
It logs `key share first: selecting G`.
Without an acceptable share the list is left as configured, so the HelloRetryRequest names the server's highest-ranked group the client supports; without a mutual group the handshake fails with `NO_SHARED_GROUP`.

### MTU

`--mtu N` is the IP path MTU, so no UDP payload may exceed N - 48 bytes (IPv6 40 + UDP 8).
`SSL_set_mtu` bounds the whole datagram, record headers included (`ssl/d1_both.cc`), so the adapter passes N - 48 and sets `SSL_OP_NO_QUERY_MTU` so that BoringSSL never replaces it.
`SSL_set_mtu` rejects values below 228 (`kMinMTU`), so `--mtu` below 276 exits 2.
With `--mtu=default` the adapter's BIO answers no MTU query, so BoringSSL falls back to `kDefaultMTU`, 1472-byte datagrams.
That is 20 bytes more than a 1500-byte IPv6 path allows.

### Teardown

The client sends `close_notify` after the pong and waits up to 2 s for the server's; the server waits up to 2 s for the client's and then sends its own.
With TLS the socket is closed afterwards.
In DTLS, `SSL_shutdown` never waits for the peer's `close_notify` (`ssl/ssl_lib.cc`), so both waits read with `SSL_read` until `SSL_ERROR_ZERO_RETURN`.
A missing `close_notify` costs the 2 s and does not fail the run.

## Supported groups

X25519, secp256r1, secp384r1, secp521r1, X25519MLKEM768 and MLKEM1024 (`kNamedGroups` in `ssl/ssl_key_share.cc`).
The default supported groups are X25519MLKEM768, X25519, secp256r1 and secp384r1.

## Unsupported (exit 2)

- `--validate=cookie`, with either transport: a BoringSSL server never sends a cookie; `do_send_hello_retry_request` in `ssl/tls13_server.cc` writes only supported_versions and key_share, and there is no API for stateless address validation.
The adapter exits 2 before it prints the ready line.
The conformance suite skips its cookie cases for a BoringSSL server; S04, S10 and T01 with a BoringSSL server are `unsupported`.
BoringSSL clients do echo a cookie (`ssl/tls13_client.cc`).
- `MLKEM512X25519`, `SecP256r1MLKEM768`, `SecP384r1MLKEM1024` and any other group BoringSSL does not implement (`SSL_get_group_name` returns NULL).
- `--mtu` below 276.

## Diagnostics

The adapter logs to stderr: a banner with commit and API version, every datagram (`>> datagram (N bytes)`), every plaintext handshake record header, every handshake message or fragment (`>> ClientHello (1337 bytes, fragment 0+1207)`), the key_share groups of each complete ClientHello (`<< ClientHello (1337 bytes, key_share=X25519MLKEM768)`), HelloRetryRequests with their extensions, ACKs and alerts.

## Observed behaviour

At the pinned commit, with OpenSSL 4.1.0 and wolfSSL v5.9.4-stable from this repository; covered by `tests/impl/test_boringssl.py` (cross-implementation tests skip unless the peer is built).

- An empty key_share works in both roles: BoringSSL clients send it and BoringSSL servers answer with a HelloRetryRequest naming a group (against BoringSSL, OpenSSL and wolfSSL servers, and from a wolfSSL client).
- A BoringSSL client in its default configuration (default groups and key shares, no MTU set) fails against a wolfSSL server in its default configuration (HRR cookie on).
The 1379-byte CH1 fits one datagram and the wolfSSL server answers with a cookie HelloRetryRequest; CH2 then grows to 1468 bytes and is fragmented at 1472 bytes.
BoringSSL writes the cookie extension after key_share (`kExtensions` in `ssl/extensions.cc`), so its last 21 bytes land in the second fragment, and wolfSSL drops a fragmented ClientHello whose first fragment does not hold the whole cookie (`DoClientHelloStateless` in `src/dtls.c`).
The client retransmits until it gives up.
Without the cookie, or against OpenSSL in either validation mode, the same client configuration succeeds.
- A fragmented CH1 with an X25519MLKEM768 share (`--mtu=1280`) is dropped by the wolfSSL `default` server, as for every fragmenting client; the `accept-tls13` server variant accepts it with the cookie off.
- PSK resumption works in both transports, also after a HelloRetryRequest: against an OpenSSL cookie server at `--mtu=1280` (S10) both connections fragment CH1 and CH2, CH2 carries cookie and PSK, and both sides report `resumed`.
Against itself, without a cookie, a key share HelloRetryRequest in both connections makes the client recompute its binder over the HelloRetryRequest (RFC 9846 sec 4.3.11.2).
- A BoringSSL TLS client echoes the cookie of an OpenSSL or wolfSSL TLS server (T01).
- Against a wolfSSL server every scenario with a fragmented CH1 (S03, S04, S08, S09, S10 and their `+split` rows) times out, exactly as with an OpenSSL client: wolfSSL drops the fragmented CH1 (see `implementations/wolfssl/README.md`); the `accept-tls13` variant accepts it only with the cookie off.
