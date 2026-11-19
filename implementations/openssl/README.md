# OpenSSL adapter

OpenSSL 4.1.0 (released 2026-10-23), built from the GitHub release tarball with a pinned SHA-256.
`build.sh` configures `no-shared no-docs no-tests`, installs into `.build/openssl/install/` and links `adapter.c` statically against `libssl.a`/`libcrypto.a` into `.build/openssl/bin/dtls-adapter`.
The library is rebuilt only when version, checksum or configure flags change; the adapter is recompiled on every run because the CI cache key covers `build.sh` but not `adapter.c`.
`.built` holds `openssl 4.1.0` on its first line (read by the runner) and the configure flags on the second.
`run` execs the adapter binary, which stays in the caller's process group; the server exits after serving one client.

The adapter is a small C program on libssl rather than `s_client`/`s_server`, because an empty key share, the listener's address validation and reliable `group`/`hrr` reporting need API-level control.
It calls `OPENSSL_init_ssl(OPENSSL_INIT_NO_LOAD_CONFIG)`, so no system `openssl.cnf` can change behaviour.
Both roles pin the protocol to DTLS 1.3 (`SSL_CTX_set_min/max_proto_version(DTLS1_3_VERSION)`).

## Option mapping

Options are accepted as `--opt=value` (what the runner passes) and as `--opt value` (`getopt_long`).

| Option | OpenSSL mapping |
|---|---|
| `--role server` | `DTLS_server_method()` and the DTLS listener API: `SSL_new_listener(ctx, SSL_LISTENER_FLAG_SINGLE_THREAD)`, `SSL_listen`, `SSL_accept_connection`, `SSL_accept` |
| `--role client` | `DTLS_client_method()`, connected UDP socket, `BIO_new_dgram`, `SSL_connect` |
| `--groups` (client) | `SSL_CTX_set1_groups_list("G1:G2")`, order is the `supported_groups` order |
| `--groups` (server) | `SSL_CTX_set1_groups_list("G1/G2")` plus `SSL_OP_SERVER_PREFERENCE`: one tuple per group, so the server picks its first group the client supports, via HRR if the client sent no share for it |
| `--key-share GROUP` | `*` prefix on that group in the client list, e.g. `X25519MLKEM768:*X25519`; without the option OpenSSL shares the first group |
| `--key-share empty` | Unsupported, exit 2 (see below) |
| `--mtu N` | `SSL_OP_NO_QUERY_MTU` + `SSL_set_mtu(N - 48)`; see below |
| `--validate cookie` | Listener default: stateless HRR with cookie before `SSL_accept_connection` returns |
| `--validate off` | `SSL_LISTENER_FLAG_NO_VALIDATE` (the default when the option is omitted) |
| `--cert/--key` | `SSL_CTX_use_certificate_chain_file`, `SSL_CTX_use_PrivateKey_file` |
| `--ca` | `SSL_CTX_load_verify_locations`, `SSL_VERIFY_PEER`, `SSL_set1_dnsname("localhost")`, SNI `localhost` |
| `--psk-out` (client, beyond the current contract) | Saves the last NewSessionTicket session (`SSL_CTX_sess_set_new_cb`) as PEM |
| `--psk-in` (client) | `PEM_read_SSL_SESSION` + `SSL_set_session` |
| `--psk-out` / `--psk-in` (server, beyond the current contract) | Writes / loads the 80-byte ticket keys (`SSL_CTX_get/set_tlsext_ticket_keys`), so a new server process can decrypt the ticket |

Options that do not apply to a role (`--key-share`, `--ca` on the server; `--validate`, `--cert`, `--key` on the client) are ignored.
The client requires only `--ca`.

### MTU

`--mtu N` is the IP path MTU, and no UDP payload may exceed N - 48 bytes (IPv6 40 + UDP 8), whatever the address family.
`SSL_set_mtu()` takes exactly that unit: the largest datagram payload, from which OpenSSL subtracts its own record overhead.
`DTLS_set_link_mtu()` is not used because it subtracts the overhead of the actual socket family, only 28 bytes on IPv4.
`SSL_OP_NO_QUERY_MTU` stops OpenSSL from replacing the value with a kernel `IP_MTU` query or shrinking it after retransmissions.
On the server the value is applied per connection in the ClientHello callback (see below), and the listener's receive limit is raised when N - 48 exceeds its 2000-byte default.
Every sent datagram is logged to stderr (`>> datagram (N bytes)`, via a BIO callback), and the tests check all of them against N - 48; at `--mtu=1500` the ServerHello flight fills exactly 1452 bytes.

## Result fields

- `version`: `SSL_get_version()`, i.e. `DTLSv1.3`.
- `group`: `SSL_get0_group_name()`, mapped to IANA spelling (OpenSSL reports `x25519` in lower case).
- `hrr`: set by a message callback that sees a sent or received ServerHello whose random is the HRR value; libssl has no public getter.
The listener creates its connections from the same `SSL_CTX`, so the callback also sees the cookie HRR sent before `SSL_accept_connection` returns.
- `error`: the last OpenSSL reason string, e.g. `handshake: certificate verify failed`.

stderr logs every handshake message, ACK and alert with its size, every sent datagram, and each plaintext (epoch 0) record header, which shows how ClientHello and ServerHello were fragmented.

## Unsupported

- `--key-share empty` on the client: `tls_construct_ctos_key_share()` fails with `SSL_R_NO_SUITABLE_KEY_SHARE` unless it adds at least one share, and no public API or group-list syntax produces an empty `key_share`.
An OpenSSL server does accept an empty `key_share` from other clients.
- Groups that OpenSSL 4.1.0 does not implement, notably `MLKEM512X25519` (draft-rosomakho-tls-ecdhe-mlkem512); any such group in `--groups` makes either role exit 2.
- An `--mtu` below 256 exits 2, because `SSL_set_mtu` rejects payloads under 208 bytes (OpenSSL's 256-byte link minimum less 48).

## Observed OpenSSL behaviour

- The listener's DTLS 1.3 cookie is OpenSSL's TLS 1.3 stateless cookie (CH1 transcript hash, group, cipher, timestamp, the listener's 40-byte timestamp+HMAC, outer HMAC) and is 140 bytes.
With X25519MLKEM768, the CH1 record is 1422 bytes and fits one datagram at `--mtu=1500` (1452-byte payload), but CH2 grows to 1555 bytes of handshake message and is fragmented; at `--mtu=1280` both are fragmented.
- Listener connections are created internally on an unconnected socket, so `IP_MTU` cannot be queried and OpenSSL falls back to its 256-byte link minimum (228-byte datagrams) unless an MTU is set.
The adapter sets the MTU from a ClientHello callback because that is the first point where the application sees the connection.
- After a DTLS endpoint has sent close_notify, its record layer silently discards non-alert records and `SSL_read` returns 0; the server therefore waits up to 2 s for the client's close_notify before sending its own.
- `hrr` is `true` on both sides whenever `--validate cookie` is used, because the cookie exchange is a real HelloRetryRequest.
