# OpenSSL adapter

OpenSSL 4.1.0 (released 2026-10-23), built from the GitHub release tarball with a pinned SHA-256.
`build.sh` configures `no-shared no-docs no-tests`, installs into `.build/openssl/install/` and links `adapter.c` statically against `libssl.a`/`libcrypto.a` into `.build/openssl/bin/dtls-adapter`.
The library is rebuilt only when version, checksum or configure flags change; the adapter is recompiled on every run because the CI cache key covers `build.sh` but not `adapter.c`.
`run` execs the adapter binary.

The adapter is a small C program on libssl rather than `s_client`/`s_server`, because an empty key share, the listener's address validation and reliable `group`/`hrr` reporting need API-level control.
It calls `OPENSSL_init_ssl(OPENSSL_INIT_NO_LOAD_CONFIG)`, so no system `openssl.cnf` can change behaviour.
Both roles pin the protocol to DTLS 1.3 (`SSL_CTX_set_min/max_proto_version(DTLS1_3_VERSION)`).

## Option mapping

| Option | OpenSSL mapping |
|---|---|
| `--role server` | `DTLS_server_method()` and the DTLS listener API: `SSL_new_listener(ctx, SSL_LISTENER_FLAG_SINGLE_THREAD)`, `SSL_listen`, `SSL_accept_connection`, `SSL_accept` |
| `--role client` | `DTLS_client_method()`, connected UDP socket, `BIO_new_dgram`, `SSL_connect` |
| `--groups` (client) | `SSL_CTX_set1_groups_list("G1:G2")`, order is the `supported_groups` order |
| `--groups` (server) | `SSL_CTX_set1_groups_list("G1/G2")` plus `SSL_OP_SERVER_PREFERENCE`: one tuple per group, so the server picks its first group the client supports, via HRR if the client sent no share for it |
| `--key-share GROUP` | `*` prefix on that group in the client list, e.g. `X25519MLKEM768:*X25519`; without the option OpenSSL shares the first group |
| `--key-share empty` | Unsupported, exit 2 (see below) |
| `--mtu N` | `SSL_OP_NO_QUERY_MTU` + `SSL_set_mtu(N)`: N is the maximum UDP payload (DTLS records per datagram) |
| `--validate cookie` | Listener default: stateless HRR with cookie before `SSL_accept_connection` returns |
| `--validate off` | `SSL_LISTENER_FLAG_NO_VALIDATE` (the default when the option is omitted) |
| `--cert/--key` | `SSL_CTX_use_certificate_chain_file`, `SSL_CTX_use_PrivateKey_file` |
| `--ca` | `SSL_CTX_load_verify_locations`, `SSL_VERIFY_PEER`, `SSL_set1_dnsname("localhost")`, SNI `localhost` |
| `--psk-out` (client) | Saves the last NewSessionTicket session (`SSL_CTX_sess_set_new_cb`) as PEM |
| `--psk-in` (client) | `PEM_read_SSL_SESSION` + `SSL_set_session` |
| `--psk-out` / `--psk-in` (server) | Writes / loads the 80-byte ticket keys (`SSL_CTX_get/set_tlsext_ticket_keys`), so a new server process can decrypt the ticket |

Options that do not apply to a role (`--key-share`, `--ca` on the server; `--validate`, `--cert`, `--key` on the client) are ignored.

## Result fields

- `version`: `SSL_get_version()`, i.e. `DTLSv1.3`.
- `group`: `SSL_get0_group_name()`, mapped to IANA spelling (OpenSSL reports `x25519` in lower case).
- `hrr`: set by a message callback that sees a sent or received ServerHello whose random is the HRR value; libssl has no public getter.
The listener creates its connections from the same `SSL_CTX`, so the callback also sees the cookie HRR sent before `SSL_accept_connection` returns.
- `error`: the last OpenSSL reason string, e.g. `handshake: certificate verify failed`.

stderr logs every handshake message, ACK and alert with its size, and each plaintext (epoch 0) record header, which shows how ClientHello and ServerHello were fragmented.

## Unsupported

- `--key-share empty` on the client: `tls_construct_ctos_key_share()` fails with `SSL_R_NO_SUITABLE_KEY_SHARE` unless it adds at least one share, and no public API or group-list syntax produces an empty `key_share`.
An OpenSSL server does accept an empty `key_share` from other clients.
- Groups that OpenSSL 4.1.0 does not implement, notably `MLKEM512X25519` (draft-rosomakho-tls-ecdhe-mlkem512); any such group in `--groups` makes either role exit 2.
- An `--mtu` that `SSL_set_mtu` rejects (below about 208 bytes) exits 2.

## Observed OpenSSL behaviour

- The listener's DTLS 1.3 cookie is OpenSSL's TLS 1.3 stateless cookie (CH1 transcript hash, group, cipher, timestamp, the listener's 40-byte timestamp+HMAC, outer HMAC) and is 140 bytes.
With X25519MLKEM768, CH1 is 1409 bytes and fits one datagram at `--mtu 1500`, but CH2 grows to 1555 bytes and is fragmented.
- Listener connections are created internally on an unconnected socket, so `IP_MTU` cannot be queried and OpenSSL falls back to its 256-byte link minimum (228-byte datagrams) unless an MTU is set.
The adapter sets the MTU from a ClientHello callback because that is the first point where the application sees the connection.
- After a DTLS endpoint has sent close_notify, its record layer silently discards non-alert records and `SSL_read` returns 0; the server therefore waits up to 2 s for the client's close_notify before sending its own.
- `hrr` is `true` on both sides whenever `--validate cookie` is used, because the cookie exchange is a real HelloRetryRequest.
