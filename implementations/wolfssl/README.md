# wolfSSL adapter

`build.sh` builds wolfSSL 5.9.4 from the wolfssl.com release zip (pinned SHA-256), which ships a generated `configure` and otherwise matches tag `v5.9.4-stable`.
The library is built statically into `.build/wolfssl/install/` and the adapter (`adapter.c`) is linked against it as `.build/wolfssl/bin/wolfssl-adapter`.
The first line of `.build/wolfssl/.built` is the version (`wolfssl v5.9.4-stable`); the following lines record the URL, checksum, configure flags and CPPFLAGS of the build.
No extra apt packages are needed: `curl`, `unzip` and a C compiler are on the stock `ubuntu-24.04` runner.

## Configure flags

Everything not listed here is the upstream default.

| Flag | Why |
|---|---|
| `--enable-dtls13` | DTLS 1.3; it also turns on DTLS, TLS 1.3 and `WOLFSSL_SEND_HRR_COOKIE`. |
| `--enable-dtls-mtu` | Needed for `wolfSSL_dtls_set_mtu()`, which `--mtu` uses. |
| `--enable-curve25519` | Deviation from defaults: X25519 is off by default in 5.9.4, and X25519MLKEM768 needs it too. |
| `--enable-static --disable-shared` | The adapter links the library statically, so no `LD_LIBRARY_PATH` is needed. |
| `--disable-examples --disable-crypttests --disable-benchmark` | Build time only; no effect on the library. |
| `CPPFLAGS=-DDEBUG_WOLFSSL` | Compiles in the debug log, which stays off unless `DTLS_INTEROP_WOLFSSL_DEBUG` is set. |

ML-KEM and the hybrid groups are on by default in 5.9.4, so no PQC flag is passed.
With ML-KEM and DTLS 1.3, configure also auto-enables `WOLFSSL_DTLS_CH_FRAG` (server-side reassembly of a fragmented ClientHello); there is no way to switch it off at configure time.

## Option mapping

| Option | wolfSSL API |
|---|---|
| `--role client` / `server` | `wolfDTLSv1_3_client_method()` / `wolfDTLSv1_3_server_method()`, then `wolfSSL_connect()` / `wolfSSL_accept()`. |
| `--variant` | `default`, or a name from `variants` (see below). |
| `--port 0` | Server only: binds an ephemeral port and reports it in the ready line. |
| `--groups` | Each group is probed with `wolfSSL_UseSupportedCurve()`, then the list is set with `wolfSSL_set_groups()` in preference order. |
| `--key-share GROUP` | `wolfSSL_UseKeyShare()` (client only); exit 2 if that share does not fit into CH1, see below. |
| `--key-share empty` | `wolfSSL_NoKeyShares()` (client only). |
| `--key-share default` | No call: wolfSSL offers a share for the first `--groups` entry. |
| `--mtu N` | `wolfSSL_dtls_set_mtu(N - 48)`, see below. |
| `--mtu default` | No call: wolfSSL's default limit of 1400 bytes applies. |
| `--validate cookie` | `wolfSSL_send_hrr_cookie(ssl, NULL, 0)` (server only); this is also the library default for a DTLS 1.3 server. |
| `--validate off` | `wolfSSL_disable_hrr_cookie()` (server only). |
| `--cert`, `--key` | `wolfSSL_CTX_use_certificate_chain_file()`, `wolfSSL_CTX_use_PrivateKey_file()` (PEM). |
| `--ca` | Client: `wolfSSL_CTX_load_verify_locations()` with `WOLFSSL_VERIFY_PEER` and a hostname check for `localhost` via `wolfSSL_check_domain_name()`. The server accepts it but does not load it, since there is no client authentication. |

Both `--opt=value` and `--opt value` are accepted; option names must match exactly (no abbreviations) and values must not be empty.
Every option of a role is required.
A missing, repeated or unknown option, an option of the other role, a variant not listed for the role or a malformed value is a usage error with exit code 64, and so is a `--key-share` group that is not in `--groups`.
The adapter never forks or daemonizes; the server serves one client and exits.

The server prints `{"event": "ready", "port": N}` once its socket is bound.
The result line takes `version` from `wolfSSL_get_version()` and `group` from `wolfSSL_get_curve_name()`, mapped back to the IANA name.
`hrr`, `hrr_cookie` and `hrr_group` are not exposed by the wolfSSL API without `OPENSSL_EXTRA`, so the adapter parses the records in its IO callbacks: the client inspects received HelloRetryRequests, the server sent ones.
`hrr_cookie` is true if the HelloRetryRequest has a `cookie` extension and `hrr_group` if it has a `key_share` extension; both are false without an HRR.

### Group selection

The server selects "key share first", as the contract requires: if the client sent a share for any group the server accepts, that group is used without an HRR, even if the server ranks another mutual group higher.
wolfSSL does this natively (`src/tls.c`, `TLSX_KeyShare_Choose`); `test_server_selects_key_share_first` confirms it.
Without an acceptable share, the HelloRetryRequest names the server's highest-ranked group the client supports.

### Teardown

After the ping/pong exchange the client sends `close_notify` with `wolfSSL_shutdown()` and waits up to 2 s for the server's `close_notify`.
The server, after its pong, waits up to 2 s in `wolfSSL_read()` for the client's `close_notify` (`WOLFSSL_ERROR_ZERO_RETURN`) and only then sends its own.
Both waits use non-blocking mode with `poll()`, so a missing `close_notify` only costs the 2 s and does not fail the run.

### MTU

`--mtu N` is the IP path MTU, so no UDP payload may exceed N - 48 bytes (IPv6 40 + UDP 8).
`wolfSSL_dtls_set_mtu()` bounds the whole datagram wolfSSL writes, record headers included (`src/internal.c`, `CheckAvailableSize`, `wolfssl_local_GetMaxPlaintextSize`), so the adapter passes N - 48.
For `--mtu=1280` the largest datagram is 1232 bytes, which the tests check on both sides from the stderr trace.
wolfSSL reads into a buffer of its MTU plus 500 bytes (`WOLFSSL_DTLS_MTU_ADDITIONAL_READ_BUFFER`), so a peer sending larger datagrams than that would be truncated.
Without `--mtu`, wolfSSL limits datagrams to 1400 bytes (`WOLFSSL_MAX_MTU`).

## Supported groups

X25519, secp256r1, secp384r1, X25519MLKEM768, SecP256r1MLKEM768 and SecP384r1MLKEM1024.

## Unsupported (exit 2)

- `MLKEM512X25519`: wolfSSL 5.9.4 has no implementation of code point 0x11EA; it only has the OQS code point X25519MLKEM512 (12214) behind `--enable-experimental`.
- `MLKEM768` (standalone ML-KEM): wolfSSL supports it, but it is off by default and not enabled in this build.
- Any other group name.

PSK options are not part of the contract and are rejected as unknown options (exit 64).

## wolfSSL behaviour around large ClientHellos

These findings are covered by `tests/impl/test_wolfssl.py` (strict xfails mark the cases that do not work).

- The wolfSSL client never fragments CH1.
If CH1 with the requested key share does not fit into the MTU, it sends an empty `key_share` instead and lets the server answer with a HelloRetryRequest (`src/tls13.c`, `SendTls13ClientHello`, debug message "Sending empty key share so we don't fragment CH1").
There is no runtime switch for this (`WOLFSSL_DTLS_CH_FRAG` is compile-time).
With `--key-share=GROUP` that breaks the contract, so the send callback refuses such a CH1 before it leaves the process and the client exits 2 ("unsupported"); nothing reaches the server.
With `--key-share=default` the substitution is the library's choice and is kept.
At `--mtu=1280` the 1403-byte X25519MLKEM768 CH1 does not fit, so a default-share handshake always has `hrr: true`; CH2 is then fragmented, which works.
With `--mtu=default` the same happens, because the default 1400-byte limit is 3 bytes short of that CH1, so a wolfSSL client never sends an X25519MLKEM768 share in CH1.
- The wolfSSL server with the cookie on (the default) silently drops a fragmented CH1, because the first fragment carries no cookie (`src/dtls13.c`, `DoClientHelloStateless`, "Cookie probably missing from first fragment. Dropping.").
The peer then times out.
- With `--validate off` the server still drops a fragmented CH1 when it runs `wolfSSL_accept()`, because that entry point does not mark the connection stateful when the cookie is off; `wolfSSL_accept_TLSv13()` does, and then reassembles the fragmented CH1 fine.
The `accept-tls13` variant exists to show this (see below).
- In the cookie exchange, the HelloRetryRequest carries only `cookie` and `supported_versions` when the key share was acceptable, and the wolfSSL client echoes the cookie in CH2.

## Variants

`variants` lists the variants besides `default` as `ROLE NAME: description`; the matrix shows them as `wolfssl+NAME`.
`--variant=default` is accepted in both roles, a listed variant only in its role, and anything else exits 64.

- `server accept-tls13`: the server calls `wolfSSL_accept_TLSv13()` instead of `wolfSSL_accept()`.
Nothing else changes; `--role=client --variant=accept-tls13` is a usage error, since the client has no such choice.
With `--validate=off` this entry point marks the connection stateful, so the server reassembles a fragmented CH1 that `wolfSSL_accept()` drops (see above).
With `--validate=cookie` both entry points behave the same.
`default` keeps `wolfSSL_accept()` because that is what wolfSSL's example server and typical applications call.

## Diagnostics

The adapter logs every handshake datagram to stderr, for example `[wolfssl-adapter] tx 1403B | rec=22 epoch=0 hs=1 seq=0 frag=0+1378/1378 exts=43:3,...,51:1222(0x11ec),...`.
`exts` lists extension type:length pairs, and the key_share groups (CH) or selected group (SH, HRR) are shown in parentheses; encrypted records are shown as `ciphertext`.
Setting `DTLS_INTEROP_WOLFSSL_DEBUG=1` additionally turns on the wolfSSL debug log on stderr via `wolfSSL_Debugging_ON()`; it changes nothing else.
A 60 s `alarm()` ends a hung handshake with exit code 1 and a result line; wolfSSL retransmits internally with backoff, so the adapter has no other timeout.
