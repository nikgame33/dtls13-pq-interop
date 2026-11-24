# NSS adapter

NSS 3.134 with NSPR 4.41 (released 2026-11-18), built from Mozilla's combined release archive `nss-3.134-with-nspr-4.41.tar.gz` (tags `NSS_3_134_RTM`, `NSPR_4_41_RTM`) with a pinned SHA-256.
`build.sh` runs `make nss_build_all BUILD_OPT=1 USE_64=1 NSS_DISABLE_GTESTS=1`, copies the shared libraries and headers into `.build/nss/install/` and links `adapter.c` into `.build/nss/bin/nss-adapter`.
NSS cannot be linked statically (libssl3 loads softoken and freebl at runtime), so the adapter is linked with a `DT_RPATH` to `install/lib`; unlike `RUNPATH`, it also applies to the libraries' own dependencies, so a system NSS is never loaded.
The adapter logs `NSS_GetVersion()` and `PR_GetVersion()` on its first stderr line, and the tests check them.
The library is rebuilt only when checksum or make flags change; the adapter is recompiled on every run.
`.built` holds `nss 3.134` on its first line, then the NSPR version, URL, checksum and make flags.
The NSS command-line tools need zlib headers, hence `apt-packages.txt`.

The adapter is a small C program on libssl rather than `tstclnt`/`selfserv`.
Those tools have DTLS (`-P`) and a group list (`-I`), but no control over the key share, the HRR cookie or the MTU, and no machine-readable result.
It calls `NSS_NoDB_Init`: no certificate or key database, no built-in roots and no policy file, so nothing outside the pinned build and the options affects a run.
Both roles pin the protocol to DTLS 1.3 (`SSL_VersionRangeSet` with `SSL_LIBRARY_VERSION_TLS_1_3` as minimum and maximum on a `DTLS_ImportFD` socket).
There are no variants: libssl has one DTLS code path per role, so `--variant` accepts only `default`.

## Option mapping

Every option of the role is required, accepted as `--opt=value` or `--opt value`, with its exact name (`getopt_long` prefixes such as `--group` are rejected).
A missing, unknown, repeated or other-role option and a malformed or empty value exit 64.

| Option | NSS mapping |
|---|---|
| `--port` | Server: binds it (`0` = any free port) and prints the bound port in the ready line; client: connects to it |
| `--groups` (client) | `SSL_NamedGroupConfig` in the given order, which is also the supported_groups order |
| `--groups` (server) | `SSL_NamedGroupConfig`, reordered per ClientHello, see Groups |
| `--key-share=GROUP` | `SSL_SendAdditionalKeyShares(fd, 0)`: one share, for the first group; GROUP must be the first `--groups` entry (else exit 2) and in `--groups` (else exit 64) |
| `--key-share=default` | Nothing is called; NSS sends one share for its first group |
| `--key-share=empty` | Unsupported, exit 2 (see below) |
| `--mtu=N` | Nothing to configure; N - 48 must be at least 1417 (else exit 2), and every sent datagram is checked against it, see MTU |
| `--mtu=default` | Nothing is configured |
| `--validate=cookie` | `SSL_HelloRetryRequestCallback`: the first ClientHello gets an HRR whose cookie carries the peer address as application token; the second is accepted only with that token |
| `--validate=off` | No callback |
| `--cert/--key` | PEM decoded with `ATOB_ConvertAsciiToItem`; `CERT_NewTempCertificate` for every certificate, `PK11_ImportDERPrivateKeyInfoAndReturnKey` (PKCS#8) for the key, then `SSL_ConfigServerCert` |
| `--ca` | Client: `CERT_NewTempCertificate` + `CERT_ChangeCertTrust("C,,")`, `SSL_SetURL("localhost")`, and `SSL_AuthCertificate` in the auth hook; server: required but unused (no client authentication) |

The server binds, prints the ready line, waits for the first datagram (`recvfrom` with `MSG_PEEK`) and `connect`s the socket to its sender, because an NSS DTLS socket serves exactly one peer.
The socket is wrapped with `PR_ImportUDPSocket` and an NSPR I/O layer that logs and checks every datagram before `DTLS_ImportFD`.
The handshake is driven non-blocking with `SSL_ForceHandshake`, `PR_Poll` and `DTLS_GetHandshakeTimeout` for the retransmission timer, with a 60 s limit.

### Groups

An unaided NSS server does not follow the contract's "key share first" rule.
`tls13_NegotiateKeyExchange` takes its first group that the client supports as preferred; it uses the client's share for that group, or for the group in the very next slot if its strength is within 2 bits (`tls13_isGroupAcceptable`), and otherwise sends an HRR for the preferred group.
So with three or more server groups, or groups of different strength, an acceptable share can trigger an HRR.
The adapter's I/O layer therefore reassembles each received ClientHello before libssl reads the datagram and calls `SSL_NamedGroupConfig` with the server's groups reordered: first those the client sent a share for, then the rest, each part in `--groups` order.
NSS then takes the highest-ranked server group with a share (rule 1), or sends an HRR for the highest-ranked server group the client supports (rule 2), or fails with `SSL_ERROR_NO_CYPHER_OVERLAP` (rule 3).
The new order is logged (`NSS group order: ...`); the tests cover all three rules and a three-group case the unaided server gets wrong.
See ADR 0007.

### MTU

NSS has no public DTLS MTU setting.
Its estimate starts at 1472 bytes (`COMMON_MTU_VALUES[0]` in `lib/ssl/dtlscon.c`, Ethernet less IPv4 and UDP) and only drops to the next table entry (1252, 548, 228) after retransmissions.
A handshake fragment is at most `mtu - DTLS_MAX_EXPANSION (77) - 12` bytes, so the largest datagram NSS sends is 1417 bytes, which the tests reach with a 3 kB certificate.
`--mtu=N` is the IP path MTU and no UDP payload may exceed N - 48, so the adapter runs `--mtu=N` for N >= 1465 without configuring anything and exits 2 below that.
The I/O layer still refuses any datagram above N - 48 and the run then fails with a clear error, so the limit cannot be exceeded silently.
The gtests use the internal `SSLInt_SetMTU`, which is not exported.
See ADR 0007 for the alternatives that were rejected.

## Result fields

- `version`: `SSL_GetChannelInfo` `protocolVersion`; `0x0304` is reported as `DTLSv1.3`.
- `group`: `SSLChannelInfo.keaGroup`, mapped to its IANA name.
- `hrr`, `hrr_cookie`, `hrr_group`: the I/O layer reassembles the plaintext handshake messages of both directions; a ServerHello with the HRR random (RFC 9846 section 4.2.3) is the HRR, and its extensions are scanned for cookie (44) and key_share (51, the selected_group).
- `error`: the NSPR/NSS error name and text, e.g. `handshake: SSL_ERROR_NO_CYPHER_OVERLAP: ...`; a failed server certificate check is reported as `certificate verify failed: SEC_ERROR_UNKNOWN_ISSUER`.

stderr logs every datagram, record, handshake message and alert with its size, the server's group order and the teardown.

## Teardown

The client sends close_notify (`PR_Shutdown(PR_SHUTDOWN_SEND)`) after `pong` and waits up to 2 s for the server's.
The server waits up to 2 s for the client's close_notify and only then sends its own.
The I/O layer turns `shutdown(2)` into a no-op, so the UDP socket stays usable for late ACKs.
Errors after `pong` only go to stderr.

## Unsupported

- `--key-share=empty`: `tls13_SetupClientHello` creates a share for the first enabled group and fails with `SSL_ERROR_NO_CIPHERS_SUPPORTED` if there is none, so an NSS client cannot send an empty `key_share`.
- `--key-share=GROUP` for any group but the first `--groups` entry: NSS shares for the first `1 + additionalShares` groups of its list, which is also the supported_groups order.
- `--mtu` below 1465 (exit 2), see MTU.
- Groups NSS 3.134 does not implement, notably `MLKEM512X25519` and pure `MLKEM768`; any such group in `--groups` makes either role exit 2.
Implemented: `X25519`, `secp256r1`, `secp384r1`, `secp521r1`, `X25519MLKEM768`, `SecP256r1MLKEM768`, `SecP384r1MLKEM1024`, `MLKEM1024` and `ffdhe2048` to `ffdhe8192`.

## Observed NSS behaviour

- Every NSS HRR carries a cookie, also with `--validate=off`: `tls13_SendHelloRetryRequest` always calls `tls13_MakeHrrCookie` (NSS servers keep no state across an HRR).
So a group-only HRR reports `hrr_cookie: true`.
- With X25519MLKEM768 the CH1 record is 1374 bytes and never fragmented, since it is below the 1383-byte fragment limit; CH2 after a cookie HRR (about 1500 bytes) is sent as two records.
- At `--mtu=default` the server flight fills 1417-byte datagrams.
On a path below 1465 bytes NSS shrinks its estimate only on every third retransmission timeout (`dtls_RetransmitTimerExpiredCb` in `lib/ssl/dtlscon.c`); behind a 1280-byte proxy path the CH1 then goes out as 1188 + 224 bytes after about 350 ms.
- A DTLS 1.3 ACK for part of a flight makes NSS resend the rest at once and restart the timer (`dtls13_HandleAck` in `lib/ssl/dtls13con.c`), so the timeout and with it the MTU backoff never happen while the peer keeps acknowledging.
Behind a 1280-byte path with a wolfSSL client, which ACKs each partial flight, the NSS server resent its 1417-byte datagram about 22,000 times in 30 s without shrinking it.
