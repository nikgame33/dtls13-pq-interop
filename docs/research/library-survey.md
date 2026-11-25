# Library survey: GnuTLS, MLKEM512X25519, mbedTLS, DTLS 1.3 bis

Research note for the open questions in TODO.md.
All sources were checked on 2026-11-24; source links point at the commit or tag listed in [Snapshots](#snapshots).
Code observations come from reading those trees; the OpenSSL S07 result comes from a local test run described in [S07 with OpenSSL](#s07-with-openssl-410-plus-a-backport).

## Summary

| Question | Answer (checked 2026-11-24) |
|---|---|
| GnuTLS DTLS 1.3? | No, neither in 3.8.14 (latest release) nor on master; a draft MR has been idle since 2024. Do not add GnuTLS now. |
| Who implements MLKEM512X25519 (0x11EA)? | Only OpenSSL master (4.2.0-dev). No release of any surveyed library has it. |
| S07 with OpenSSL 4.1.0? | Not as released. With a backport of OpenSSL commit 108ced2 it works: DTLS 1.3, HRR cookie, CH1 and CH2 each in one datagram below 1232 bytes. |
| S07 with wolfSSL 5.9.4? | No configuration. Its X25519MLKEM512 uses the OQS code point 0x2FB6, not 0x11EA; a source patch would be needed. |
| mbedTLS 4.3.0 DTLS 1.3? | Absent in 4.3.0 and on development; requests are rejected with "DTLS 1.3 is not yet supported." |
| mbedTLS TLS 1.3 HRR cookie | The client echoes a cookie from an HRR; the server never sends one. |
| mbedTLS ML-KEM | None, neither in mbedTLS nor in TF-PSA-Crypto (release or development). |
| dtls13-spec #313, #333 | Both open; the CH1 fragmentation fix PR #334 was closed unmerged; draft -02 has no text on CH1 fragmentation. |

## GnuTLS

Sources in this section checked 2026-11-24.

- The latest release is 3.8.14 ([NEWS](https://gitlab.com/gnutls/gnutls/-/blob/3.8.14/NEWS), released 2026-11-18); master is at its release merge [6542d6f](https://gitlab.com/gnutls/gnutls/-/commit/6542d6fc9e05a7fd5370da0832dbbc6bbd7a54db).
- The highest DTLS version is DTLS 1.2: `GNUTLS_DTLS_VERSION_MAX = GNUTLS_DTLS1_2` in [gnutls.h.in L825 (3.8.14)](https://gitlab.com/gnutls/gnutls/-/blob/3.8.14/lib/includes/gnutls/gnutls.h.in#L825), same on [master](https://gitlab.com/gnutls/gnutls/-/blob/6542d6fc9e05a7fd5370da0832dbbc6bbd7a54db/lib/includes/gnutls/gnutls.h.in#L825).
- The priority code still says "we need to introduce similar handling to above when DTLS1.3 is supported" ([priority.c L2937](https://gitlab.com/gnutls/gnutls/-/blob/3.8.14/lib/priority.c#L2937)).
- Feature request [#1019 "Add support for DTLS 1.3"](https://gitlab.com/gnutls/gnutls/-/work_items/1019) is open (created 2020-06-05, last updated 2022-11-10).
- [MR !1667 "Draft: DTLS1_3"](https://gitlab.com/gnutls/gnutls/-/merge_requests/1667) is still a draft (opened 2022-11-10, last updated 2024-12-21).
Its branch [wip/dtls13](https://gitlab.com/gnutls/gnutls/-/commits/wip/dtls13) ends at [92e0dc7 "DTLS1_3: server support"](https://gitlab.com/gnutls/gnutls/-/commit/92e0dc7d629294737179f3cb90ccd9feef167f14) from 2023-05-22.
- Recent DTLS merge requests (!2153, !2169, !2179, !2180) are DTLS 1.2 fixes ([MR list](https://gitlab.com/gnutls/gnutls/-/merge_requests?search=DTLS)).
- PQ groups exist for TLS 1.3 only with ML-KEM-768 and ML-KEM-1024, e.g. `GNUTLS_GROUP_EXP_X25519_MLKEM768` ([gnutls.h.in L1170-L1172](https://gitlab.com/gnutls/gnutls/-/blob/3.8.14/lib/includes/gnutls/gnutls.h.in#L1170-1172)); there is no ML-KEM-512 hybrid.

Recommendation: do not add GnuTLS to the matrix; revisit when !1667 is merged.

## MLKEM512X25519 (0x11EA)

Sources in this section checked 2026-11-24.

### Registry and draft

- IANA lists 4585 SecP256r1MLKEM512 and 4586 (0x11EA) MLKEM512X25519 with DTLS-OK "Y" and Recommended "N", referencing draft-rosomakho-tls-ecdhe-mlkem512-00 ([TLS Supported Groups](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8)).
- The current draft is [-01](https://datatracker.ietf.org/doc/html/draft-rosomakho-tls-ecdhe-mlkem512-01) (2026-09-14).
Its Section 4.1 puts the ML-KEM-512 encapsulation key (800 bytes) first and the X25519 public key (32 bytes) second, so the client key share is 832 bytes.

### Per library

| Library | Version checked | MLKEM512X25519 0x11EA | DTLS 1.3 | Evidence |
|---|---|---|---|---|
| OpenSSL | 4.1.0 | no | yes | [tlsgroups.h (4.1.0)](https://github.com/openssl/openssl/blob/openssl-4.1.0/include/internal/tlsgroups.h) has no ML-KEM-512 hybrid |
| OpenSSL | master 5928f99 (4.2.0-dev) | yes, TLS 1.3 and DTLS 1.3 | yes | [tlsgroups.h L67-L68](https://github.com/openssl/openssl/blob/5928f99e9cee5203f52081a040b64da6c4616662/include/internal/tlsgroups.h#L67-L68), [capabilities.c L97](https://github.com/openssl/openssl/blob/5928f99e9cee5203f52081a040b64da6c4616662/providers/common/capabilities.c#L97), [CHANGES.md L171](https://github.com/openssl/openssl/blob/5928f99e9cee5203f52081a040b64da6c4616662/CHANGES.md#L171) |
| wolfSSL | v5.9.4-stable and master d31d625 | no (only 0x2FB6, see below) | yes | [ssl.h L5006-L5018 (5.9.4)](https://github.com/wolfSSL/wolfssl/blob/v5.9.4-stable/wolfssl/ssl.h#L5006-L5018) |
| BoringSSL | main 5ec0991 | no; only X25519MLKEM768 and MLKEM1024 | yes | [ssl.h L2732-L2733](https://github.com/google/boringssl/blob/5ec099107553142e9cb34dfe52f3c5bb42c9b7fb/include/openssl/ssl.h#L2732-L2733), [DTLS1_3_VERSION L578](https://github.com/google/boringssl/blob/5ec099107553142e9cb34dfe52f3c5bb42c9b7fb/include/openssl/ssl.h#L578) |
| NSS | 3.134 RTM and master bf1a5ff (3.135 Beta) | no; ML-KEM-768/1024 groups only | yes | [sslt.h L272-L276 (3.134)](https://github.com/nss-dev/nss/blob/NSS_3_134_RTM/lib/ssl/sslt.h#L272-L276), [sslproto.h L26](https://github.com/nss-dev/nss/blob/NSS_3_134_RTM/lib/ssl/sslproto.h#L26); no Bugzilla bug matches "mlkem512" or "ML-KEM-512" ([search](https://bugzilla.mozilla.org/buglist.cgi?quicksearch=mlkem512)) |
| mbedTLS | 4.3.0 and development 0e2cc5f | no ML-KEM at all | no | see [mbedTLS](#mbedtls-430) |
| GnuTLS | 3.8.14 and master | no | no | see [GnuTLS](#gnutls) |
| pion/dtls (Go) | v4.0.2 | no; X25519MLKEM768 only | yes, default since v4.0.0 | [README](https://github.com/pion/dtls/blob/v4.0.2/README.md), [options.go L494-L498](https://github.com/pion/dtls/blob/v4.0.2/options.go#L494-L498), [PR #1271 "Enable DTLS 1.3 by default"](https://github.com/pion/dtls/pull/1271) |
| Go crypto/tls | master ca94e2d | no; 4587, 4588, 4589, 514 | no DTLS | [common.go L151-L158](https://github.com/golang/go/blob/ca94e2de875d2665297df109c80db5e8e94db3cc/src/crypto/tls/common.go#L151-L158) |
| rustls | main e11f980 | no | no; only the version code points | [enums.rs L188-L189](https://github.com/rustls/rustls/blob/e11f98090bee85e6cb2ca03b11819fd145668795/rustls/src/enums.rs#L188-L189) |

### OpenSSL

- The groups came with [commit 108ced2 "ML-KEM-512 hybrid TLS KEMs"](https://github.com/openssl/openssl/commit/108ced2e23df54b8e6cb7062c6ae95fcd9365e28) from [PR #32670](https://github.com/openssl/openssl/pull/32670), merged on 2026-09-21.
- The PR says: "Commit on 'hold' pending 4.1 branch fork, this feature is too late for 4.1."
So 0x11EA ships with 4.2.0 at the earliest; it is listed in the 4.2 section of CHANGES.md.
- The capability entry allows both TLS 1.3 and DTLS 1.3 (`TLS1_3_VERSION, 0, DTLS1_3_VERSION, 0`, [capabilities.c L97](https://github.com/openssl/openssl/blob/5928f99e9cee5203f52081a040b64da6c4616662/providers/common/capabilities.c#L97)).
- Untested alternative: OpenSSL lets a provider register TLS groups through the TLS-GROUP capability ([provider-base(7)](https://docs.openssl.org/master/man7/provider-base/)), so a third-party provider could add 0x11EA to an unpatched 4.1.0.
I did not find a provider that ships it.

### S07 with OpenSSL 4.1.0 plus a backport

Local test on 2026-11-24, not part of this repository's harness:

1. [openssl-4.1.0.tar.gz](https://github.com/openssl/openssl/releases/download/openssl-4.1.0/openssl-4.1.0.tar.gz), SHA-256 50c17baf54cb008f6ce42d50deb4b28050a1aad711636cabd4b241c7e90cc2fd as pinned in implementations/openssl/build.sh.
2. The diff of commit 108ced2 without its CHANGES.md hunk (17 files, +1241 -954) applies to 4.1.0 without conflicts.
3. Built with `no-shared no-docs no-tests`; `openssl list -tls-groups` then lists MLKEM512X25519 and SecP256r1MLKEM512.
4. `s_server -dtls1_3 -groups MLKEM512X25519` against `s_client -dtls1_3 -groups MLKEM512X25519 -mtu 1232` completed the handshake and echoed data.

Observed with `-trace` (s_server turns on DTLS cookie exchange, [s_server.c L3382](https://github.com/openssl/openssl/blob/openssl-4.1.0/apps/s_server.c#L3382)):

| Message | Handshake length | Record length | UDP payload |
|---|---|---|---|
| CH1 (key share 4586, 832 bytes) | 1013 | 1025 | 1038 |
| HRR (cookie extension 122 bytes, no key_share) | 172 | 184 | 197 |
| CH2 (key share and cookie) | 1139 | 1151 | 1164 |

Both ClientHellos fit in one datagram at PMTU 1280 (limit 1232), as S07 expects.
These ClientHellos carry s_client's defaults: SNI, a long signature_algorithms list, no ALPN and no use_srtp.
So this is a first data point for the TODO item on realistic extensions, not an answer to it.

### wolfSSL

- `WOLFSSL_X25519MLKEM512 = 12214` (0x2FB6) and `WOLFSSL_SECP256R1MLKEM512 = 12107` are labelled "Taken from OQS's openssl provider" ([ssl.h L5006-L5018](https://github.com/wolfSSL/wolfssl/blob/v5.9.4-stable/wolfssl/ssl.h#L5006-L5018); master [ssl.h L5224](https://github.com/wolfSSL/wolfssl/blob/d31d62514e182ed7af9c488c584032dcb446e8de/wolfssl/ssl.h#L5224)).
- The hybrid mapping is `{WOLFSSL_X25519MLKEM512, WOLFSSL_ECC_X25519, WOLFSSL_ML_KEM_512, 1}`, i.e. ML-KEM first ([tls.c L8994](https://github.com/wolfSSL/wolfssl/blob/v5.9.4-stable/src/tls.c#L8994)), which is the component order of the IANA group.
- It is only compiled with `--enable-extra-pqc-hybrids`, which requires `--enable-experimental` and ML-KEM ([configure.ac L8556-L8565](https://github.com/wolfSSL/wolfssl/blob/v5.9.4-stable/configure.ac#L8556-L8565)).
wolfSSL's own DTLS 1.3 test uses it ([test-dtls13-pq-hybrid-extra.conf L17](https://github.com/wolfSSL/wolfssl/blob/v5.9.4-stable/tests/test-dtls13-pq-hybrid-extra.conf#L17)).
- No flag maps it to 4586, and I found no wolfSSL issue or PR for draft-rosomakho-tls-ecdhe-mlkem512 ([search](https://github.com/wolfSSL/wolfssl/pulls?q=mlkem512)).
- So wolfSSL cannot run S07 without a source patch; changing the code point of X25519MLKEM512 would probably be enough, since the component order already matches (untested).
A wolfSSL build with 0x2FB6 would not interoperate with OpenSSL's 0x11EA.

## mbedTLS 4.3.0

Sources in this section checked 2026-11-24.

### DTLS 1.3 is absent upstream

- [ssl_tls.c L1142 (v4.3.0)](https://github.com/Mbed-TLS/mbedtls/blob/v4.3.0/library/ssl_tls.c#L1142): a TLS 1.3-only configuration with datagram transport fails with "DTLS 1.3 is not yet supported." (`MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE`).
- [ssl_tls.c L1161](https://github.com/Mbed-TLS/mbedtls/blob/v4.3.0/library/ssl_tls.c#L1161): a 1.2 + 1.3 datagram configuration fails with "DTLS not yet supported in Hybrid TLS 1.3 + TLS 1.2".
- The same checks are on development ([ssl_tls.c L1142 at 0e2cc5f](https://github.com/Mbed-TLS/mbedtls/blob/0e2cc5fdac71ffbddb4b463189b042f8d7a5cf35/library/ssl_tls.c#L1142)).
- The feature request [#10982 "Support for DTLS 1.3"](https://github.com/Mbed-TLS/mbedtls/issues/10982) is open with no maintainer reply (created 2026-10-02).

### TLS 1.3 HRR cookie handling

- Client: `ssl_tls13_parse_cookie_ext` stores the cookie from an HRR ([ssl_tls13_client.c L535](https://github.com/Mbed-TLS/mbedtls/blob/v4.3.0/library/ssl_tls13_client.c#L535), called from [L1764](https://github.com/Mbed-TLS/mbedtls/blob/v4.3.0/library/ssl_tls13_client.c#L1764)).
CH2 writes it back ("Echo the cookie if the server provided one in its preceding HelloRetryRequest", [L1160-L1163](https://github.com/Mbed-TLS/mbedtls/blob/v4.3.0/library/ssl_tls13_client.c#L1160-L1163)), as RFC 9846 Section 4.3.2 requires.
- Server: there is no cookie writer in [ssl_tls13_server.c](https://github.com/Mbed-TLS/mbedtls/blob/v4.3.0/library/ssl_tls13_server.c); cookies appear only in comments ([L1283](https://github.com/Mbed-TLS/mbedtls/blob/v4.3.0/library/ssl_tls13_server.c#L1283), [L2362](https://github.com/Mbed-TLS/mbedtls/blob/v4.3.0/library/ssl_tls13_server.c#L2362)).
So an mbedTLS server sends HRR only for a key share and never for address validation.
- T01 should confirm the client behaviour on the wire against an OpenSSL or wolfSSL TLS 1.3 server that sends a cookie.

### ML-KEM hybrids

- mbedTLS 4.3.0 and development define no ML-KEM named groups; the group list in [ssl.h](https://github.com/Mbed-TLS/mbedtls/blob/v4.3.0/include/mbedtls/ssl.h) has only ECDHE and FFDHE groups.
- TF-PSA-Crypto, which provides the crypto since mbedTLS 4.0, has no ML-KEM in [v1.3.0](https://github.com/Mbed-TLS/TF-PSA-Crypto/tree/v1.3.0) or on development [50cce24](https://github.com/Mbed-TLS/TF-PSA-Crypto/tree/50cce24d22ddad007c838f20e4515e625da9192d) (no match for "mlkem" or "ML-KEM" in either tree).
- A maintainer wrote on 2026-05-25 that they are integrating mldsa-native first and mlkem-native after it, and on 2026-08-04 that they would not work on the ML-DSA API layer in Q3 2026 ([#9803](https://github.com/Mbed-TLS/mbedtls/issues/9803)).

## DTLS 1.3 bis: issues #313 and #333, CH1 fragmentation

Sources in this section checked 2026-11-24.

### Issues and PRs

- [#313 "Implementations"](https://github.com/tlswg/dtls13-spec/issues/313) is open (created 2025-03-03, last comment 2026-07-23).
Firefox (Anna Weine) expressed interest on 2025-08-11.
On 2026-07-23 the discussion moved implementation lists to tlswg.org: Sean Turner pointed to the [tlswg-wiki IMPLEMENTATIONS.md](https://github.com/tlswg/tlswg-wiki/blob/main/IMPLEMENTATIONS.md), which still lists only TLS 1.3 implementations and has no DTLS section.
- [#333 "fragmented initial ClientHello vs. stateless cookie exchange"](https://github.com/tlswg/dtls13-spec/issues/333) is open with no comments (created 2026-11-01).
Its body proposes to "work on that as a separate extension and not to hold up rfc9147bis".
- [PR #334 "Initial text about initial handshake message fragmentation"](https://github.com/tlswg/dtls13-spec/pull/334) was opened on 2026-11-01 and closed unmerged on 2026-11-18, without comments.
It proposed that servers MUST process a fragmented CH1 with a bounded reassembly cache, that clients SHOULD put the cookie first in CH2, and an empty client_shares fallback.

### Working group direction

- At IETF 127 "The room agrees to not do FAAT and to try to fix things in 9147bis"; David Schinazi: "do this in 9147bis, nothing is waiting on this doc" ([minutes](https://notes.ietf.org/notes-ietf-127-tls)).
This reverses #333's proposal of a separate extension.
- Eric Rescorla earlier wrote "I don't think that there is a complete server-side only fix" ([2026-11-01](https://mailarchive.ietf.org/arch/msg/tls/acaB45Ra2W65Qz73LGA5B9uiAys/)).
- Martin Thomson suggested an approach like QUIC Retry ([2026-11-04](https://mailarchive.ietf.org/arch/msg/tls/muCrAyVaWCYLWbbsr3QpsuivydU/)).
- Hannes Tschofenig listed 8 options with CH1 sizes: an ML-KEM-512 hybrid CH1 of 1019 bytes fits, X25519MLKEM768 at 1403 bytes does not; a wolfSSL prototype holds about 3 KB of state per spoofed fragment ([2026-11-17](https://mailarchive.ietf.org/arch/msg/tls/VDJhDdMRN7No-VgxxvOX5iqJNDw/)).
- Rescorla prefers a full CH1 plus a server-triggered stateless check and notes "The tricky part here seems like where we stuff the indicator in the CH1." ([2026-11-17](https://mailarchive.ietf.org/arch/msg/tls/-kX-27PjmIfIyjxiFqxBDZwLrWY/)).
- Valery Smyslov found no requirement in RFC 9846, RFC 9147 or rfc9147bis that the cookie be in the first fragment, so a server cannot tell CH1 from CH2 without reassembly ([2026-11-18](https://mailarchive.ietf.org/arch/msg/tls/j8qd0Boe5erCYkQgUKQAJIyTF_s/)).
- The chairs (Deirdre Connolly) are "Not sending DTLS 1.3 bis to the FATT (out of scope)" ([2026-11-19](https://mailarchive.ietf.org/arch/msg/tls/mMxNK8QzGd1eLLI_yyxOkXCqCZI/)), and Rescorla describes 9147-bis as "largely to address deployment and clarity issues" ([2026-11-19](https://mailarchive.ietf.org/arch/msg/tls/qIVQPVLx-42Mdw9UU0IuZ0NNI7o/)).

### What draft -02 says

- The newest draft is [draft-ietf-tls-rfc9147bis-02](https://datatracker.ietf.org/doc/html/draft-ietf-tls-rfc9147bis-02) (2026-07-06); the [editor's copy](https://github.com/tlswg/dtls13-spec) has had no commit since 2026-07-07 (PR #330).
- Section 5.1 (Denial-of-Service Countermeasures) still only says the server MAY answer a ClientHello with a stateless-cookie HRR and the client MUST resend with the cookie.
- Section 5.5 (Handshake Message Fragmentation and Reassembly) still says a receiver MUST process a fragment of the next expected message, by buffering or in-order processing, and MUST handle overlapping fragments.
- Neither section, nor any other, addresses a fragmented CH1, its interaction with the cookie exchange, or PQ key share sizes; both are unchanged in substance from [RFC 9147](https://www.rfc-editor.org/rfc/rfc9147).
- Stale cross-reference: draft -02 cites "Section 4.2.2" of [TLS13] for the cookie (twice in Section 5.1), but TLS13 is now [RFC 9846](https://www.rfc-editor.org/rfc/rfc9846), where 4.2.2 is Client Hello and Cookie is Section 4.3.2.

## Recommendations

- GnuTLS: stay out of the matrix until DTLS 1.3 is merged upstream.
- S07: only OpenSSL can run it, either as 4.1.0 plus a backport patch of 108ced2 or as a pinned master commit; every other library reports unsupported.
- wolfSSL S07: needs a code point patch, which would test a modified wolfSSL rather than wolfSSL.
- mbedTLS: keep it to T01; its client echoes the cookie per source, to be confirmed on the wire.
- pion/dtls v4 is a new DTLS 1.3 implementation with X25519MLKEM768 and is a candidate for the matrix.
Its clients lead with X25519 because "some DTLS servers drop a fragmented first ClientHello" ([options.go L763-L771](https://github.com/pion/dtls/blob/v4.0.2/options.go#L763-L771)).

## Snapshots

| Repository | Ref | Commit |
|---|---|---|
| openssl/openssl | openssl-4.1.0 | ad2c6be0cf142e3d8ce78fcdb25070674d28130f |
| openssl/openssl | master (4.2.0-dev) | 5928f99e9cee5203f52081a040b64da6c4616662 |
| wolfSSL/wolfssl | v5.9.4-stable | 25ada78b639375fcb252be6fef0f9ad568d46ce2 |
| wolfSSL/wolfssl | master | d31d62514e182ed7af9c488c584032dcb446e8de |
| google/boringssl | main | 5ec099107553142e9cb34dfe52f3c5bb42c9b7fb |
| nss-dev/nss | NSS_3_134_RTM | 72611a02c4348e03bccc684c32990b8c93497648 |
| nss-dev/nss | master (3.135 Beta) | bf1a5ff1936567bb3c5589ff4723c23f15a82081 |
| Mbed-TLS/mbedtls | v4.3.0 | 7ad5d99db40801b48b4e2b713d567d40d34ff7c8 |
| Mbed-TLS/mbedtls | development | 0e2cc5fdac71ffbddb4b463189b042f8d7a5cf35 |
| Mbed-TLS/TF-PSA-Crypto | v1.3.0 | 730be94fac5629b933673449e72a9a10b90093cd |
| Mbed-TLS/TF-PSA-Crypto | development | 50cce24d22ddad007c838f20e4515e625da9192d |
| gnutls/gnutls | master (3.8.14 merge) | 6542d6fc9e05a7fd5370da0832dbbc6bbd7a54db |
| gnutls/gnutls | wip/dtls13 | 92e0dc7d629294737179f3cb90ccd9feef167f14 |
| pion/dtls | v4.0.2 | tag, released 2026-11-12 |
| golang/go | master | ca94e2de875d2665297df109c80db5e8e94db3cc |
| rustls/rustls | main | e11f98090bee85e6cb2ca03b11819fd145668795 |
