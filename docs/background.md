# Background

## The problem

An X25519MLKEM768 key share is 1216 bytes.
With the other ClientHello extensions, the first ClientHello (CH1) exceeds one datagram at a 1280-byte PMTU and DTLS fragments it.

A DTLS 1.3 server that wants to stay stateless until the client's address is validated sends a HelloRetryRequest (HRR) with a cookie.
The cookie must bind the hash of the complete CH1, so the server has to reassemble CH1 first, which means holding state for an unvalidated peer.
After the HRR, CH2 carries the cookie but may be fragmented too, and the cookie extension is not required to be in the first fragment.

Implementations resolve this differently, and their defaults do not interoperate.

## Known findings to reproduce

From the tls@ietf.org thread "Deployability of DTLS 1.3, HRR, and MLKEM512X25519" (Aug to Nov 2026):

- wolfSSL rejects a fragmented initial ClientHello by default; NSS and BoringSSL clients offering a PQ share cannot connect to it.
- BoringSSL and wolfSSL do not interoperate in default DTLS 1.3 configurations.
- BoringSSL (DTLS 1.3) does not handle an empty `key_share` that should trigger HRR.
- wolfSSL and mbedTLS do not echo the HRR cookie (TLS 1.3).
- OpenSSL needed a fix for a wolfSSL PSK interaction.
- NSS interoperates with BoringSSL and wolfSSL except for the wolfSSL fragmented-CH case.

These are claims from the list, not yet reproduced by us.
Library versions and configurations were not published.

## Current WG direction

- IETF 127 (16 Nov 2026): the room agreed to try to fix this inside RFC 9147bis (record-layer approach discussed), not as a separate extension.
- Tracked in https://github.com/tlswg/dtls13-spec/issues/333 ; implementation status in https://github.com/tlswg/dtls13-spec/issues/313 .

## Relevant group code points

| Code point | Name | Status |
|---|---|---|
| 0x001D | X25519 | baseline |
| 4588 (0x11EC) | X25519MLKEM768 | RFC 10024, Recommended=Y |
| 4586 (0x11EA) | MLKEM512X25519 | draft-rosomakho-tls-ecdhe-mlkem512 |
| 4587 (0x11EB) | SecP256r1MLKEM768 | RFC 10024 |
| 513 (0x0201) | MLKEM768 | draft-ietf-tls-mlkem, Recommended=N |

## References

- Thread start: https://mailarchive.ietf.org/arch/browse/tls/?index=j8qd0Boe5erCYkQgUKQAJIyTF_s
- Rescorla's analysis: https://mailarchive.ietf.org/arch/msg/tls/acaB45Ra2W65Qz73LGA5B9uiAys/
- Tschofenig's option list: https://mailarchive.ietf.org/arch/msg/tls/VDJhDdMRN7No-VgxxvOX5iqJNDw/
- IETF 127 TLS notes: https://notes.ietf.org/notes-ietf-127-tls
- RFC 9147 (DTLS 1.3), RFC 9846 (TLS 1.3 bis), RFC 10024 (ECDHE-MLKEM)
