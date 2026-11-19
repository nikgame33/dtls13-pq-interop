# Test matrix

Every scenario runs for every (client, server) pair, including same-implementation pairs as a sanity check.

## Implementations

| Name | Version | DTLS 1.3 | Notes |
|---|---|---|---|
| openssl | 4.1.0 (2026-10-23) | yes | Listener API validates addresses by default (HRR cookie) |
| wolfssl | v5.9.4-stable | yes | Rejects fragmented CH1 by default (reported) |
| boringssl | pinned commit (TBD) | yes | No releases; pin a commit |
| nss | pinned release (TBD) | yes | Used by Firefox / WebRTC |
| mbedtls | 4.3.0 | no (upstream) | TLS 1.3 HRR scenarios only |

## Dimensions

- **Group**: X25519, X25519MLKEM768, MLKEM512X25519, SecP256r1MLKEM768.
- **Key-share strategy**: full share for the preferred group; empty `key_share`; wrong guess (client shares X25519, server requires a hybrid).
- **Server address validation**: off; stateless HRR cookie on every new peer.
- **Path**: PMTU 1500; PMTU 1280; CH fragments reordered; first CH fragment lost once.

## Scenarios

| ID | Description | Expected outcome |
|---|---|---|
| S01 | X25519, full share, PMTU 1500, no validation | Handshake succeeds, 1 RTT |
| S02 | X25519MLKEM768, full share, PMTU 1500 | Succeeds, CH1 in one datagram |
| S03 | X25519MLKEM768, full share, PMTU 1280 | Succeeds with fragmented CH1 |
| S04 | S03 + server stateless HRR cookie | Succeeds; record server state before validation |
| S05 | Empty `key_share` + HRR (X25519MLKEM768) | Succeeds, 2 RTT |
| S06 | Wrong guess (X25519 share, server requires hybrid) | Succeeds via HRR |
| S07 | MLKEM512X25519, full share, PMTU 1280, cookie | Succeeds, CH1 and CH2 unfragmented |
| S08 | S04 with CH1 fragments reordered | Succeeds |
| S09 | S04 with first CH1 fragment lost once | Succeeds after retransmission |
| S10 | PSK resumption after HRR at PMTU 1280 | Succeeds |
| T01 | TLS 1.3 HRR cookie echo (incl. mbedtls) | Cookie echoed in CH2 |

## Recorded per run

- Outcome: pass, fail (with alert / error), unsupported (adapter exit 2), timeout, error (harness or adapter protocol problem, not a library verdict).
- Datagram trace from the proxy: direction, size, timing and action per datagram.
Record and handshake headers are derived with `records.parse_datagram(d.payload)` on each trace entry.
- CH1/CH2 total size and fragment count.
- Round trips to completion.
- Bytes sent by the server before address validation (amplification ratio vs. bytes received).
