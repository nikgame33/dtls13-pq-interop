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

## Proxy-split rows

The wolfSSL client never fragments CH1: if CH1 does not fit its MTU, it sends an empty `key_share` instead.
So S03, S04, S08 and S09 never show a server a fragmented CH1 from it.
Each scenario that expects a fragmented CH1 therefore also runs as `<ID>+split` ([ADR 0003](adr/0003-proxy-split-ch1-rows.md)).
Client `--mtu` and PMTU are 1500, so a full-share CH1 fits one datagram, and the proxy delivers an unfragmented CH1 as two fragments.
Server options, impairments and expectations are those of the base row, except that the client's CH1 fragmentation is not checked.
Every client runs these rows; clients that fragment CH1 themselves are the control.

| ID | Description | Expected outcome |
|---|---|---|
| S03+split | S03, client MTU and PMTU 1500, proxy splits CH1 in two | As S03; CH1 reaches the server in 2 fragments |
| S04+split | S04, client MTU and PMTU 1500, proxy splits CH1 in two | As S04; CH1 reaches the server in 2 fragments |
| S08+split | S08, client MTU and PMTU 1500, proxy splits CH1 in two | As S08; CH1 reaches the server in 2 fragments |
| S09+split | S09, client MTU and PMTU 1500, proxy splits CH1 in two | As S09; CH1 reaches the server in 2 fragments |

## Recorded per run

- Outcome: pass, fail (with alert / error), unsupported (adapter exit 2), timeout, error (harness or adapter protocol problem, not a library verdict).
- Datagram trace from the proxy: direction, size, timing and action per datagram.
Record and handshake headers are derived with `records.parse_datagram(d.payload)` on each trace entry.
- CH1/CH2 message size and fragment count as the client sent them, before any proxy rule.
A run fails if they contradict the scenario's CH1/CH2 fragmentation expectation.
- Path: PMTU, impairments, `split_ch1` (the proxy, not the client, split CH1), and `actions`: how many datagrams the proxy dropped, delayed or replaced, by reason (e.g. `replaced: split CH1 into 2 fragments`).
- Round trips to completion.
- Bytes sent by the server before address validation (amplification ratio vs. bytes received).
