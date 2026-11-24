# ADR 0003: Proxy-split CH1 rows for clients that never fragment CH1

Status: accepted (2026-11-24)

## Context

S03, S04, S08 and S09 test how a server handles a fragmented first ClientHello (CH1) carrying an X25519MLKEM768 share.
The wolfSSL 5.9.4 client never fragments CH1 (RFC 9147 sec 5.5 would allow it).
If CH1 does not fit its MTU it sends an empty `key_share` instead (`src/tls13.c`, "Sending empty key share so we don't fragment CH1").
At `--mtu=1280` its CH1 shrinks from 1378 to 158 bytes of message, so these rows only exercise the HRR path for wolfSSL clients, never server reassembly.

The proxy rule `SplitClientHello` (ADR 0001) can deliver an unfragmented CH1 as several fragments.
The matrix needs a way to use it that no reader can mistake for the client fragmenting CH1.

Two facts constrain the options:

- The client only sends its full share if CH1 fits its own MTU, so the client `--mtu` must be raised (a 1403-byte datagram needs at least 1451).
- With a raised client MTU on a 1280 path, the client's other datagrams no longer fit the path.
Measured: after the cookie HRR, wolfSSL fragments its 1524-byte CH2 at its own 1452-byte limit, and the proxy drops the first fragment for exceeding the PMTU, so S04 never completes.

## Options

1. Apply the split silently for wolfSSL clients in the existing rows.
Rejected: the result would claim a fragmented CH1 the client never sent, and it is a hidden switch of the kind ADR 0002 rules out.
2. A run-level CLI flag that adds the split to the selected scenarios.
Rejected: one scenario ID would stand for two configurations, and the results tree, keyed by scenario, could not tell them apart.
3. Keep the base row's options and split whatever CH1 the client sends.
Rejected: wolfSSL's CH1 at MTU 1280 has an empty share, so the case still tests the HRR path and fails the base expectations.
4. Client MTU 1500 on a 1280 path, with the proxy splitting every client ClientHello record, CH2 included.
Rejected: the proxy would rewrite more of the client's behaviour, and a client that assumes 1500 on a 1280 path is not a configuration anyone deploys.
5. Separate matrix rows with the client MTU and the path PMTU at 1500 and only CH1 split.

## Decision

Option 5.
Every scenario that expects a fragmented CH1 gets a derived row `<ID>+split` (today S03+split, S04+split, S08+split, S09+split), defined in `scenarios.py` and listed in docs/test-matrix.md.
A derived row differs from its base row only in:

- client `--mtu` and path PMTU 1500, so a full-share CH1 fits one datagram and nothing the client sends is dropped by the path;
- `PathConditions.split_ch1 = 2`: the proxy splits an unfragmented CH1 into two fragments, before any impairment rule, so S08+split reorders and S09+split drops the proxy's fragments;
- the client's CH1 fragmentation is not checked; every other expectation is the base row's.

The server options stay those of the base row, so the server's flights are the same as in the base row.
The rows run for every client; a client that fragments CH1 itself (OpenSSL) has its CH1 split the same way and acts as the control.

Every result states what the proxy did, separately from what the client did:

- `path.split_ch1` records the path option, and `path.actions` counts each datagram the proxy did not simply forward, e.g. `"replaced: split CH1 into 2 fragments": 1`.
- `ch1_size`, `ch1_fragments`, `ch2_size` and `ch2_fragments` describe the ClientHellos as the client sent them, before any proxy rule; for a wolfSSL client in a split row `ch1_fragments` is 1.
- The result schema version is 2.

## Consequences

- A split row says how a server handles a fragmented CH1 with this client's content and retransmission behaviour, not how the client behaves at PMTU 1280; the base row keeps answering that.
- Client-to-server datagrams in split rows can be up to 1452 bytes, so they do not test the server's receive path at 1280.
- Matrix size grows by four rows per client and server pair.
- A future client that fragments CH1 even at MTU 1500 is left alone by the rule; its row then tests its own fragments, and `path.actions` shows no split.

First results (OpenSSL 4.1.0, wolfSSL 5.9.4, 2026-11-24):

- OpenSSL servers (listener and `accept`) pass all four split rows with a wolfSSL client.
- wolfSSL servers drop the split CH1 exactly as they drop OpenSSL's fragmented CH1: `default` in all four rows, `accept-tls13` with the cookie (S04, S08, S09); `accept-tls13` passes S03+split.
