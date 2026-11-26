# ADR 0004: PSK resumption and a TLS transport in the adapter contract

Status: proposed (2026-11-24)

## Context

Scenario S10 needs a second connection that resumes the first one with a PSK, after a cookie HRR at PMTU 1280.
Scenario T01 needs TLS 1.3 over TCP, to see whether a client echoes the HRR cookie in its second ClientHello (RFC 9846 sec 4.2.4, 4.3.2), including implementations without DTLS 1.3 such as mbedTLS.
Until now the contract (docs/shim-interface.md) knew one connection over UDP, and the runner refused both scenarios.
The existing rules stay: no implicit defaults, exit codes 0/1/2/64, JSON result lines, the runner owns timeouts.

## Decision

### Two required options

`--transport=dtls|tls` and `--resume=off|ticket` are required in both roles, and the runner always passes them.
A required option keeps "no implicit defaults" true: an adapter that does not know about TLS or resumption fails with a usage error instead of silently running DTLS with one connection.

### Resumption inside one adapter run

With `--resume=ticket` one client process runs two connections, and one server process serves both from the same library context.
The alternative, two runner-driven client processes that hand a serialized session over a file, would need a session export format per library and a second contract for passing it; libraries do not agree on one, and the server would still have to keep its ticket keys across connections.
Within one process each library uses its own session API (`SSL_get1_session`/`SSL_set_session`, `wolfSSL_get1_session`/`wolfSSL_set_session`).
Connection 2 uses a new socket, so with DTLS it comes from a new source port: the server sees a new peer, so `--validate=cookie` sends a cookie HRR again and the client has to compute its PSK binder over the HRR transcript (RFC 9846 sec 4.3.11.2), which is the path S10 is about.
A client that got no usable NewSessionTicket (RFC 9846 sec 4.7.1) in connection 1 exits 1, because S10 cannot make its point without a ticket.

### Result line

The result line gets one field, `resumed`: the server accepted the PSK.
It describes the last connection attempted, and errors are prefixed `connection N: `.
One result line per run keeps the runner's parser and the exit code rule unchanged; connection 1 of S10 is the S04 handshake, which S04 already measures.
A full-handshake fallback is reported as `ok: true, resumed: false` and judged by the runner against `Expected.resumed`, so the adapter reports and the runner decides, as for every other field.

### TLS over TCP, through a TCP relay

`--transport=tls` runs TLS 1.3 over a plain TCP connection, and `--mtu` must be `default` there, since a byte stream has no datagram size.
The runner always puts a userspace TCP relay (`TcpProxy`) between client and server for TLS cases.
It accepts each client connection, opens its own connection to the server, copies bytes in both directions, passes FIN on as FIN, and records every chunk with flow number, direction and time in `trace.jsonl`.
The trace analysis (`hello_trace`) reassembles each direction's byte stream, parses the plaintext handshake records (RFC 9846 sec 5.1) up to the first encrypted record, and compares the HRR cookie with the cookie extension of the second ClientHello.
This is the simplest robust way to see the bytes on the wire: it needs no privileges, no packet capture and no TCP reassembly from packets, and it is the same seam as the UDP proxy (ADR 0001).
Alternatives were packet capture on loopback (needs privileges, TCP reassembly, and makes CI fragile) and adapter self-reporting (the adapter would grade its own library, and a client cannot know whether its CH2 is what the server needed).
The relay has no impairments; a TLS scenario with impairments is an error.

The UDP proxy also changed: each client source address is now its own flow with its own upstream socket, so connection 2 of S10 reaches the server from a new port, as it would without the proxy.
The trace analysis reads the same cookie verdict from UDP traces, per flow; `cookie_echoed` in result.json is false if any flow failed to echo, and null without a trace showing an HRR cookie and a CH2.

### Declared transports

`implementations/<name>/transports` lists the transports an adapter implements; without the file it is `dtls` only.
The runner records `unsupported` without starting any process when an entry does not declare the scenario's transport, and `dtls-interop list` shows the declaration.
A TLS-only implementation such as mbedTLS therefore joins with a `transports` file that lists `tls` and runs only T01, while every DTLS case it is part of shows as unsupported rather than failed.
The adapter still exits 2 for a transport it does not implement, so a wrong declaration fails safely, and DTLS-only variants (`openssl+accept`, `wolfssl+accept-tls13`) do the same for `tls`.
A per-variant declaration was not added: two variants is not enough to justify a second file format.

## Consequences

- Adapters in development (BoringSSL, NSS) must accept `--transport` and `--resume` and print `resumed`; until they do, every case they take part in is a usage error.
- wolfSSL is now built with `--enable-session-ticket`, so its servers send a NewSessionTicket in every scenario and its clients add psk_key_exchange_modes to every ClientHello, which changes CH1 sizes by a few bytes.
- T01 runs with `--mtu=default` while its path PMTU stays 1500 for the record; the TCP relay does not enforce it.
- `result.json` gains `cookie_echoed`, so the result schema version is 3 (ADR 0003 made it 2).
- With two connections in one trace, `ch1_size`/`ch2_size` and their fragment counts describe the last connection, like the result lines.
