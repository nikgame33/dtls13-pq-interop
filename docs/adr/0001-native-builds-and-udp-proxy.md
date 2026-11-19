# ADR 0001: Native pinned builds and a userspace UDP proxy

Status: accepted (2026-11-19)

## Context

We need per-datagram control over the path (PMTU limit, reordering, loss) and a record of every datagram.
The usual options are containers with network emulation (as in quic-interop-runner), Linux network namespaces with `tc netem`, or a userspace proxy.

## Decision

- Build each implementation natively from a pinned upstream version into `.build/<name>/`.
- Run client and server on loopback and route all traffic through a Python UDP proxy owned by the harness.
The proxy drops datagrams above the configured PMTU, can reorder or drop specific datagrams, and logs each one.

## Consequences

- Deterministic impairments: "drop the first fragment of CH1" is a rule on parsed records, not a probability.
- No root, container runtime or namespaces needed; runs the same locally and on CI runners.
- The proxy sees what the library actually sends, so oversize-datagram bugs show up as drops in the trace.
- Build reproducibility relies on pinning and checksums instead of container images.
Containers can be added later for CI caching without changing the adapter interface.
- Loopback has no real middleboxes; middlebox behaviour has to be modelled in the proxy if needed.

## Proxy semantics (PR #1)

- PMTU is converted to a UDP payload limit with a fixed 48-byte IPv6+UDP overhead, so PMTU 1280 allows 1232-byte datagrams.
- Rules run first and the PMTU check applies to every datagram the proxy sends, so a rule can split an oversize ClientHello into pieces that fit.
- The trace has one entry per datagram, timed when it leaves the proxy or is dropped; reordered datagrams appear as "delayed".
- A datagram a rule replaces appears as "replaced"; each datagram emitted instead has its own index and `origin` pointing to it.
- `SplitClientHello` renumbers every client epoch 0 record from n to K*n + i (piece i of K), so numbers stay unique and ordered for the server's replay window.
Server ACKs for epoch 0 are mapped back to the client's numbers, and a split record counts as acknowledged only when all its pieces are.
