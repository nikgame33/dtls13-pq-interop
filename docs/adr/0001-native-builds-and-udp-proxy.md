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
