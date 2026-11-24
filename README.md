# dtls13-pq-interop

Reproducible interoperability matrix for DTLS 1.3 with post-quantum key shares.

The TLS WG is reworking RFC 9147 (draft-ietf-tls-rfc9147bis), partly because a ClientHello carrying an ML-KEM key share no longer fits into one datagram.
Interop evidence so far comes from a private test suite whose configurations are not public.
This project produces an open, scripted, re-runnable matrix so that implementers and the WG can reproduce every result.

See [docs/background.md](docs/background.md) for the problem and the mailing-list context.

## What it tests

Every client implementation against every server implementation, across:

- key-exchange groups (X25519, X25519MLKEM768, MLKEM512X25519, ...),
- key-share strategy (full share, empty `key_share`, wrong guess forcing HelloRetryRequest),
- server address validation (none, stateless HRR cookie),
- path conditions (PMTU 1500 / 1280, fragment reordering, loss).

The full matrix and scenario IDs are in [docs/test-matrix.md](docs/test-matrix.md).

## How it works

- Each implementation is built natively from a pinned upstream version (`implementations/<name>/`).
- Each implementation exposes one adapter with a uniform command line ([docs/shim-interface.md](docs/shim-interface.md)).
- A Python harness starts server and client and routes every datagram through a userspace UDP proxy.
The proxy enforces the PMTU, reorders or drops datagrams, and records each datagram for analysis.
No root, containers or network namespaces are needed ([ADR 0001](docs/adr/0001-native-builds-and-udp-proxy.md)).

## Status

Harness core (proxy, record parser, runner, results) and the OpenSSL 4.1.0 and wolfSSL 5.9.4 adapters work.
Work items are tracked in [TODO.md](TODO.md).

## Development

```sh
uv sync
uv run ruff check
uv run ruff format --check
uv run pytest
```
