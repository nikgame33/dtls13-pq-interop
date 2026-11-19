# Adapter interface (draft)

Each implementation provides `implementations/<name>/build.sh` and an adapter executable `implementations/<name>/run`.
The harness only talks to the adapter, never to library-specific tools directly.

## Build

`build.sh` fetches the pinned upstream source, verifies it (tag + commit hash or tarball checksum), and installs into `.build/<name>/`.
It must be idempotent and must not touch anything outside `.build/`.
As its last step it creates the marker file `.build/<name>/.built`; tests treat an implementation without the marker as unbuilt.
CI caches `.build/<name>/` keyed on `build.sh` and any `*.patch` in the implementation directory.

## Tests

Adapter tests for an implementation live in `tests/impl/test_<name>.py` and obtain it through the `require_impl("<name>")` fixture.
Locally they skip when the implementation is not built.
CI runs them per implementation with `DTLS_INTEROP_REQUIRE=<name>`, which turns a missing build into a failure.

## Run

```
run --role client|server
    --host HOST --port PORT
    --groups G1[,G2...]            # preference order, IANA names
    --key-share GROUP|empty         # client only: what goes into CH1 key_share
    --mtu N                         # DTLS record/fragment size the library should use
    --validate off|cookie           # server only: stateless HRR cookie for new peers
    --cert FILE --key FILE --ca FILE
    [--psk-in FILE] [--psk-out FILE]
```

Client behaviour: complete the handshake, send `ping`, expect `pong`, exit.
Server behaviour: accept one connection, answer `ping` with `pong`, exit.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Handshake and echo succeeded |
| 1 | Failure (handshake error, alert, wrong echo) |
| 2 | Configuration not supported by this implementation (reported as "unsupported", not "fail") |

The adapter prints one JSON line on stdout at exit with the negotiated version, group, whether HRR occurred, and any error string.
Everything else goes to stderr and is kept in the run log.

Open points are tracked in TODO.md.
