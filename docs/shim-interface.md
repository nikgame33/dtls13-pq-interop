# Adapter interface

Each implementation provides `implementations/<name>/build.sh` and an adapter executable `implementations/<name>/run`.
The harness only talks to the adapter, never to library-specific tools directly.

## Build

`build.sh` fetches the pinned upstream source, verifies it (tag + commit hash or tarball checksum), and installs into `.build/<name>/`.
It must be idempotent and must not touch anything outside `.build/`.
As its last step it creates the marker file `.build/<name>/.built`; tests treat an implementation without the marker as unbuilt.
The first line of `.built` is the pinned version (e.g. `openssl 4.1.0`); further lines may list build flags.
The runner records that first line as the implementation version.
CI caches `.build/<name>/` keyed on `build.sh` and any `*.patch` in the implementation directory.

## Tests

Adapter tests for an implementation live in `tests/impl/test_<name>.py` and obtain it through the `require_impl("<name>")` fixture.
Locally they skip when the implementation is not built.
CI runs them per implementation with `DTLS_INTEROP_REQUIRE=<name>`, which turns a missing build into a failure.

## Run

```
run --role=client|server
    --host=HOST --port=PORT
    --groups=G1[,G2...]             # preference order, IANA names
    --key-share=GROUP|empty         # client only: what goes into CH1 key_share
    --mtu=N                         # path MTU at the IP layer, see below
    --validate=off|cookie           # server only: stateless HRR cookie for new peers
    --cert=FILE --key=FILE          # server only
    --ca=FILE                       # both; the client verifies the server as "localhost"
```

The runner passes every option as `--opt=value`; adapters must accept that form and should also accept `--opt value`.

`--mtu N` uses the same unit as the proxy's `pmtu`: the path MTU at the IP layer.
The adapter configures the library so that no UDP payload exceeds N - 48 bytes (IPv6 40 + UDP 8), e.g. 1232 bytes for N = 1280.
Each implementation's README states how this maps to the library's MTU API.

PSK resumption (`--psk-in`/`--psk-out`, scenario S10) and a TLS-over-TCP mode (scenario T01) are not defined yet.

Client behaviour: complete the handshake, send `ping`, expect `pong`, exit.
Server behaviour: accept one connection, answer `ping` with `pong`, exit.

Adapters stay in the process group the runner starts them in and never daemonize.
The runner kills the group at the case timeout, and the server 5 s after the client has exited.

## Output protocol

stdout carries only JSON lines; everything else goes to stderr and is kept in the run log.

- Server, once its socket is bound and it accepts datagrams: `{"event": "ready"}`.
The runner starts the client only after this line.
- Both roles, last line before exit:

```json
{"event": "result", "ok": true, "version": "DTLSv1.3", "group": "X25519MLKEM768", "hrr": false, "error": null}
```

`version` and `group` use IANA names; `hrr` says whether a HelloRetryRequest happened; `error` is a short string from the library on failure.
Fields the library cannot report are `null`, never guessed.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Handshake and echo succeeded |
| 1 | Failure (handshake error, alert, wrong echo) |
| 2 | Configuration not supported by this implementation (reported as "unsupported", not "fail") |

## System packages

If the build needs Debian/Ubuntu packages beyond a stock GitHub `ubuntu-24.04` runner, list them one per line in `implementations/<name>/apt-packages.txt`; CI installs them before `build.sh`.
