# Adapter interface

Each implementation provides `implementations/<name>/build.sh` and an adapter executable `implementations/<name>/run`.
The harness only talks to the adapter, never to library-specific tools directly.
The rules here make adapters behave equivalently; ADR 0002 explains why.

## Build

`build.sh` fetches the pinned upstream source, verifies it (tag + commit hash or tarball checksum), and installs into `.build/<name>/`.
It must be idempotent and must not touch anything outside `.build/`.
As its last step it creates the marker file `.build/<name>/.built`; tests treat an implementation without the marker as unbuilt.
The first line of `.built` is the pinned version (e.g. `openssl 4.1.0`); further lines may list build flags.
The runner records that first line as the implementation version.
CI caches `.build/<name>/` keyed on all files in `implementations/<name>/`, falling back to a cache with the same `build.sh` and `*.patch` files.
So an adapter change restores the built library and `build.sh` only recompiles the adapter.

## Tests

Adapter tests for an implementation live in `tests/impl/test_<name>.py` and obtain it through the `require_impl("<name>")` fixture.
Locally they skip when the implementation is not built.
CI runs them per implementation with `DTLS_INTEROP_REQUIRE=<name>`, which turns a missing build into a failure.
The conformance suite in `tests/conformance/` checks every rule in this document against every built implementation and variant.

## Run

```
run --role=client|server
    --variant=NAME                       # both; "default" or a name from the variants file
    --host=HOST --port=PORT              # both; the server binds (0 = any free port), the client connects
    --groups=G1[,G2...]                  # both; preference order, IANA names
    --mtu=N|default                      # both; path MTU at the IP layer, see below
    --ca=FILE                            # both; the client verifies the server as "localhost"
    --key-share=GROUP|empty|default      # client only: what goes into CH1 key_share
    --validate=off|cookie                # server only: stateless HRR cookie for new peers
    --cert=FILE --key=FILE               # server only
```

Every option listed for a role is required; there are no implicit defaults.
The value `default` means "do not configure this, let the library decide", so library defaults are measured explicitly.
A missing, unknown, repeated or other-role option, or a malformed value, is a usage error (exit 64).
A `--key-share` group that is not in `--groups` counts as malformed.
The runner passes every option as `--opt=value`; adapters must accept that form and should also accept `--opt value`.

### Variants

A library code path the adapter can choose between is a variant, never an environment variable or a compile-time switch of the adapter.
`implementations/<name>/variants` lists the non-default variants, one per line as `ROLE NAME: one-sentence description`, where ROLE is `client`, `server` or `both`; the file is optional.
The matrix runs every variant as its own entry, named `<name>+<variant>` (e.g. `wolfssl+accept-tls13`), only in the roles it lists, and records the variant in each result.
An adapter accepts `--variant=default` in both roles and a listed variant only in its roles; anything else is a usage error.
Each implementation's README documents what every variant changes.

### Groups

`--groups` lists the groups the role supports, most preferred first.
For a client it is the supported_groups extension in that order.
A server selects the group as follows:

1. Among the client's key shares for groups in `--groups`, use the one ranked highest in `--groups` (ServerHello).
2. Otherwise send an HRR selecting the highest-ranked group in `--groups` that the client lists in supported_groups.
3. Otherwise fail the handshake.

An acceptable key share never triggers an HRR just to get a group the server ranks higher.

### Key share

`--key-share=GROUP` sends exactly one key share for GROUP, which must be in `--groups`.
`--key-share=empty` sends an empty key_share extension, so the server has to send an HRR.
`--key-share=default` leaves the choice to the library.
A library that cannot send what is asked exits 2.

### MTU

`--mtu=N` uses the same unit as the proxy's `pmtu`: the path MTU at the IP layer.
The adapter configures the library so that no UDP payload exceeds N - 48 bytes (IPv6 40 + UDP 8), e.g. 1232 bytes for N = 1280.
`--mtu=default` leaves the MTU unconfigured, so the library's own default applies.
Each implementation's README states how this maps to the library's MTU API.

### Lifecycle and teardown

1. Server: bind, print `ready` with the bound port, accept one connection.
The runner passes `--port=0`, so the port is never picked by one process and bound by another.
2. Client: complete the handshake, send `ping`, read `pong`, send close_notify, wait up to 2 s for the server's close_notify, print the result, exit.
3. Server: answer `ping` with `pong`, wait up to 2 s for the client's close_notify, send its own close_notify, print the result, exit.

The client's verdict is final once it has read `pong`; errors during teardown go to stderr and never change the result.
Adapters impose no handshake timeout of their own below 60 s; the runner owns timeouts.
Adapters stay in the process group the runner starts them in and never daemonize.
The runner kills the group at the case timeout, and the server 5 s after the client has exited.

PSK resumption (scenario S10) and a TLS-over-TCP mode (scenario T01) are not defined yet.

## Output protocol

stdout carries only JSON lines; everything else goes to stderr and is kept in the run log.

- Server, once its socket is bound and it accepts datagrams: `{"event": "ready", "port": 40123}` with the port actually bound.
The runner starts the client only after this line.
- Both roles, last line before exit:

```json
{"event": "result", "ok": true, "version": "DTLSv1.3", "group": "X25519MLKEM768", "hrr": true, "hrr_cookie": true, "hrr_group": false, "error": null}
```

| Field | Meaning |
|---|---|
| `ok` | Handshake and echo succeeded; must match exit code 0 |
| `version` | Negotiated protocol version, e.g. `DTLSv1.3` |
| `group` | Negotiated group, IANA name |
| `hrr` | A HelloRetryRequest was sent (server) or received (client) |
| `hrr_cookie` | That HRR carried a cookie extension |
| `hrr_group` | That HRR carried a key_share selected_group, i.e. asked for a new key share |
| `error` | Short error string from the library on failure |

Fields the adapter cannot determine are `null`, never guessed; `hrr_cookie` and `hrr_group` are `false` when `hrr` is `false`.
Before the handshake has started (usage error, unsupported configuration) `version`, `group`, `hrr`, `hrr_cookie` and `hrr_group` are `null`.
Every exit, including exit 2 and 64, prints a result line with `ok` false and `error` set; the runner falls back to the last stderr line if it is missing.
An adapter may get these values from the library API or by parsing the plaintext handshake records it sends and receives.

## Exit codes

| Code | Meaning | Runner outcome |
|---|---|---|
| 0 | Handshake and echo succeeded | pass (if expectations hold) |
| 1 | Failure (handshake error, alert, wrong echo) | fail |
| 2 | Configuration not supported by this implementation | unsupported |
| 64 | Usage error (see Run: missing, unknown, repeated or other-role option, malformed value, variant not listed for the role) | error |

## System packages

If the build needs Debian/Ubuntu packages beyond a stock GitHub `ubuntu-24.04` runner, list them one per line in `implementations/<name>/apt-packages.txt`; CI installs them before `build.sh`.
