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
It discovers implementations and variants itself, so a new adapter needs no change to the suite; CI runs it in each implementation's job.

## Run

```
run --role=client|server
    --variant=NAME                       # both; "default" or a name from the variants file
    --host=HOST --port=PORT              # both; the server binds (0 = any free port), the client connects
    --groups=G1[,G2...]                  # both; preference order, IANA names
    --transport=dtls|tls                 # both; DTLS 1.3 over UDP or TLS 1.3 over TCP
    --resume=off|ticket                  # both; one connection, or a second one resuming the first
    --mtu=N|default                      # both; path MTU at the IP layer, see below
    --ca=FILE                            # both; the client verifies the server as "localhost"
    --key-share=GROUP|empty|default      # client only: what goes into CH1 key_share
    --validate=off|cookie                # server only: stateless HRR cookie for new peers
    --cert=FILE --key=FILE               # server only
```

Every option listed for a role is required; there are no implicit defaults.
The value `default` means "do not configure this, let the library decide", so library defaults are measured explicitly.
The runner passes `--transport` and `--resume` in every case, so an adapter can never fall back to an assumed transport or connection count.
A missing, unknown, repeated or other-role option, or a malformed value, is a usage error (exit 64).
Option names match exactly, so an abbreviation such as `--group` is an unknown option, and an empty value is malformed.
A `--key-share` group that is not in `--groups` counts as malformed.
The runner passes every option as `--opt=value`; adapters must accept that form and should also accept `--opt value`.

### Transport

ADR 0004 explains the transport and resumption rules.
`--transport=dtls` runs DTLS 1.3 over UDP; every rule in this document applies to it unless it says otherwise.
`--transport=tls` runs TLS 1.3 over TCP: the server listens on a TCP socket, the client connects to it, and `version` reports `TLSv1.3`.
Both pin the protocol to version 1.3 only.
With `--transport=tls`, `--mtu` must be `default`; a number is a malformed value (exit 64), since a byte stream has no datagram size to configure.
`--validate=cookie` with `--transport=tls` makes the server answer every first ClientHello with a HelloRetryRequest that carries a cookie (RFC 9846 sec 4.2.4, 4.3.2) and complete the handshake only with a second ClientHello that echoes it.

`implementations/<name>/transports` declares the transports the adapter implements, one per line (`dtls` or `tls`); without the file the adapter implements `dtls` only.
The runner starts a case only when both entries declare the scenario's transport and records `unsupported` otherwise, without starting either adapter.
An adapter accepts both values of `--transport` and exits 2 for one it does not implement, so an undeclared run fails safely.
A variant that only exists for one transport (e.g. a DTLS-only server code path) also exits 2 for the other one.
So a TLS-only implementation joins the matrix with a `transports` file that lists only `tls`: it runs the TLS scenarios, and every DTLS case it would be part of is `unsupported`.
`dtls-interop list` shows the declared transports of every entry.

### Resumption

`--resume=off` runs one connection, as described in Lifecycle and teardown.
`--resume=ticket` runs two connections in sequence, where the second one resumes the first with a PSK from a NewSessionTicket (RFC 9846 sec 2.2, 4.7.1).

- Client: connection 1 runs the full client lifecycle.
If it has not received a NewSessionTicket the library can resume with by the time it has read `pong`, the client exits 1 with the error `connection 1: no session ticket received`.
Otherwise it opens a new socket (a new UDP source port or a new TCP connection) to the same address and runs connection 2, offering that ticket in the pre_shared_key extension (RFC 9846 sec 4.3.11).
The client uses the library's default psk_key_exchange_modes (RFC 9846 sec 4.3.9) and never sends early data.
- Server: it prints `ready` once, then serves connection 1 and connection 2 one after the other with the full server lifecycle each, from the same library context, and exits after connection 2.
It issues tickets as the library does by default; a library that issues none with its defaults is configured to issue one and the README says so.
`--validate=cookie` applies to both connections, so with DTLS connection 2 also gets an HRR with a cookie, from which the client computes a new PSK binder (RFC 9846 sec 4.3.11.2).

The exit code covers both connections: 0 only if both succeeded.
The result line describes the last connection the adapter attempted: connection 2, or connection 1 if that one failed.
Whenever `--resume=ticket` is set, every `error` after option parsing is prefixed with `connection N: `; a usage error (exit 64) may lack it.
A server that declines the PSK and completes a full handshake on connection 2 is a successful handshake: the adapters report `ok: true` with `resumed: false`, and the runner judges that against the scenario.

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

### Address validation

`--validate=cookie` makes the server send an HRR with a cookie to a new peer before it continues the handshake.
With `--validate=off` the server never sends an HRR whose only purpose is a cookie; an HRR needed for group selection may still carry a cookie the library always adds (e.g. for a stateless HRR), and `hrr_cookie` reports it.

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

1. Server: bind, print `ready` with the bound port, accept one connection (two with `--resume=ticket`).
The runner passes `--port=0`, so the port is never picked by one process and bound by another.
2. Client: complete the handshake, send `ping`, read `pong`, send close_notify, wait up to 2 s for the server's close_notify, print the result, exit.
3. Server: answer `ping` with `pong`, wait up to 2 s for the client's close_notify, send its own close_notify, print the result, exit.

The client's verdict is final once it has read `pong`; errors during teardown go to stderr and never change the result.
Adapters impose no handshake timeout of their own below 60 s; the runner owns timeouts.
With `--transport=tls`, close_notify is followed by closing the TCP connection.
Adapters stay in the process group the runner starts them in and never daemonize.
The runner kills the group at the case timeout, and the server 5 s after the client has exited.
Exit 2 or 64 decides the outcome whatever the peer does, so the runner then kills the peer at once.

## Output protocol

stdout carries only JSON lines; everything else goes to stderr and is kept in the run log.

- Server, once its socket is bound and it accepts datagrams (or, with `--transport=tls`, listens): `{"event": "ready", "port": 40123}` with the port actually bound.
The runner starts the client only after this line.
- Both roles, last line before exit:

```json
{"event": "result", "ok": true, "version": "DTLSv1.3", "group": "X25519MLKEM768", "hrr": true, "hrr_cookie": true, "hrr_group": false, "resumed": false, "error": null}
```

| Field | Meaning |
|---|---|
| `ok` | Handshake and echo succeeded; must match exit code 0 |
| `version` | Negotiated protocol version, e.g. `DTLSv1.3` |
| `group` | Negotiated group, IANA name |
| `hrr` | A HelloRetryRequest was sent (server) or received (client) |
| `hrr_cookie` | That HRR carried a cookie extension |
| `hrr_group` | That HRR carried a key_share selected_group, i.e. asked for a new key share |
| `resumed` | The server accepted the client's PSK, so the handshake was a resumption |
| `error` | Short error string from the library on failure |

Fields the adapter cannot determine are `null`, never guessed; `hrr_cookie` and `hrr_group` are `false` when `hrr` is `false`.
Before the handshake has started (usage error, unsupported configuration) `version`, `group`, `hrr`, `hrr_cookie`, `hrr_group` and `resumed` are `null`.
With `--resume=off`, `resumed` is `false` once the handshake has completed.
Every exit prints a result line; on exit 1, 2 and 64 `ok` is false and `error` is set, and the runner falls back to the last stderr line if it is missing.
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
