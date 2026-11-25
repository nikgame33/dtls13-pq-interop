# ADR 0006: BoringSSL adapter

Status: proposed (2026-11-24)

## Context

BoringSSL has no releases, no DTLS mode in the `bssl` tool, no datagram BIO, no DTLS listener and no stateless HelloRetryRequest cookie.
Its server selects groups in strict server preference (`tls1_get_shared_group` in `ssl/extensions.cc`), while ADR 0002 requires "key share first".
The adapter has to fill these gaps without turning adapter choices into findings.

## Decision

- Pin the tip of `main` at the time of writing, `f3ba8e447de666b3820ab613f050b3bd6d1cb333` (2026-11-24), fetched by commit hash and verified with `git rev-parse`.
A newer pin is a deliberate change of `build.sh`, which also invalidates the CI cache.
- Write a small C adapter on libssl with its own `BIO_METHOD` over a non-blocking socket, and drive DTLS timers with `DTLSv1_get_timeout` and `DTLSv1_handle_timeout`.
The DTLS server peeks the first datagram from a new source and then exchanges datagrams with that peer only, without connecting the socket, so that the second connection of `--resume=ticket` arrives on the same socket from a new source port.
- Declare `--transport=tls` as well: `TLS_method()` over TCP differs only in socket setup and the record and handshake header sizes the message callback parses, so BoringSSL clients take part in T01 at little cost.
- Emulate key share first in `select_certificate_cb`: per connection, move the highest-ranked server group the client sent a share for to the front of the server's list with `SSL_set1_group_ids`.
This uses only public API and leaves BoringSSL's selection code unchanged; the HelloRetryRequest and no-mutual-group paths are still BoringSSL's own.
- `SSL_GROUP_FLAG_EQUAL_PREFERENCE_WITH_NEXT` was rejected as the mechanism: equal preference picks by the client's supported_groups order, not by its key shares, so it does not implement rule 1.
- `--validate=cookie` exits 2: there is no API to make a BoringSSL server send a cookie, and an adapter-side cookie exchange would test the adapter, not BoringSSL.
- No variants: there is a single server and a single client code path.

## Consequences

- S04, S08, S09, S10, T01 and every other cookie case with a BoringSSL server are `unsupported`; BoringSSL clients are still tested against cookie servers.
- A result with a BoringSSL server reflects the contract's selection rule, not BoringSSL's native strict preference; the adapter logs `key share first: selecting G` whenever the emulation decides.
- The pin has to be moved by hand to follow upstream.
