# ADR 0007: NSS adapter - group reordering and MTU

Status: proposed (2026-11-24)

## Context

NSS 3.134 is reached through a C adapter on libssl (`implementations/nss/`), because `tstclnt`/`selfserv` cannot set the key share, the HRR cookie or the MTU.
Two contract rules from ADR 0002 and `docs/shim-interface.md` have no direct NSS API.

Server group selection: `tls13_NegotiateKeyExchange` (`lib/ssl/tls13con.c`) prefers the first server group the client supports.
It uses a client share only for that group or, if the strength matches within 2 bits (`tls13_isGroupAcceptable`), for the group in the next slot.
Otherwise it sends an HRR, so "key share first" is violated with three or more server groups or with groups of different strength.

MTU: NSS has no public DTLS MTU setting.
The estimate starts at 1472 bytes (`COMMON_MTU_VALUES` in `lib/ssl/dtlscon.c`), which allows 1417-byte datagrams, and drops to the next table entry after every third retransmission.
The gtests set it through `SSLInt_SetMTU`, which is internal and not exported.

## Decision

Groups: the adapter's NSPR I/O layer reassembles each ClientHello the server receives and, before libssl reads it, calls the public `SSL_NamedGroupConfig` with the server's groups reordered.
Groups the client sent a share for come first, then the others, each part in `--groups` order.
NSS's own selection then yields exactly rules 1 to 3; the reordering is logged.

MTU: `--mtu=N` with N - 48 >= 1417 (N >= 1465) runs with NSS's built-in estimate, because no datagram can exceed the limit; smaller values exit 2 (unsupported).
`--mtu=default` also configures nothing.
The I/O layer refuses any datagram above N - 48, so a wrong assumption fails a run instead of silently breaking the limit.

## Alternatives considered

- Setting `ss->ssl3.mtu` through the private `sslimpl.h` layout, as `SSLInt_SetMTU` does: it would make `--mtu=1280` work, but depends on an unexported struct layout that can change in any release and is not how any NSS application can behave.
- Dropping oversize datagrams in the I/O layer so that NSS's own backoff shrinks the estimate: it never exceeds N - 48 on the wire, but it adds retransmission delays and local losses that the scenario did not ask for, and it reaches only the table values 1252, 548 and 228, not N - 48.
- Leaving the server's group order alone: NSS results would then reflect NSS's selection rule rather than the scenarios, contrary to ADR 0002.

## Consequences

- The NSS rows of all scenarios at `--mtu=1280` (S03, S04, S07 to S10) report unsupported, which is NSS's real limitation: no application can configure the DTLS MTU.
- How NSS behaves on a 1280-byte path can still be measured with `--mtu=default` behind the proxy; that would need new scenarios and is left to the project owner.
- On a real 1280-byte path NSS shrinks only after three retransmission timeouts, and never while the peer ACKs partial flights (`dtls13_HandleAck` resends and restarts the timer); the README records the measurements.
- The group reordering relies on `SSL_NamedGroupConfig` being callable between two reads during a handshake, which holds for 3.134 and is covered by the adapter tests.
