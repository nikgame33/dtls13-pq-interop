# ADR 0002: Equivalent adapter behaviour

Status: accepted (2026-11-19)

## Context

The first two adapters (OpenSSL 4.1.0, wolfSSL 5.9.4) showed that libraries differ in defaults and policies that are not part of what the matrix wants to measure.
Without a central rule, a cross-implementation result could reflect an adapter choice instead of library behaviour.
Examples: server group selection, which server API is used, what happens when an option is omitted, and how the connection is torn down.

## Decision

Every adapter implements the rules below; `docs/shim-interface.md` is the normative contract and this ADR records why.
A shared conformance suite (`tests/conformance/`) runs against every built implementation and variant, so equivalence is tested, not assumed.

### Server group selection

1. Among the client's key shares for groups in the server's `--groups`, the server uses the one ranked highest in `--groups`.
2. If there is no such share, the server sends an HRR selecting the highest-ranked server group that the client lists in supported_groups.
3. If there is no mutual group, the handshake fails.

This is "key share first": an acceptable share never triggers an HRR just to get a group the server ranks higher.
It is what wolfSSL does natively (`TLSX_KeyShare_Choose`) and what OpenSSL does with all groups in one preference tuple.
Strict server preference cannot be implemented in wolfSSL without patching it; a scenario that needs it gives the server only the groups it accepts.

### No hidden switches: variants

A library code path the adapter can choose (e.g. `wolfSSL_accept()` vs `wolfSSL_accept_TLSv13()`) is a named variant, never an environment variable.
Variants are listed in `implementations/<name>/variants`, are selected with `--variant=NAME`, and are run by the matrix as their own entry (`wolfssl+accept-tls13`).
The variant is recorded in every result.

### No implicit defaults

Every option of a role is required, so a run never depends on what an adapter assumes.
Library defaults that matter for deployment are selected explicitly with the value `default` (`--mtu=default`, `--key-share=default`), which means "do not configure this, let the library decide".

### HRR reasons

The result reports `hrr_cookie` and `hrr_group` next to `hrr`, because an HRR sent only for address validation and one sent for a missing key share are different findings.

### Teardown

The client sends close_notify after it has read `pong`; the server waits for it before sending its own close_notify.
A DTLS endpoint drops non-alert records after it has sent close_notify, and on Linux an ICMP error from a closed port can be reported before queued data, so the opposite order loses `pong` intermittently.
Errors after `pong` are logged and never change the outcome.

## Consequences

- Cross-implementation differences in a result come from the library, not from adapter defaults.
- Adapters are stricter: an unknown option, an option of the other role, or a missing option is a usage error (exit 64), which the runner reports as "error".
- New adapters must pass the conformance suite before they join the matrix.
