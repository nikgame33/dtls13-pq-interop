# TODO

Phases are ordered; items within a phase can run in parallel.
Mark done with `[x]` and add the commit or PR reference.

## Phase 0: Repo setup

- [x] Repo skeleton, README, background, test matrix, adapter interface draft, ADR 0001
- [x] Python tooling (uv, ruff, pytest)
- [x] Public GitHub repo, Apache-2.0
- [x] CI workflow: ruff, pytest, per-implementation build + adapter tests (auto-discovered)
- [ ] CI: full matrix run on a schedule, report as artifact

## Phase 1: Harness core

- [x] UDP proxy: forward client<->server on loopback, enforce PMTU (drop oversize), log every datagram with timestamp and direction (PR #1)
- [x] DTLS record parser for the trace: DTLSPlaintext and DTLSCiphertext (unified header) records, handshake type, message_seq, fragment offset/length (PR #1)
- [x] Impairment rules on parsed records: reorder CH1 fragments, drop the first CH1 fragment once (PR #1)
- [x] E2E tests for the proxy with real UDP sockets (no mocks): PMTU drop, reorder, drop-once, trace content (PR #1)
- [x] Proxy rule that splits an unfragmented CH1 into fragments (wolfSSL clients never fragment CH1) (PR #1)
- [ ] Runner: start server adapter, wait for readiness, start client, enforce timeout, collect exit code, JSON line, logs, trace
- [ ] Result schema (JSON per run) and a results directory layout keyed by date, implementation versions and scenario
- [x] Test PKI generation (ECDSA P-256 CA + leaf), fresh per test session

- [x] Conformance suite `tests/conformance/`: every rule of docs/shim-interface.md against every built implementation and variant (ADR 0002) (PR #9)

## Phase 2: Implementations

Each item: `build.sh` with pinned version and checksum, `run` adapter per docs/shim-interface.md, self-interop of S01 passing.

- [ ] OpenSSL 4.1.0: decide between `openssl s_client`/`s_server` and a small C adapter on the listener API (`SSL_new_listener`, validation on by default)
- [ ] wolfSSL v5.9.4-stable: configure flags for DTLS 1.3 + ML-KEM hybrids; find the option that allows fragmented CH1
- [x] BoringSSL: pin a commit; small C/C++ adapter (bssl tool has no DTLS) (PR #10)
- [ ] NSS: pin a release; check `tstclnt`/`selfserv` DTLS 1.3 + group options, otherwise a small adapter
- [ ] mbedTLS 4.3.0: TLS 1.3 only, for T01 (HRR cookie echo); confirm DTLS 1.3 is really absent upstream
- [ ] Document per implementation which matrix options map to which flags or API calls, and which are unsupported

## Phase 3: Scenarios

- [ ] S01 to S03 (baseline, PQ share, fragmented CH1)
- [ ] S04 stateless cookie with fragmented CH1, including server state and amplification measurement
- [ ] S05, S06 HRR paths (empty share, wrong guess)
- [ ] S07 MLKEM512X25519 at PMTU 1280: measure whether CH1 and CH2 really stay unfragmented with realistic extensions (SNI, ALPN, use_srtp for WebRTC-like profile)
- [x] S08, S09 reordering and loss (PR #11)
- [x] Run S03, S04, S08, S09 with wolfSSL clients through `SplitClientHello`, since they never fragment CH1 (PR #11, `<ID>+split` rows, ADR 0003)
- [x] S10 PSK resumption after HRR (PR #13)
- [ ] T01 TLS 1.3 HRR cookie echo: contract, runner, TCP proxy trace and OpenSSL/wolfSSL adapters done (PR #13); mbedTLS adapter pending

## Phase 4: Results and outreach

- [ ] Matrix report (Markdown + HTML) generated from result JSON, with links to each trace
- [ ] Reproduce or refute each claim listed in docs/background.md, with version and configuration
- [ ] File bugs upstream for confirmed failures, with a one-command reproduction
- [ ] Summarise on tlswg/dtls13-spec#313 and #333
- [ ] Post results to tls@ietf.org (thread "Deployability of DTLS 1.3, HRR, and MLKEM512X25519")

## Later (Topic 2 prototype)

- [ ] Use this harness as the test bed for candidate fixes for fragmented CH1 + stateless validation (record-layer approach from IETF 127, HelloVerifyRequest-style exchange)

## Open questions

- [ ] Ask John Mattsson for the CipherSnake configurations behind his findings, so we test the same settings
- [ ] Include GnuTLS? (check DTLS 1.3 status)
- [x] Which BoringSSL commit to pin: f3ba8e44 (2026-11-24), tip of main at Phase 2 (PR #10)
- [ ] Which NSS release to pin (latest at time of Phase 2)
