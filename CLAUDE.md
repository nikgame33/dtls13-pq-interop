# dtls13-pq-interop

DTLS 1.3 + post-quantum key share interop matrix. Read README.md, then TODO.md for current work.

- Python harness in `src/dtls_interop/`, managed with uv. Run `uv run ruff check`, `uv run ruff format --check`, `uv run pytest` before committing.
- Tests use real UDP sockets and real library builds; do not mock the network or the libraries.
- Library builds go to `.build/<name>/` only (git-ignored). Every upstream version is pinned with a checksum or commit hash.
- Each implementation is reached only through its adapter (docs/shim-interface.md).
- Results must be reproducible: record library versions, build flags and adapter options with every run.
- Keep TODO.md current: tick items with the commit reference when done.
- Design decisions go into `docs/adr/NNNN-*.md`.
