"""Command line: `dtls-interop list` and `dtls-interop run`."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from dtls_interop import implementations, pki, runner, scenarios
from dtls_interop.implementations import Implementation
from dtls_interop.results import Outcome, RunLayout

DEFAULT_RESULTS_DIR = implementations.REPO_ROOT / "results"
# Outcomes that make `run` exit non-zero; "unsupported" is a valid matrix result.
FAILING = {Outcome.FAIL, Outcome.TIMEOUT, Outcome.ERROR}
EXIT_FAILED = 1
EXIT_USAGE = 2


class UsageError(Exception):
    pass


def _parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
    common.add_argument(
        "--implementations-dir", type=Path, default=implementations.IMPLEMENTATIONS_DIR
    )
    common.add_argument("--build-dir", type=Path, default=implementations.BUILD_DIR)

    parser = argparse.ArgumentParser(prog="dtls-interop", allow_abbrev=False)
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser(
        "list", parents=[common], allow_abbrev=False, help="implementations and scenarios"
    )

    run = sub.add_parser("run", parents=[common], allow_abbrev=False, help="run scenarios")
    run.add_argument(
        "--scenario",
        action="append",
        required=True,
        help="scenario ID, repeatable or comma-separated; 'all' for every scenario",
    )
    run.add_argument(
        "--client", action="append", help="NAME or NAME+VARIANT, repeatable (default: all built)"
    )
    run.add_argument(
        "--server", action="append", help="NAME or NAME+VARIANT, repeatable (default: all built)"
    )
    run.add_argument("--results-dir", type=Path, default=DEFAULT_RESULTS_DIR)
    run.add_argument("--ready-timeout", type=float, default=runner.DEFAULT_READY_TIMEOUT)
    run.add_argument("--timeout", type=float, default=runner.DEFAULT_CASE_TIMEOUT)
    run.add_argument("--server-grace", type=float, default=runner.DEFAULT_SERVER_GRACE)
    return parser


def _split(values: Sequence[str]) -> list[str]:
    return [v.strip() for value in values for v in value.split(",") if v.strip()]


def _cmd_list(impls: list[Implementation]) -> int:
    print("Implementations:")
    if not impls:
        print("  (none)")
    width = max((len(i.id) for i in impls), default=0)
    for impl in impls:
        state = "built" if impl.is_built else "not built"
        if impl.is_built and impl.version:
            state += f" ({impl.version})"
        note = f"  variant: {impl.variant_description}" if impl.variant_description else ""
        print(f"  {impl.id:<{width}}  {state}{note}")
    print("Scenarios:")
    for s in scenarios.SCENARIOS:
        print(f"  {s.id}  {s.description}")
    return 0


def _select(
    impls: list[Implementation], names: list[str] | None, role: str
) -> list[Implementation]:
    built = {i.id: i for i in impls if i.is_built}
    if names is None:
        return list(built.values())
    known = {i.id for i in impls}
    chosen = []
    for name in _split(names):
        if name not in known:
            raise UsageError(f"unknown {role} implementation {name!r}")
        if name not in built:
            raise UsageError(f"{role} implementation {name!r} is not built")
        chosen.append(built[name])
    return chosen


def _cmd_run(args: argparse.Namespace, impls: list[Implementation]) -> int:
    ids = _split(args.scenario)
    if "all" in (i.lower() for i in ids):
        selected = list(scenarios.SCENARIOS)
    else:
        try:
            selected = [scenarios.get(i) for i in ids]
        except KeyError as e:
            raise UsageError(e.args[0]) from None
    clients = _select(impls, args.client, "client")
    servers = _select(impls, args.server, "server")
    if not clients or not servers:
        raise UsageError("no built implementations to run")

    layout = RunLayout.new(args.results_dir)
    layout.directory.mkdir(parents=True, exist_ok=True)
    credentials = pki.generate(layout.directory / "pki")
    print(f"run {layout.run_id} -> {layout.directory}", flush=True)
    failed = 0
    for scenario in selected:
        for client in clients:
            for server in servers:
                result = runner.run_case(
                    scenario,
                    client,
                    server,
                    layout=layout,
                    pki=credentials,
                    ready_timeout=args.ready_timeout,
                    case_timeout=args.timeout,
                    server_grace=args.server_grace,
                )
                failed += result.outcome in FAILING
                reason = f"  {result.reason}" if result.reason else ""
                print(
                    f"{scenario.id}  {client.id}__{server.id}  {result.outcome}"
                    f"  {result.duration_s:.2f}s{reason}",
                    flush=True,
                )
    total = len(selected) * len(clients) * len(servers)
    print(f"{total - failed}/{total} cases passed or unsupported; results in {layout.directory}")
    return EXIT_FAILED if failed else 0


def _discover(args: argparse.Namespace) -> list[Implementation]:
    try:
        return implementations.discover(args.implementations_dir, args.build_dir)
    except ValueError as e:  # malformed variants file
        raise UsageError(str(e)) from None


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        impls = _discover(args)
        if args.command == "list":
            return _cmd_list(impls)
        return _cmd_run(args, impls)
    except UsageError as e:
        print(f"dtls-interop: {e}", file=sys.stderr)
        return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())
