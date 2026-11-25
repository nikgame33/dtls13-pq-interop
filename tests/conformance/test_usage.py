"""Usage errors (docs/shim-interface.md, Run and Variants): exit 64 with a result line."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

import pytest

from dtls_interop import implementations
from dtls_interop.implementations import CLIENT, SERVER

from .harness import (
    EXIT_USAGE,
    MLKEM,
    P256,
    ROLE_OPTIONS,
    Harness,
    Options,
    Subject,
    check_protocol,
    render,
    subjects,
)

# A usage error must be detected before any network activity.
USAGE_TIMEOUT = 10.0

MALFORMED = {
    "role": ["both", "Client"],
    "port": ["abc", "-1", "65536", "1e3"],
    "groups": [",", "X25519,", ",X25519", "X25519,,secp256r1"],
    "mtu": ["abc", "-1", "0", "48", "1280x"],
    "validate": ["maybe", "on"],
    # The baseline --groups is X25519 only.
    "key-share": [P256, MLKEM],
}


@dataclass(frozen=True)
class UsageCase:
    name: str
    change: Callable[[Options], Options]
    extra: tuple[str, ...] = ()  # raw arguments appended after the options


def _drop(opts: Options, name: str) -> Options:
    return [(k, v) for k, v in opts if k != name]


def _set(opts: Options, name: str, value: str) -> Options:
    return [(k, value if k == name else v) for k, v in opts]


def _rename(opts: Options, name: str, new: str) -> Options:
    return [(new if k == name else k, v) for k, v in opts]


def _other_role_value(opts: Options, name: str) -> str:
    # Any existing file for the file options; a valid value otherwise.
    return {"key-share": "X25519", "validate": "off"}.get(name, dict(opts)["ca"])


def usage_cases(subject: Subject, entries: list[implementations.Implementation]) -> list[UsageCase]:
    role = subject.role
    own = ROLE_OPTIONS[role]
    cases = []
    for name in own:
        cases += [
            UsageCase(f"missing-{name}", lambda o, n=name: _drop(o, n)),
            UsageCase(f"repeated-{name}", lambda o, n=name: [*o, (n, dict(o)[n])]),
            UsageCase(f"empty-{name}", lambda o, n=name: _set(o, n, "")),
        ]
        for value in MALFORMED.get(name, []):
            cases.append(UsageCase(f"bad-{name}={value}", lambda o, n=name, v=value: _set(o, n, v)))
    if role == CLIENT:
        cases.append(UsageCase("bad-port=0", lambda o: _set(o, "port", "0")))
    for name in ROLE_OPTIONS[SERVER if role == CLIENT else CLIENT]:
        if name not in own:
            cases.append(
                UsageCase(
                    f"other-role-{name}", lambda o, n=name: [*o, (n, _other_role_value(o, n))]
                )
            )
    cases += [
        UsageCase("unknown-option", lambda o: [*o, ("no-such-option", "1")]),
        UsageCase("abbreviated-option", lambda o: _rename(o, "groups", "group")),
        UsageCase("positional-argument", lambda o: o, ("stray",)),
        UsageCase("missing-value", lambda o: _drop(o, "mtu"), ("--mtu",)),
        UsageCase("unknown-variant", lambda o: _set(o, "variant", "no-such-variant")),
    ]
    # Variants listed only for the other role.
    for e in entries:
        if e.name == subject.impl.name and role not in e.roles:
            cases.append(
                UsageCase(
                    f"variant-not-for-{role}-{e.variant}",
                    lambda o, v=e.variant: _set(o, "variant", v),
                )
            )
    return cases


def pytest_generate_tests(metafunc: pytest.Metafunc) -> None:
    if "usage" not in metafunc.fixturenames:
        return
    entries = implementations.discover()
    params = [
        pytest.param((s, case), id=f"{s.role}-{s.impl.id}-{case.name}")
        for s in subjects(entries)
        for case in usage_cases(s, entries)
    ]
    metafunc.parametrize("usage", params, indirect=True)


@pytest.fixture
def usage(request: pytest.FixtureRequest) -> tuple[Subject, UsageCase]:
    request.getfixturevalue("require_impl")(request.param[0].impl.id)
    return request.param


def test_usage_error_exits_64(usage: tuple[Subject, UsageCase], harness: Harness) -> None:
    subject, case = usage
    opts = case.change(harness.options(subject.impl, subject.role))
    for form in ("equals", "space"):
        args = render(opts, form) + list(case.extra)
        run = harness.run(subject.impl, subject.role, args, USAGE_TIMEOUT)
        assert run.code == EXIT_USAGE, f"{form} form\n{run.describe()}"
        check_protocol(run)
        assert len(run.stdout) == 1, f"only the result line, no ready line\n{run.describe()}"
