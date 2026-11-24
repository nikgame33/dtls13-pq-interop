"""Versioned per-case result JSON and the results directory layout.

Layout: <root>/<UTC date>/<run-id>/<scenario>/<client>__<server>/result.json (+ logs, trace).
Paths inside result.json are relative to the case directory so a results tree can be moved.
"""

from __future__ import annotations

import dataclasses
import datetime
import json
import re
import secrets
import types
import typing
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

# Bump on any incompatible change to CaseResult; readers reject other versions.
SCHEMA_VERSION = 2
RESULT_FILE = "result.json"

_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")


class Outcome(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    UNSUPPORTED = "unsupported"
    TIMEOUT = "timeout"
    ERROR = "error"


class SchemaError(ValueError):
    """A result file that does not match this schema version."""


@dataclass(frozen=True)
class AdapterRecord:
    implementation: str
    variant: str
    implementation_version: str | None
    command: list[str]
    started: bool
    # None when the process did not exit by itself (killed by the runner, or never started).
    exit_code: int | None
    killed: bool
    duration_s: float | None
    # The adapter's final {"event": "result", ...} line, or None if missing/malformed.
    result: dict[str, Any] | None
    stdout_log: str | None
    stderr_log: str | None


@dataclass(frozen=True)
class PathRecord:
    # False: client talked to the server directly, so PMTU was not enforced on the wire.
    proxied: bool
    pmtu: int
    impairments: list[str]
    # The proxy, not the client, cut CH1 into this many fragments (ADR 0003); None: no split.
    split_ch1: int | None
    # From the trace: "action: reason" -> count for every datagram not simply forwarded.
    actions: dict[str, int]


@dataclass(frozen=True)
class CaseResult:
    schema_version: int
    run_id: str
    timestamp: str
    scenario: str
    outcome: Outcome
    reason: str | None
    duration_s: float
    client: AdapterRecord
    server: AdapterRecord
    path: PathRecord
    trace: str | None
    # CH1/CH2 as the client sent them, before proxy rules: message length, fragments in the
    # first transmission. None without a proxy trace or if the client sent no such message.
    ch1_size: int | None = None
    ch1_fragments: int | None = None
    ch2_size: int | None = None
    ch2_fragments: int | None = None

    def to_json(self) -> str:
        return json.dumps(dataclasses.asdict(self), indent=2) + "\n"


def utc_now() -> datetime.datetime:
    return datetime.datetime.now(datetime.UTC)


def check_name(name: str) -> str:
    """Names become path components; "__" separates client and server, "+" marks a variant."""
    if not _NAME_RE.match(name) or "__" in name:
        raise ValueError(f"invalid name for a results path: {name!r}")
    return name


@dataclass(frozen=True)
class RunLayout:
    root: Path
    run_id: str
    started: datetime.datetime

    @classmethod
    def new(cls, root: Path, now: datetime.datetime | None = None) -> RunLayout:
        started = (now or utc_now()).astimezone(datetime.UTC)
        run_id = f"{started:%Y%m%dT%H%M%SZ}-{secrets.token_hex(3)}"
        return cls(root=root, run_id=run_id, started=started)

    @property
    def directory(self) -> Path:
        return self.root / f"{self.started:%Y-%m-%d}" / self.run_id

    def case_dir(self, scenario: str, client: str, server: str) -> Path:
        pair = f"{check_name(client)}__{check_name(server)}"
        return self.directory / check_name(scenario) / pair


def write_result(case_dir: Path, result: CaseResult) -> Path:
    case_dir.mkdir(parents=True, exist_ok=True)
    path = case_dir / RESULT_FILE
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(result.to_json())
    tmp.replace(path)
    return path


def read_result(path: Path) -> CaseResult:
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError as e:
        raise SchemaError(f"{path}: not JSON: {e}") from None
    if not isinstance(data, dict):
        raise SchemaError(f"{path}: top level is not an object")
    version = data.get("schema_version")
    if version != SCHEMA_VERSION:
        raise SchemaError(f"{path}: schema_version {version!r}, expected {SCHEMA_VERSION}")
    try:
        return _decode(CaseResult, data, "")
    except SchemaError as e:
        raise SchemaError(f"{path}: {e}") from None


def read_run(run_dir: Path) -> list[CaseResult]:
    return [read_result(p) for p in sorted(run_dir.glob(f"*/*/{RESULT_FILE}"))]


def _decode[T](cls: type[T], data: Any, where: str) -> T:
    if not isinstance(data, dict):
        raise SchemaError(f"{where or 'result'}: expected an object")
    hints = typing.get_type_hints(cls)
    fields = {f.name: f for f in dataclasses.fields(cls)}  # type: ignore[arg-type]
    unknown = set(data) - set(fields)
    if unknown:
        raise SchemaError(f"{where or 'result'}: unknown keys {sorted(unknown)}")
    kwargs = {}
    for name, f in fields.items():
        key = f"{where}.{name}" if where else name
        if name not in data:
            if f.default is dataclasses.MISSING:
                raise SchemaError(f"{key}: missing")
            continue
        kwargs[name] = _check(hints[name], data[name], key)
    return cls(**kwargs)


def _check(tp: Any, value: Any, key: str) -> Any:
    origin = typing.get_origin(tp)
    if origin in (types.UnionType, typing.Union):
        for option in typing.get_args(tp):
            try:
                return _check(option, value, key)
            except SchemaError:
                continue
        raise SchemaError(f"{key}: {value!r} does not match {tp}")
    if tp is type(None):
        if value is not None:
            raise SchemaError(f"{key}: expected null")
        return None
    if dataclasses.is_dataclass(tp):
        return _decode(tp, value, key)
    if isinstance(tp, type) and issubclass(tp, StrEnum):
        try:
            return tp(value)
        except ValueError:
            raise SchemaError(f"{key}: {value!r} is not one of {[m.value for m in tp]}") from None
    if origin is list:
        (item,) = typing.get_args(tp)
        if not isinstance(value, list):
            raise SchemaError(f"{key}: expected a list")
        return [_check(item, v, f"{key}[{i}]") for i, v in enumerate(value)]
    if origin is dict:
        if not isinstance(value, dict):
            raise SchemaError(f"{key}: expected an object")
        return value
    if tp is float:
        ok = isinstance(value, int | float) and not isinstance(value, bool)
    elif tp is int:
        ok = isinstance(value, int) and not isinstance(value, bool)
    else:
        ok = isinstance(value, tp)
    if not ok:
        raise SchemaError(f"{key}: expected {tp.__name__}, got {value!r}")
    return value
