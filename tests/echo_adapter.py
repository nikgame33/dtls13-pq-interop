"""Helpers to install the plain-UDP test adapter (fixtures/udp_echo/run) as fake implementations."""

from __future__ import annotations

import os
import shlex
import sys
from pathlib import Path

from dtls_interop.implementations import VARIANTS_FILE, Implementation

ECHO_ADAPTER = Path(__file__).parent / "fixtures" / "udp_echo" / "run"
ECHO_VERSION = "udp-echo 1.0"


def install(
    root: Path, name: str, *flags: str, built: bool = True, variants: str | None = None
) -> Implementation:
    """Create <root>/implementations/<name>/ (with an optional variants file) and, if built,
    <root>/build/<name>/.built. Returns the default-variant entry."""
    impl_dir = root / "implementations" / name
    impl_dir.mkdir(parents=True)
    if variants is not None:
        (impl_dir / VARIANTS_FILE).write_text(variants)
    build_script = impl_dir / "build.sh"
    build_script.write_text("#!/bin/sh\nexit 0\n")
    adapter = impl_dir / "run"
    echo = shlex.join([sys.executable, str(ECHO_ADAPTER)])
    # exec keeps the adapter's pid, so the runner's process group handling is exercised as-is.
    adapter.write_text(f'#!/bin/sh\nexec {echo} "$@" {shlex.join(flags)}\n')
    adapter.chmod(0o755)
    prefix = root / "build" / name
    if built:
        prefix.mkdir(parents=True)
        (prefix / ".built").write_text(ECHO_VERSION + "\n")
    return Implementation(name=name, adapter=adapter, build_script=build_script, prefix=prefix)


def child_pids() -> set[int]:
    """Direct children of this process, including unreaped zombies."""
    me = os.getpid()
    found = set()
    for stat in Path("/proc").glob("[0-9]*/stat"):
        try:
            text = stat.read_text()
        except OSError:
            continue
        # Field 4 is the ppid; the command name in field 2 may contain spaces.
        if int(text.rsplit(")", 1)[1].split()[1]) == me:
            found.add(int(stat.parent.name))
    return found


def pid_alive(pid: int) -> bool:
    """True if pid exists and is not a zombie."""
    try:
        text = Path(f"/proc/{pid}/stat").read_text()
    except OSError:
        return False
    return text.rsplit(")", 1)[1].split()[0] != "Z"
