"""Discovery of implementation adapters under implementations/<name>/."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
IMPLEMENTATIONS_DIR = REPO_ROOT / "implementations"
BUILD_DIR = REPO_ROOT / ".build"

# Comma-separated names that MUST be built; set in CI so a broken build fails instead of skipping.
REQUIRED_ENV = "DTLS_INTEROP_REQUIRE"


@dataclass(frozen=True)
class Implementation:
    name: str
    adapter: Path
    build_script: Path
    prefix: Path

    @property
    def is_built(self) -> bool:
        return (self.prefix / ".built").is_file()


def discover(
    implementations_dir: Path = IMPLEMENTATIONS_DIR, build_dir: Path = BUILD_DIR
) -> list[Implementation]:
    """All implementations that ship a build.sh."""
    found = []
    for build_script in sorted(implementations_dir.glob("*/build.sh")):
        name = build_script.parent.name
        found.append(
            Implementation(
                name=name,
                adapter=build_script.parent / "run",
                build_script=build_script,
                prefix=build_dir / name,
            )
        )
    return found


def required_names() -> set[str]:
    return {n.strip() for n in os.environ.get(REQUIRED_ENV, "").split(",") if n.strip()}
