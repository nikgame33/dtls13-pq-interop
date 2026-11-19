"""Discovery of implementation adapters under implementations/<name>/, one entry per variant."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
IMPLEMENTATIONS_DIR = REPO_ROOT / "implementations"
BUILD_DIR = REPO_ROOT / ".build"

# Comma-separated names that MUST be built; set in CI so a broken build fails instead of skipping.
REQUIRED_ENV = "DTLS_INTEROP_REQUIRE"

DEFAULT_VARIANT = "default"
VARIANTS_FILE = "variants"
VARIANT_SEPARATOR = "+"
_VARIANT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


@dataclass(frozen=True)
class Implementation:
    name: str
    adapter: Path
    build_script: Path
    prefix: Path
    variant: str = DEFAULT_VARIANT
    variant_description: str | None = None

    @property
    def id(self) -> str:
        """Matrix entry name: `<name>` for the default variant, else `<name>+<variant>`."""
        if self.variant == DEFAULT_VARIANT:
            return self.name
        return f"{self.name}{VARIANT_SEPARATOR}{self.variant}"

    @property
    def is_built(self) -> bool:
        return (self.prefix / ".built").is_file()

    @property
    def version(self) -> str | None:
        """First line of the .built marker: the pinned upstream version."""
        try:
            text = (self.prefix / ".built").read_text().strip()
        except OSError:
            return None
        return text.splitlines()[0] if text else None


def read_variants(path: Path) -> list[tuple[str, str]]:
    """Parse a variants file (`NAME: description` per line); a missing file means none."""
    if not path.is_file():
        return []
    variants: list[tuple[str, str]] = []
    for number, line in enumerate(path.read_text().splitlines(), start=1):
        if not line.strip():
            continue
        name, sep, description = line.partition(":")
        name, description = name.strip(), description.strip()
        if not sep or not _VARIANT_RE.match(name) or not description:
            raise ValueError(f"{path}:{number}: expected 'NAME: description', got {line!r}")
        if name == DEFAULT_VARIANT or name in dict(variants):
            raise ValueError(f"{path}:{number}: duplicate or reserved variant {name!r}")
        variants.append((name, description))
    return variants


def discover(
    implementations_dir: Path = IMPLEMENTATIONS_DIR, build_dir: Path = BUILD_DIR
) -> list[Implementation]:
    """One entry per variant of every implementation that ships a build.sh, default first."""
    found = []
    for build_script in sorted(implementations_dir.glob("*/build.sh")):
        name = build_script.parent.name
        base = Implementation(
            name=name,
            adapter=build_script.parent / "run",
            build_script=build_script,
            prefix=build_dir / name,
        )
        found.append(base)
        for variant, description in read_variants(build_script.parent / VARIANTS_FILE):
            found.append(
                Implementation(
                    name=name,
                    adapter=base.adapter,
                    build_script=build_script,
                    prefix=base.prefix,
                    variant=variant,
                    variant_description=description,
                )
            )
    return found


def required_names() -> set[str]:
    return {n.strip() for n in os.environ.get(REQUIRED_ENV, "").split(",") if n.strip()}
