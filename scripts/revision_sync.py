#!/usr/bin/env python3
"""Synchronize README revision badges from authoritative file metadata."""
from __future__ import annotations

import html
import re
from pathlib import Path
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]
START = "<!-- AEGIS-REVISION-MATRIX:START -->"
END = "<!-- AEGIS-REVISION-MATRIX:END -->"
VERSION = r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"

TRACKED = [
    ("autounattend.xml", "version"),
    ("AegisWin11_Deploy.ps1", "version"),
    ("Post-FeatureUpdate-Compare-AegisBase.ps1", "version"),
    ("README.md", "document"),
    ("CHANGELOG.md", "changelog"),
    ("docs/wiki/home.md", "document"),
    ("docs/wiki/Technical-Reference-Manual.md", "document"),
    ("docs/wiki/Security-Architecture-Compliance-Report.md", "document"),
]


def get_version(path: Path, kind: str) -> str:
    content = path.read_text(encoding="utf-8-sig")
    if kind == "changelog":
        pattern = r"(?m)^##\s+\[([^\]\r\n]+)\]"
    elif kind == "document":
        pattern = r"(?im)^\s*(?:<!--\s*)?(?:\*\*)?Document (?:Version|Revision)(?:\*\*)?\s*:\s*(\S+)"
    else:
        pattern = r"(?im)^\s*(?:\#\s*)?Version\s*:\s*(\S+)"

    match = re.search(pattern, content)
    if not match:
        raise ValueError(f"Missing {kind} revision metadata: {path.relative_to(ROOT)}")
    value = match.group(1).strip()
    if not re.fullmatch(VERSION, value):
        raise ValueError(f"Invalid revision {value!r} in {path.relative_to(ROOT)}; expected MAJOR.MINOR.PATCH")
    return value


def badge(version: str) -> str:
    return ("https://img.shields.io/badge/Rev-"
            f"{version}-334155?style=flat-square&labelColor=1E293B")


def generate() -> None:
    readme_path = ROOT / "README.md"
    readme = readme_path.read_text(encoding="utf-8")
    if readme.count(START) != 1 or readme.count(END) != 1:
        raise ValueError("README.md must contain exactly one START and END revision-matrix marker")
    if readme.index(START) >= readme.index(END):
        raise ValueError("README revision-matrix markers are reversed")

    rows = []
    for relative_path, kind in TRACKED:
        path = ROOT / relative_path
        if not path.is_file():
            raise FileNotFoundError(f"Tracked file missing: {relative_path}")
        version = get_version(path, kind)
        name = html.escape(path.name)
        url = "https://github.com/narcarsiss/Aegis-Win11/blob/main/" + quote(relative_path, safe="/")
        rows.append(
            f'  <tr><td><a href="{url}"><code>{name}</code></a></td>'
            f'<td><img src="{html.escape(badge(version), quote=True)}" '
            f'alt="Revision {version}"></td></tr>'
        )
        print(f"{relative_path}: {version}")

    block = "\n".join([
        START,
        '<table>',
        '  <thead><tr><th>Tracked File</th><th>Revision</th></tr></thead>',
        '  <tbody>',
        *rows,
        '  </tbody>',
        '</table>',
        END,
    ])
    new_readme = readme[:readme.index(START)] + block + readme[readme.index(END) + len(END):]
    if new_readme != readme:
        readme_path.write_text(new_readme, encoding="utf-8")
        print("README revision matrix updated")
    else:
        print("README revision matrix already current")


if __name__ == "__main__":
    generate()
