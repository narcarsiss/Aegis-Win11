#!/usr/bin/env python3
"""Synchronize README revision badges from authoritative file metadata."""

from __future__ import annotations

import html
import re
from pathlib import Path
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]
README_PATH = ROOT / "README.md"

REPO_URL = "https://github.com/narcarsiss/Aegis-Win11"
BRANCH = "main"

START = "<!-- AEGIS-REVISION-MATRIX:START -->"
END = "<!-- AEGIS-REVISION-MATRIX:END -->"

# Strict MAJOR.MINOR.PATCH.
VERSION = r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"

# Label, repository-relative path, metadata type.
TRACKED = [
    ("XML", "autounattend.xml", "version"),
    ("DEPLOY", "AegisWin11_Deploy.ps1", "version"),
    ("COMPARE", "Post-FeatureUpdate-Compare-AegisBase.ps1", "version"),
    ("README", "README.md", "document"),
    ("CHANGELOG", "CHANGELOG.md", "changelog"),
    ("WIKI", "docs/wiki/home.md", "document"),
    ("MANUAL", "docs/wiki/Technical-Reference-Manual.md", "document"),
    ("SECURITY", "docs/wiki/Security-Architecture-Compliance-Report.md", "document"),
]


def get_version(path: Path, kind: str) -> str:
    content = path.read_text(encoding="utf-8-sig")

    if kind == "changelog":
        # Latest Keep a Changelog release heading.
        pattern = r"(?m)^##\s+\[([^\]\r\n]+)\]"

    elif kind == "document":
        # Accept Document-Version, Document Version,
        # Document-Revision and Document Revision.
        pattern = (
            r"(?im)^\s*Document[- ](?:Version|Revision)"
            r"\s*:\s*([^\r\n]+?)\s*$"
        )

    else:
        # PowerShell .NOTES or XML header comment.
        # Old Match--> pattern = r"(?im)^\s*(?:#\s*)?Version\s*:\s*(\S+)"
        #New Match Patters for Complient Enterprise Scanning  [METADATA] Blocks
        pattern = r'(?m)^\s*"Version"\s*:\s*"([^"]+)"\s*,?\s*$'

    match = re.search(pattern, content)

    if not match:
        raise ValueError(
            f"Missing {kind} revision metadata: "
            f"{path.relative_to(ROOT)}"
        )

    version = match.group(1).strip()

    if not re.fullmatch(VERSION, version):
        raise ValueError(
            f"Invalid revision {version!r} in "
            f"{path.relative_to(ROOT)}; "
            "expected MAJOR.MINOR.PATCH"
        )

    return version


def render_revision_badges(versions: dict[str, str]) -> str:
    badges = []

    for label, relative_path, _ in TRACKED:
        version = versions[relative_path]

        file_url = (
            f"{REPO_URL}/blob/{BRANCH}/"
            f"{quote(relative_path, safe='/')}"
        )

        badge_url = (
            "https://img.shields.io/badge/"
            f"{quote(label, safe='')}-{quote(version, safe='')}-334155"
            "?style=flat-square"
            "&labelColor=1E293B"
        )

        badges.append(
            f'  <a href="{html.escape(file_url, quote=True)}">'
            f'<img src="{html.escape(badge_url, quote=True)}" '
            f'alt="{html.escape(label)} revision '
            f'{html.escape(version)}"></a>'
        )

    return "\n".join([
        START,
        '<p align="center"><strong>BUILD REVISIONS</strong></p>',
        '<p align="center">',
        *badges,
        '</p>',
        END,
    ])


def generate() -> None:
    readme = README_PATH.read_text(encoding="utf-8")

    if readme.count(START) != 1 or readme.count(END) != 1:
        raise ValueError(
            "README.md must contain exactly one START "
            "and END revision-matrix marker"
        )

    if readme.index(START) >= readme.index(END):
        raise ValueError(
            "README revision-matrix markers are reversed"
        )

    # Validate every tracked file before modifying README.
    versions = {}

    for label, relative_path, kind in TRACKED:
        path = ROOT / relative_path

        if not path.is_file():
            raise FileNotFoundError(
                f"Tracked file missing: {relative_path}"
            )

        version = get_version(path, kind)
        versions[relative_path] = version

        print(f"{label}: {version}")

    block = render_revision_badges(versions)

    start_pos = readme.index(START)
    end_pos = readme.index(END) + len(END)

    new_readme = (
        readme[:start_pos]
        + block
        + readme[end_pos:]
    )

    if new_readme != readme:
        README_PATH.write_text(
            new_readme,
            encoding="utf-8"
        )
        print("README revision badges updated")
    else:
        print("README revision badges already current")


if __name__ == "__main__":
    generate()
