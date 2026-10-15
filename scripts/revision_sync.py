```python
#!/usr/bin/env python3

##
# @file badge_sync.py
# @brief Synchronize README revision badges from authoritative file metadata.
# @pre The README.md file must contain exactly one START and END revision-matrix marker.
# @post README.md is updated with the latest revision badges if changes are detected.
# @warning Do not manually modify the revision matrix section in README.md; it is auto-generated.

"""Synchronize README revision badges from authoritative file metadata."""
from __future__ import annotations

import html
import re
from pathlib import Path
from urllib.parse import quote

## @brief Absolute path to the repository root directory (Path).
ROOT = Path(__file__).resolve().parents[1]

## @brief Absolute path to the target README.md file (Path).
README_PATH = ROOT / "README.md"

## @brief Target GitHub repository URL (str).
REPO_URL = "https://github.com/narcarsiss/Aegis-Win11"

## @brief Target repository branch for file blob URLs (str).
BRANCH = "main"

## @brief Matrix start marker within the README.md (str).
START = "<!-- AEGIS-REVISION-MATRIX:START -->"

## @brief Matrix end marker within the README.md (str).
END = "<!-- AEGIS-REVISION-MATRIX:END -->"

## @brief Regex pattern for strict semantic versioning MAJOR.MINOR.PATCH (str).
# Strict MAJOR.MINOR.PATCH
VERSION = r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"

## @brief List of tuples containing (Label, repository-relative path, metadata type) for tracked files (list).
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

##
# @brief Extracts the semantic version string from a given file based on its metadata type.
# @param path (Path) Absolute file path object to read.
# @param kind (str) Metadata type determining the regex pattern ('changelog', 'document', or standard).
# @return (str) The extracted semantic version (MAJOR.MINOR.PATCH).
# @throws ValueError If the revision metadata is missing or does not match the strict semantic versioning format.
# @pre The file at `path` must exist and be readable as utf-8-sig.
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
        pattern = r"(?im)^\s*(?:#\s*)?Version\s*:\s*(\S+)"
        
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

##
# @brief Generates the HTML block containing the revision badges for all tracked files.
# @param versions (dict[str, str]) Dictionary mapping repository-relative file paths to their extracted versions.
# @return (str) Formatted HTML string block containing the centered badges and matrix markers.
# @pre The `versions` dictionary must contain valid version strings for all tracked file paths.
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
            """ TWO OPTIONS: flat-square and for-the-badge"""
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

##
# @brief Main execution workflow to validate files, extract versions, and update the README.md.
# @return None
# @throws ValueError If README.md lacks exactly one of each matrix marker, or if markers are reversed.
# @throws FileNotFoundError If any tracked file from `TRACKED` does not exist on disk.
# @pre All tracked files must exist at their expected relative paths.
# @post README.md is overwritten with updated badge HTML if version discrepancies exist.
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
        readme[:start_pos] + block + readme[end_pos:]
    )
    
    if new_readme != readme:
        README_PATH.write_text(
            new_readme, encoding="utf-8"
        )
        print("README revision badges updated")
    else:
        print("README revision badges already current")

if __name__ == "__main__":
    generate()

```
