#!/usr/bin/env python3
"""Build a strictly allowlisted student ZIP and integrity manifest, no solutions."""
from __future__ import annotations

import hashlib
import io
import zipfile
from pathlib import Path
from verify_case import ROOT, EVIDENCE, CSV_FILES, validate

DOCS = (
    "README.txt",
    "docs/CASE_BRIEF.md",
    "docs/EVIDENCE_LIMITS.md",
    "docs/ARCHITECTURE.md",
    "questions/INVESTIGATION.md",
)
EVIDENCE_FILES = sorted(path.name for path in EVIDENCE.iterdir() if path.is_file())
DIST = ROOT / "dist"
NAME = "Cuantium-Centinell-QC001-STUDENT.zip"

def manifest(entries: dict[str, bytes]) -> bytes:
    return "".join(
        f"{hashlib.sha256(entries[name]).hexdigest()}  {name}\n"
        for name in sorted(entries)
    ).encode("utf-8")

def build() -> Path:
    validate()
    DIST.mkdir(exist_ok=True)
    members = {name: (ROOT / name).read_bytes() for name in DOCS}
    members.update({f"evidence/{name}": (EVIDENCE / name).read_bytes() for name in EVIDENCE_FILES})
    members["SHA256SUMS.txt"] = manifest(members)
    target = DIST / NAME
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in sorted(members.items()):
            archive.writestr(name, content)

    verify_student(target)
    print(f"PASS: student package built: {target}, {len(members)} members")
    return target

def verify_student(target: Path) -> None:
    with zipfile.ZipFile(target, "r") as archive:
        names = archive.namelist()
        expected = set(DOCS) | {f"evidence/{n}" for n in EVIDENCE_FILES} | {"SHA256SUMS.txt"}
        if len(names) != len(set(names)) or set(names) != expected:
            raise ValueError("Student ZIP membership mismatch")
        if archive.testzip() is not None:
            raise ValueError("Bad ZIP member CRC")
        if any(name.startswith("/") or ".." in Path(name).parts for name in names):
            raise ValueError("Unsafe archive path")
        if any(any(s in name.lower() for s in ("instructor", "writeup", "solution", "answer_key")) for name in names):
            raise ValueError("Solution contamination")
        entries = {name: archive.read(name) for name in names if name != "SHA256SUMS.txt"}
        if archive.read("SHA256SUMS.txt") != manifest(entries):
            raise ValueError("Evidence hash manifest mismatch")

if __name__ == "__main__":
    build()
