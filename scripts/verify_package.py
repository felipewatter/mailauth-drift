"""Verify checksum and ZIP CRC, inspect for sensitive file names."""
from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ARCHIVE = ROOT / "dist" / "mailauth-drift-v0.1.0.zip"


def verify() -> int:
    digest = hashlib.sha256(ARCHIVE.read_bytes()).hexdigest()
    expected = (ROOT / "dist" / "SHA256SUMS").read_text(encoding="utf-8").strip()
    if expected != f"{digest}  {ARCHIVE.name}":
        raise ValueError("SHA256SUMS does not match ZIP")
    with zipfile.ZipFile(ARCHIVE) as zf:
        assert zf.testzip() is None, "ZIP CRC corruption"
        paths = zf.namelist()
        assert len(paths) == len(set(paths)), "duplicate archive entries"
        assert all(p.startswith("mailauth-drift-v0.1.0/") for p in paths)
        assert not any("../" in p or p.startswith("/") for p in paths), "zip slip"
        assert not any(p.endswith((".key", ".pem", ".p12", ".pfx")) for p in paths)
        assert "mailauth-drift-v0.1.0/README.md" in paths
        assert "mailauth-drift-v0.1.0/.github/workflows/ci.yml" in paths
        return len(paths)


if __name__ == "__main__":
    print(f"Validated reproducible archive with {verify()} files")
