"""Build deterministic source bundle with no credentials, binaries or caches."""
from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "dist" / "mailauth-drift-v0.1.0.zip"
EXCLUDED = {"dist", ".git", ".venv", ".pytest_cache", ".ruff_cache", "__pycache__", ".mypy_cache",
            "build", ".tox", ".idea", ".vscode"}
ALLOWED_TOP_DIRS = {".github", "docs", "examples", "scripts", "src", "tests"}
ALLOWED_ROOT_FILES = {".gitignore", "README.md", "LICENSE", "SECURITY.md", "CHANGELOG.md",
                      "CONTRIBUTING.md", "pyproject.toml"}
ALLOWED_EXTENSIONS = {".py", ".md", ".yml", ".yaml", ".json", ".toml", ".txt"}


def inputs() -> list[Path]:
    files = []
    for path in ROOT.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        rel = path.relative_to(ROOT)
        if len(rel.parts) == 1:
            if rel.name not in ALLOWED_ROOT_FILES:
                continue
        elif rel.parts[0] not in ALLOWED_TOP_DIRS:
            continue
        if any(part in EXCLUDED or part.endswith(".egg-info") for part in rel.parts):
            continue
        if len(rel.parts) > 1 and path.suffix not in ALLOWED_EXTENSIONS:
            continue
        if path.suffix in {".pyc", ".pyo", ".pem", ".key", ".p12", ".pfx"}:
            continue
        if path.name.startswith(".env") or path.name in {"id_rsa", "id_ed25519"}:
            continue
        files.append(path)
    return sorted(files)


def build() -> tuple[str, str]:
    OUTPUT.parent.mkdir(exist_ok=True)
    with zipfile.ZipFile(OUTPUT, "w") as zf:
        for file in inputs():
            rel = file.relative_to(ROOT).as_posix()
            metadata = zipfile.ZipInfo(f"mailauth-drift-v0.1.0/{rel}", date_time=(2020, 1, 1, 0, 0, 0))
            metadata.compress_type = zipfile.ZIP_DEFLATED
            metadata.external_attr = (0o100644 << 16)
            zf.writestr(metadata, file.read_bytes(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    digest = hashlib.sha256(OUTPUT.read_bytes()).hexdigest()
    (ROOT / "dist" / "SHA256SUMS").write_text(f"{digest}  {OUTPUT.name}\n", encoding="utf-8")
    return digest, OUTPUT.name


if __name__ == "__main__":
    checksum, archive = build()
    print(f"{archive}: SHA256 {checksum} ({len(inputs())} files)")
