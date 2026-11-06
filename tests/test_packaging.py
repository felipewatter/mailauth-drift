from __future__ import annotations

import importlib.util
from pathlib import Path


def _load_module(name: str, file: Path):
    spec = importlib.util.spec_from_file_location(name, file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_reproducible_zip_and_sha(tmp_path):
    root = Path(__file__).resolve().parents[1]
    pkg = _load_module("mailauth_packaging", root / "scripts/package.py")
    verify = _load_module("mailauth_verification", root / "scripts/verify_package.py")
    before, name = pkg.build()
    second, same_name = pkg.build()
    assert before == second
    assert name == same_name
    assert verify.verify() >= 25
    assert all(f.name != ".coverage" for f in pkg.inputs())


def test_package_excludes_sensitive_files(tmp_path):
    root = Path(__file__).resolve().parents[1]
    pkg = _load_module("mailauth_packaging_sec", root / "scripts/package.py")
    injected = [root / "internal-secrets.json", root / "src" / "private.key", root / "src" / ".env.test"]
    try:
        for f in injected:
            f.write_text("not-real-test-key")
        names = [p.name for p in pkg.inputs()]
        assert not any(p.name in names for p in injected)
    finally:
        for f in injected:
            f.unlink(missing_ok=True)
