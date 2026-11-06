from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def baseline():
    return json.loads((ROOT / "examples" / "baseline.json").read_text(encoding="utf-8"))


@pytest.fixture
def candidate():
    return json.loads((ROOT / "examples" / "candidate.json").read_text(encoding="utf-8"))


@pytest.fixture
def modify():
    return lambda obj: copy.deepcopy(obj)
