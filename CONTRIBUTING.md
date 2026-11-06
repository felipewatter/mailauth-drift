# Contributing

Open an issue before proposing a large change. For patches:

1. Create a virtual environment with Python 3.11 or newer.
2. Install tools: `python -m pip install -e '.[dev]'`.
3. Run `ruff check .`, `python -m compileall -q src scripts tests`, `pytest -q`.
4. Run `python scripts/package.py && python scripts/verify_package.py`.
5. Include positive, negative, malformed, and regression fixtures; avoid snapshots from real clients.
6. Document any approximation to protocol behavior prominently. Never claim a live DNS/SPF/DKIM verification unless implemented and tested.

Security reports must use the private advisory channel in SECURITY.md.
