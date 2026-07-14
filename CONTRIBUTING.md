# Contributing

MRMA changes are reviewed as changes to an experimental instrument, not only as CLI features.

Every experiment-engine change should state the hypothesis it tests, preserve negative and
unstable controls, define incomplete-evidence behavior, record effective configuration, and avoid
claiming exploitability or severity from influence alone.

Run the local gates before opening a pull request:

```bash
python -m pip install -e ".[dev]"
python -m ruff check mrma tests
python -m mypy mrma/core/compare.py mrma/core/experiment.py mrma/core/http_client.py mrma/core/privacy.py mrma/core/sender.py
python -m pytest --cov=mrma.core.compare --cov=mrma.core.experiment --cov=mrma.core.http_client --cov=mrma.core.privacy --cov=mrma.core.sender --cov-fail-under=85
python -m build
python -m twine check dist/*
```

Tests for evidence changes should include a stable negative control, an unstable or incomplete
case, and the machine-output contract. Network integration tests must use loopback fixtures; do not
send CI traffic to public targets.
