# Release checklist (mrma)

## Quality gates
- [ ] `pytest` passes
- [ ] `ruff check mrma tests` passes
- [ ] `python -m compileall mrma` passes
- [ ] clean virtualenv install succeeds with `pip install .`
- [ ] CI passes on Python 3.10 and 3.13 across Linux, Windows, and macOS

## Versioning
- [ ] `python -c "import mrma; print(mrma.__version__)"` matches `pyproject.toml`
- [ ] `mrma --version` matches `pip show mrma`

## CLI sanity (smoke)
- [ ] `mrma --help` shows commands
- [ ] `mrma config --json` works
- [ ] `mrma run --url https://example.com --follow-redirects` works
- [ ] `mrma experiment` detects a deterministic local mutation
- [ ] `mrma experiment --json` emits `mrma.experiment/v1` without terminal decoration
- [ ] unstable local controls produce `INCONCLUSIVE`
- [ ] `mrma impact --url https://example.com --follow-redirects --top-deltas 5` works
- [ ] `mrma report --url https://example.com --follow-redirects --top-deltas 10` writes `mrma_report.json` + `mrma_report.md`

## Docs
- [ ] README examples tested (copy/paste)
- [ ] Authorized-use note present
- [ ] Transport mode and limitations are stated
- [ ] Result dimensions are not presented as severity or exploitability
