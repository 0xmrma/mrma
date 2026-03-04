# Release checklist (mrma)

## Quality gates
- [ ] `pytest` passes
- [ ] `ruff check mrma tests` passes
- [ ] `python -m compileall mrma` passes

## Versioning
- [ ] `python -c "import mrma; print(mrma.__version__)"` matches `pyproject.toml`
- [ ] `mrma --version` matches `pip show mrma`

## CLI sanity (smoke)
- [ ] `mrma --help` shows commands
- [ ] `mrma config --json` works
- [ ] `mrma run --url https://example.com --follow-redirects` works
- [ ] `mrma impact --url https://example.com --follow-redirects --top-deltas 5` works
- [ ] `mrma report --url https://example.com --follow-redirects --top-deltas 10` writes `mrma_report.json` + `mrma_report.md`

## Docs
- [ ] README examples tested (copy/paste)
- [ ] Authorized-use note present
