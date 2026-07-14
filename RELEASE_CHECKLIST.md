# Release checklist (mrma)

## Quality gates
- [ ] `pytest` passes
- [ ] branch coverage meets the configured floor
- [ ] `ruff check mrma tests` passes
- [ ] `mypy` passes for the experiment, transport, comparison, privacy, and sender core
- [ ] `python -m compileall mrma` passes
- [ ] wheel and sdist pass `twine check`
- [ ] clean virtualenv installs the built wheel and passes `pip check`
- [ ] `pip-audit` reports no known vulnerable runtime dependency
- [ ] CI passes on Python 3.10 and 3.13 across Linux, Windows, and macOS

## Versioning
- [ ] `python -c "import mrma; print(mrma.__version__)"` matches `pyproject.toml`
- [ ] `mrma --version` matches `pip show mrma`

## CLI sanity (smoke)
- [ ] `mrma --help` shows commands
- [ ] `mrma config --json` works
- [ ] `mrma run --url https://example.com --follow-redirects` works
- [ ] `mrma experiment` detects a deterministic local mutation
- [ ] `mrma experiment --json` emits schema-valid `mrma.experiment/v4` without decoration
- [ ] cookie state does not cross observations in default isolated mode
- [ ] response limits and transport failures produce typed evidence instead of crashes
- [ ] redirect and retry traces affect verdicts when final responses are identical
- [ ] equivalent redirect targets and parsed response headers do not create false signals
- [ ] retry error subtypes are decision-bearing while timing remains quantitative context
- [ ] assurance presets, profiles, and structured limitations satisfy v4 cross-field constraints
- [ ] durable evidence mode syncs the file and the parent directory where supported
- [ ] every connection mode passes its state and pool-isolation tests
- [ ] exit codes `10` and `11` match the documented `--fail-on` policy
- [ ] unstable local controls produce `INCONCLUSIVE`
- [ ] `mrma impact --url https://example.com --follow-redirects --top-deltas 5` works
- [ ] `mrma report --url https://example.com --follow-redirects --top-deltas 10` writes `mrma_report.json` + `mrma_report.md`

## Docs
- [ ] README examples tested (copy/paste)
- [ ] Authorized-use note present
- [ ] Transport mode and limitations are stated
- [ ] Result dimensions are not presented as severity or exploitability
- [ ] release tag is cut only after all quality, CodeQL, and container checks pass on its commit
- [ ] base image digest and hash-locked container requirements are current and reviewed
