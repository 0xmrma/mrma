# MRMA v0.4.2 release checklist

## Correctness and security

- [ ] Every network command is covered by the architectural policy-boundary test.
- [ ] Authorization, budget, redirect, retry, hook, journal, privacy, and partial-result adversarial tests pass.
- [ ] `mrma.experiment/v8`, authorization v2, benchmark v2, and all negative fixtures validate.
- [ ] Experiment schemas v2-v8, authorization v1-v2, and benchmark v1-v2 match immutable SHA-256 fixtures.
- [ ] The 22-case loopback benchmark passes with zero false positives/negatives.
- [ ] Critical semantic mutation gate kills all 24 committed mutants.
- [ ] No unresolved P0/P1 correctness, authorization, evidence, or secret-exposure issue remains.

## Quality gates

- [ ] Full test suite passes on Linux, Windows, macOS and Python 3.10/3.13.
- [ ] `ruff check mrma tests tools` passes.
- [ ] Strict mypy passes for all 19 v0.4 modules; corrected-core mypy passes.
- [ ] Whole-repository branch coverage is published honestly.
- [ ] Every gated v0.4 runtime module is at least 90%; combined critical coverage is at least 90%.
- [ ] Corrected-core branch coverage remains at least 85%.
- [ ] `python -m compileall -q mrma` passes.
- [ ] Runtime `pip-audit` passes on Python 3.10 and 3.13.
- [ ] CodeQL passes.

## Distribution and container

- [ ] Version is `0.4.2` in package metadata, import, CLI, wheel, and container.
- [ ] Wheel and sdist build from a clean tree and pass `twine check`.
- [ ] Clean wheel install passes `pip check` outside the source tree.
- [ ] Clean wheel contains experiment v2-v8, authorization v1-v2, benchmark v1-v2, and release baseline.
- [ ] Non-root container builds from digest-pinned base and hash-locked dependencies.
- [ ] Container smoke, local authorized experiment, bundle creation, and offline verification pass.
- [ ] Multi-architecture OCI publication includes provenance and SBOM; final digest is recorded.

## Documentation and governance

- [ ] README, SECURITY, ROADMAP, CHANGELOG, validation guide, and all model docs agree.
- [ ] Product claims remain limited to implemented and verified behavior.
- [ ] Semantic HTTP, unsigned authorization, DNS/socket binding, exploratory legacy, and hash-chain trust limitations are explicit.
- [ ] Protected PR checks and review complete without weakening rules.
- [ ] Release commit is clean; annotated tag is SSH-signed and accepted by release signer policy.
- [ ] Protected release environment gates package/container publication.
- [ ] GitHub release assets, attestations, hashes, OCI index, and digest verify independently.

## Final report

- [ ] Record release commit/tag, test/coverage/mutation results, dependency checks, wheel/sdist hashes,
  OCI digest, evidence verification, migration status, deferred work, and exact release claims.
