from __future__ import annotations

import re
from pathlib import Path

from packaging.requirements import Requirement
from packaging.version import Version

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 compatibility branch
    import tomli as tomllib


def _minimum(requirement: Requirement) -> Version | None:
    candidates = []
    for specifier in requirement.specifier:
        if specifier.operator in {">=", ">", "==", "~="} and "*" not in specifier.version:
            candidates.append(Version(specifier.version))
    return max(candidates) if candidates else None


def _audit_requirements() -> list[Requirement]:
    return [
        Requirement(line)
        for raw in Path("requirements-audit.txt").read_text(encoding="utf-8").splitlines()
        if (line := raw.strip()) and not line.startswith("#")
    ]


def test_audit_security_floors_cannot_exceed_published_dependency_floors():
    project = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))["project"]
    published = {Requirement(value).name.lower(): Requirement(value) for value in project["dependencies"]}
    for audited in _audit_requirements():
        packaged = published[audited.name.lower()]
        assert packaged.marker == audited.marker
        audit_minimum = _minimum(audited)
        package_minimum = _minimum(packaged)
        if audit_minimum is not None:
            assert package_minimum is not None
            assert package_minimum >= audit_minimum


def test_container_lock_includes_bounded_regex_runtime_for_both_architectures():
    lock = Path("requirements-container.txt").read_text(encoding="utf-8")
    assert "regex==2026.7.10" in lock
    block = lock.split("regex==2026.7.10", 1)[1].split("\nrich==", 1)[0]
    hashes = re.findall(r"--hash=sha256:([0-9a-f]{64})", block)
    assert len(hashes) == 2
