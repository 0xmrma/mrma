from pathlib import Path

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 CI exercises this branch.
    import tomli as tomllib


def _requirements_by_name(values: list[str]) -> dict[str, Requirement]:
    requirements: dict[str, Requirement] = {}
    for value in values:
        requirement = Requirement(value)
        name = canonicalize_name(requirement.name)
        assert name not in requirements, f"duplicate dependency declaration: {name}"
        requirements[name] = requirement
    return requirements


def test_runtime_audit_manifest_matches_published_dependencies():
    project = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    published = _requirements_by_name(project["project"]["dependencies"])
    audit_lines = [
        line.strip()
        for line in Path("requirements-audit.txt").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    audited = _requirements_by_name(audit_lines)

    assert audited == published
