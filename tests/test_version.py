import hashlib
import json
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 CI exercises this branch.
    import tomli as tomllib

from mrma import __version__


def test_runtime_and_package_versions_match():
    project = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    assert project["project"]["version"] == __version__


def test_published_v2_schema_contract_is_immutable():
    schema = json.loads(
        Path("mrma/schemas/experiment-v2.schema.json").read_text(encoding="utf-8")
    )
    canonical = json.dumps(schema, sort_keys=True, separators=(",", ":")).encode()

    assert hashlib.sha256(canonical).hexdigest() == (
        "e3ad9c0976370a2585c61afdbb08433b0f89cda373050407e802ec02cfb34d06"
    )


def test_published_v3_schema_contract_is_immutable():
    schema = json.loads(
        Path("mrma/schemas/experiment-v3.schema.json").read_text(encoding="utf-8")
    )
    canonical = json.dumps(schema, sort_keys=True, separators=(",", ":")).encode()

    assert hashlib.sha256(canonical).hexdigest() == (
        "2c293418ddfc42916aa4402acfa9aa22033c68f20f53a549da2bfbe94cc221e9"
    )


def test_published_v4_schema_contract_is_immutable():
    schema = json.loads(
        Path("mrma/schemas/experiment-v4.schema.json").read_text(encoding="utf-8")
    )
    canonical = json.dumps(schema, sort_keys=True, separators=(",", ":")).encode()

    assert hashlib.sha256(canonical).hexdigest() == (
        "9657ec9f1d1be555386878de6d07ea9d9fa12b568ff9d005c725953c93bff648"
    )
