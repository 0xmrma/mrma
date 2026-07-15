from __future__ import annotations

import hashlib
import json
from pathlib import Path

EXPECTED = {
    2: (
        "305bf1192b70b249683d4f11db074f2ec0fd89164283010875c96b65fa2a552e",
        "e3ad9c0976370a2585c61afdbb08433b0f89cda373050407e802ec02cfb34d06",
    ),
    3: (
        "fb91f542e418a130c4c8f8c22a69f6e14522e45c2a92e6b47fb67dcd9e217406",
        "2c293418ddfc42916aa4402acfa9aa22033c68f20f53a549da2bfbe94cc221e9",
    ),
    4: (
        "76c6fbd05280746f976131185ba65f81e00fff1e58d4123dcef8c8b8993f0412",
        "9657ec9f1d1be555386878de6d07ea9d9fa12b568ff9d005c725953c93bff648",
    ),
    5: (
        "8674aede093a1b9bf903f57df3dab014e3dc60a6f1fce667ee5eab6da36073b6",
        "ccba85b25067a43f091797771b0fb82eee9a15c9f6c8ff30804b7fc79cb77cfa",
    ),
    6: (
        "0e43e4e3bdc6fa6619ea47886081a377272c11a2377652fbbe3765e6c8e7da65",
        "a782a82858c36eb8945f72b77dfa6f24e49767306d12a89bfafbeab2acd31d96",
    ),
}


def test_experiment_v2_through_v6_are_byte_and_semantically_immutable():
    for version, (raw_expected, canonical_expected) in EXPECTED.items():
        raw = Path(f"mrma/schemas/experiment-v{version}.schema.json").read_bytes()
        # Existing Windows worktrees may retain Git's historical CRLF checkout conversion.
        repository_bytes = raw.replace(b"\r\n", b"\n")
        assert b"\r" not in repository_bytes
        canonical = json.dumps(
            json.loads(raw),
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        assert hashlib.sha256(repository_bytes).hexdigest() == raw_expected
        assert hashlib.sha256(canonical).hexdigest() == canonical_expected
