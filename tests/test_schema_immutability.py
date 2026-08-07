from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

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
    7: (
        "0938215c78446a930b412cec079b2262e38d2770d3b82603dab4afd7e30cc683",
        "29c501bb27f63775c709cf24ff8343cd3dba8ef9f2ebf27c5e639e86212d4169",
    ),
}


def test_experiment_v2_through_v7_are_byte_and_semantically_immutable():
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


def test_authorization_v1_is_byte_and_semantically_immutable():
    raw = Path("mrma/schemas/authorization-v1.schema.json").read_bytes()
    repository_bytes = raw.replace(b"\r\n", b"\n")
    canonical = json.dumps(
        json.loads(raw),
        sort_keys=True,
        separators=(",", ":"),
    ).encode()

    assert hashlib.sha256(repository_bytes).hexdigest() == (
        "ed131358e40dd5312087eb16bd1487b9645e77aed2c833d2feadbd26969864ff"
    )
    assert hashlib.sha256(canonical).hexdigest() == (
        "d1fae6b6d22f3ec6d708359f398c3550b07e3d5155f2e62bf889437453c3a8c1"
    )


@pytest.mark.parametrize(
    ("path", "raw_expected", "canonical_expected"),
    [
        (
            "mrma/schemas/benchmark-v1.schema.json",
            "c45f4a0d0acddf10f4b53767bd7c6188772d06feea6cfeb347d4bf210a395c95",
            "ec4cf2c56d9007003c1fd6ee23691dc823d0e9198c4f3f97f9848cf7ae815c5c",
        ),
        (
            "mrma/schemas/benchmark-v2.schema.json",
            "014f7c0b7e3490b6ff44cbb6f256af659ae445e3cb7d9a3ebb1618d7bbb8df9c",
            "359ffd90270ac1361be2fc08bb1d0ea962325f9f94822d2a8f78d81f8ea88f61",
        ),
        (
            "mrma/schemas/authorization-v2.schema.json",
            "4ef879a31ea5a092aa998da3e722a6c12f26db3151e77048b09158ad1987aa04",
            "c28c21d084f3eff4f9d95279fd16281dfeb5bb4316d9842c4073deffa3902e22",
        ),
        (
            "mrma/schemas/experiment-v8.schema.json",
            "f4fd01242049d77e63256c9f21ac88eb6f81366146f22ba118a0186b6fb40c5b",
            "b06a1ea651142b0428f03be60c7e3dfa4e50e965a5e0f7c4e4ee52b1eaf1268f",
        ),
        (
            "mrma/schemas/experiment-v9.schema.json",
            "0df4da87d92c8a51e28276451af7ad71644b07a56261e81fbc9ac5d31c918363",
            "4d088c206d35e554136a527e92593909424ef513aa211ab96a4aa96908d575a1",
        ),
    ],
)
def test_published_public_schemas_are_byte_and_semantically_immutable(
    path: str,
    raw_expected: str,
    canonical_expected: str,
):
    raw = Path(path).read_bytes()
    repository_bytes = raw.replace(b"\r\n", b"\n")
    canonical = json.dumps(
        json.loads(raw),
        sort_keys=True,
        separators=(",", ":"),
    ).encode()

    assert hashlib.sha256(repository_bytes).hexdigest() == raw_expected
    assert hashlib.sha256(canonical).hexdigest() == canonical_expected
