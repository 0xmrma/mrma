from mrma.core.compare import (
    EquivalenceConfig,
    equivalent_response,
    resolve_equivalence_policy,
)


def test_equivalent_same_body():
    cfg = EquivalenceConfig(min_similarity=0.99, max_len_delta_ratio=0.01, preset="default")
    r = equivalent_response(200, b"hello", 200, b"hello", cfg)
    assert r.equivalent is True


def test_not_equivalent_status_change_when_required():
    cfg = EquivalenceConfig(require_same_status=True)
    r = equivalent_response(200, b"a", 403, b"a", cfg)
    assert r.equivalent is False


def test_ignore_body_regex_makes_equivalent():
    cfg = EquivalenceConfig(
        min_similarity=0.99,
        max_len_delta_ratio=0.50,
        preset="default",
        ignore_body_regex=(r"token=\w+",),
    )
    a = b"token=ABC123\nok"
    b = b"token=ZZZ999\nok"
    r = equivalent_response(200, a, 200, b, cfg)
    assert r.equivalent is True


def test_resolved_policy_merges_and_deduplicates_preset_rules():
    policy = resolve_equivalence_policy(
        EquivalenceConfig(
            preset="nextjs",
            ignore_headers=("X-Vercel-Id", "x-custom"),
            ignore_body_regex=(r'"nonce"',),
        )
    )

    assert policy.ignore_headers.count("x-vercel-id") == 1
    assert "x-custom" in policy.ignore_headers
    assert policy.ignore_body_regex


def test_large_text_comparison_is_cpu_bounded():
    body_a = b"a" * (256 * 1024 + 1)
    body_b = b"b" * (256 * 1024 + 1)
    result = equivalent_response(200, body_a, 200, body_b, EquivalenceConfig())
    assert result.comparator == "bounded-size"
    assert result.equivalent is False


def test_invalid_body_ignore_regex_is_rejected():
    try:
        resolve_equivalence_policy(EquivalenceConfig(ignore_body_regex=("[",)))
    except ValueError as exc:
        assert "invalid ignore_body_regex" in str(exc)
    else:
        raise AssertionError("invalid regex was accepted")
