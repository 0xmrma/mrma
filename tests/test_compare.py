from mrma.core.compare import EquivalenceConfig, equivalent_response


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
