from hypothesis import given
from hypothesis import strategies as st

from mrma.core.experiment import operating_characteristics, wilson_interval
from mrma.core.http_semantics import canonical_uri


@given(total=st.integers(min_value=1, max_value=50), data=st.data())
def test_wilson_interval_is_bounded_and_contains_observed_rate(total, data):
    successes = data.draw(st.integers(min_value=0, max_value=total))
    low, high = wilson_interval(successes, total)
    observed = successes / total

    assert 0.0 <= low <= observed <= high <= 1.0


@given(rounds=st.integers(min_value=6, max_value=50))
def test_operating_characteristics_are_exact_threshold_boundaries(rounds):
    result = operating_characteristics(rounds, 0.8, 0.2, 0.2, rounds)
    positive = result["positive_min_changed"]
    negative = result["negative_max_changed"]

    if positive is not None:
        assert wilson_interval(positive, rounds)[0] >= 0.8
        if positive > 0:
            assert wilson_interval(positive - 1, rounds)[0] < 0.8
    if negative is not None:
        assert wilson_interval(negative, rounds)[1] <= 0.2
        if negative < rounds:
            assert wilson_interval(negative + 1, rounds)[1] > 0.2


@given(octet=st.sampled_from(["41", "61", "2D", "2E", "5F", "7E"]))
def test_unreserved_percent_encoding_is_canonicalized(octet):
    character = chr(int(octet, 16))

    assert canonical_uri(f"https://example.test/%{octet.lower()}") == canonical_uri(
        f"https://example.test/{character}"
    )


@given(
    segments=st.lists(
        st.sampled_from(["a", "b", ".", "..", "%41", "%7e", ""]),
        min_size=1,
        max_size=12,
    )
)
def test_canonical_redirect_targets_are_idempotent(segments):
    target = "https://EXAMPLE.test:443/" + "/".join(segments)
    canonical = canonical_uri(target)

    assert canonical_uri(canonical) == canonical
