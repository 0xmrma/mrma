from hypothesis import given
from hypothesis import strategies as st

from mrma.core.experiment import wilson_interval


@given(total=st.integers(min_value=1, max_value=50), data=st.data())
def test_wilson_interval_is_bounded_and_contains_observed_rate(total, data):
    successes = data.draw(st.integers(min_value=0, max_value=total))
    low, high = wilson_interval(successes, total)
    observed = successes / total

    assert 0.0 <= low <= observed <= high <= 1.0
