from mrma.core.stability import measure_stability


def test_stability_applies_nextjs_normalization():
    bodies = iter(
        [
            b'{"buildId":"first","value":"stable"}',
            b'{"buildId":"second","value":"stable"}',
        ]
    )

    report = measure_stability(lambda: (200, next(bodies)), repeats=2, preset="nextjs")

    assert report.sim_min == 1.0
    assert report.sim_avg == 1.0
