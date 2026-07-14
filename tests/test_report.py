from mrma.core.report import render_md_report


def test_report_keeps_signal_dimensions_separate():
    report = render_md_report(
        {
            "target": {"url": "https://example.test"},
            "generated_at": "2026-01-01T00:00:00+00:00",
            "signal_summary": {
                "summary": "Observed dimensions are not severity.",
                "breakdown": {
                    "impact_changed": 2,
                    "proxy_trust_changed": 1,
                },
                "signals": ["proxy trust: 1 case changed"],
            },
        }
    )

    assert "## Observed signals" in report
    assert "impact_changed: `2`" in report
    assert "Trust boundary score" not in report
    assert "Severity:" not in report
