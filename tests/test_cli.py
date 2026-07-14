from mrma.cli import _redacted_target_metadata
from mrma.core.raw_request import RawRequest


def test_experiment_target_metadata_redacts_credentials_and_query():
    request = RawRequest(
        method="GET",
        path="/account?token=secret",
        http_version="HTTP/1.1",
        headers=[("Host", "example.test")],
        body=b"",
    )

    metadata = _redacted_target_metadata("https://user:password@example.test:8443", request)

    assert metadata["origin"] == "https://example.test:8443"
    assert metadata["path"] == "/account"
    assert metadata["query_present"] is True
    assert "query_sha256" in metadata
    assert "secret" not in str(metadata)
