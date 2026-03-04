from mrma.core.raw_request import parse_raw_http_request


def test_parse_simple_get():
    req = parse_raw_http_request("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    assert req.method == "GET"
    assert req.path == "/"
    assert any(k.lower() == "host" for k, _ in req.headers)
