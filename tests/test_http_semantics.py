import pytest

from mrma.core.http_semantics import canonical_header_values, canonical_uri


def test_equivalent_redirect_references_have_one_canonical_target():
    base = "https://example.com/start/index"
    expected = "https://example.com/login?next=~user"

    assert canonical_uri("/a/../login?next=%7euser", base_url=base) == expected
    assert canonical_uri("https://EXAMPLE.com:443/%6cogin?next=~user") == expected


def test_uri_normalization_preserves_semantically_relevant_query_order_and_slashes():
    assert canonical_uri("https://example.com") == "https://example.com/"
    assert canonical_uri("https://example.com/a//b") == "https://example.com/a//b"
    assert canonical_uri("https://example.com/?a=1&b=2") != canonical_uri(
        "https://example.com/?b=2&a=1"
    )


@pytest.mark.parametrize(
    ("reference", "expected"),
    [
        ("https://example.com/a/b/./../../c/.", "https://example.com/c/"),
        ("https://example.com/a/b/../..", "https://example.com/"),
        ("https://example.com/a/./b/../c", "https://example.com/a/c"),
        ("https://user:pa%73s@EXAMPLE.com:443/a", "https://user:pass@example.com/a"),
        ("https://münich.example/%41", "https://xn--mnich-kva.example/A"),
    ],
)
def test_uri_canonicalization_covers_dot_segments_userinfo_and_idna(reference, expected):
    assert canonical_uri(reference) == expected


def test_invalid_uri_port_is_preserved_conservatively():
    value = "https://example.com:bad/x"

    assert canonical_uri(value) == value


def test_field_registry_handles_token_sets_cache_directives_and_uri_references():
    assert canonical_header_values("allow", ("GET, post",)) == canonical_header_values(
        "allow", ("POST", "get")
    )
    assert canonical_header_values(
        "cache-control", ('no-cache, private="Set-Cookie, Authorization"',)
    ) == canonical_header_values(
        "cache-control", ('private="Set-Cookie, Authorization"', "no-cache")
    )
    assert canonical_header_values(
        "location", ("/login",), base_url="https://example.com/start"
    ) == canonical_header_values(
        "location", ("https://EXAMPLE.com:443/login",), base_url="https://example.com/start"
    )


def test_cache_control_parser_preserves_escaped_commas_inside_quoted_values():
    combined = ('private="field\\",one", max-age=60',)
    split = ('max-age="60"', 'private="field\\",one"')

    assert canonical_header_values("cache-control", combined) == canonical_header_values(
        "cache-control", split
    )


def test_unknown_and_set_cookie_fields_remain_conservative_and_ordered():
    first = ("a=1; Path=/", "b=2; Path=/")
    second = tuple(reversed(first))

    assert canonical_header_values("set-cookie", first) != canonical_header_values(
        "set-cookie", second
    )
    assert canonical_header_values("x-unknown", ("A", "B")) != canonical_header_values(
        "x-unknown", ("B", "A")
    )
