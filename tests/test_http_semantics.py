import pytest
from hypothesis import given
from hypothesis import strategies as st

from mrma.core.http_semantics import (
    canonical_header_values,
    canonical_uri,
    content_type_media_type,
    header_semantic_ambiguities,
)


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
    assert canonical_header_values("allow", ("GET, POST",)) == canonical_header_values(
        "allow", ("POST", "GET")
    )
    assert canonical_header_values("allow", ("GET",)) != canonical_header_values(
        "allow", ("get",)
    )
    assert canonical_header_values(
        "access-control-allow-methods", ("PATCH",)
    ) != canonical_header_values("access-control-allow-methods", ("patch",))
    assert canonical_header_values("vary", ("Accept-Encoding",)) == canonical_header_values(
        "vary", ("accept-encoding",)
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


def test_ambiguous_cache_control_preserves_duplicate_order_and_malformed_fields():
    first = ("max-age=0, max-age=3600",)
    reversed_order = ("max-age=3600, max-age=0",)
    malformed = ('private="Set-Cookie',)

    assert canonical_header_values("cache-control", first) != canonical_header_values(
        "cache-control", reversed_order
    )
    assert header_semantic_ambiguities("cache-control", first) == ("duplicate-directive",)
    assert header_semantic_ambiguities("cache-control", malformed) == ("malformed-syntax",)


def test_content_type_requires_one_well_formed_declared_media_type():
    assert content_type_media_type(()) is None
    assert content_type_media_type(("Text/Plain; charset=utf-8",)) == "text/plain"
    assert content_type_media_type(("text/plain", "application/json")) is None
    assert content_type_media_type(("not-a-media-type",)) is None
    assert header_semantic_ambiguities(
        "content-type", ("text/plain", "application/json")
    ) == ("multiple-values",)
    assert header_semantic_ambiguities("content-type", ('text/plain; charset="',)) == (
        "malformed-syntax",
    )


@given(
    st.lists(
        st.sampled_from(["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]),
        min_size=1,
        max_size=6,
        unique=True,
    )
)
def test_method_set_order_is_irrelevant_but_token_case_is_not(methods):
    forward = (", ".join(methods),)
    reverse = tuple(reversed(methods))

    assert canonical_header_values("allow", forward) == canonical_header_values(
        "allow", reverse
    )
    assert canonical_header_values("allow", (methods[0],)) != canonical_header_values(
        "allow", (methods[0].lower(),)
    )


@given(
    st.sampled_from(["max-age", "s-maxage", "stale-while-revalidate"]),
    st.integers(min_value=0, max_value=86_400),
    st.integers(min_value=0, max_value=86_400),
)
def test_duplicate_cache_directive_order_remains_decision_bearing(name, first, second):
    if first == second:
        return
    left = (f"{name}={first}, {name}={second}",)
    right = (f"{name}={second}, {name}={first}",)

    assert canonical_header_values("cache-control", left) != canonical_header_values(
        "cache-control", right
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
