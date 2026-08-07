from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import socket
import threading
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from mrma.core.http_semantics import canonical_uri, origin_base_url, semantic_request_url
from mrma.core.raw_request import RawRequest

from .budget import BudgetError, BudgetLimits
from .method_risk import RISK_RANK, classify_method

AUTHORIZATION_SCHEMA_VERSION = "mrma.authorization/v2"
SUPPORTED_AUTHORIZATION_SCHEMAS = frozenset(
    {"mrma.authorization/v1", AUTHORIZATION_SCHEMA_VERSION}
)
AUTHORIZATION_POLICY_VERSION = "authorization-policy/2.2"

Resolver = Callable[[str, int], Sequence[str]]
_HTTP_METHOD = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")


class AuthorizationError(RuntimeError):
    mrma_fatal_policy_error = True

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(f"{code}: {message}")


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise AuthorizationError("DUPLICATE_MANIFEST_KEY", f"duplicate key {key!r}")
        result[key] = value
    return result


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("ascii")


def _reject_constant(value: str) -> None:
    raise AuthorizationError("NONFINITE_NUMBER", value)


def _canonical_host(value: str) -> str:
    host = value.strip().rstrip(".").lower()
    if (
        not host
        or any(character in host for character in "*\\%")
        or any(ord(character) < 0x21 or ord(character) == 0x7F for character in host)
    ):
        raise AuthorizationError("INVALID_HOST", "authorization hosts must be exact names")
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    if not host.isascii():
        raise AuthorizationError(
            "NON_ASCII_HOST_REJECTED",
            "authorization hosts must be explicit ASCII A-labels",
        )
    labels = host.split(".")
    if (
        len(host) > 253
        or any(
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or re.fullmatch(r"[a-z0-9-]+", label) is None
            for label in labels
        )
    ):
        raise AuthorizationError("INVALID_HOST", "authorization host labels are malformed")
    return host


def _parse_time(value: str, field: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise AuthorizationError("INVALID_TIME", f"{field} must be RFC 3339 compatible") from exc
    if parsed.tzinfo is None:
        raise AuthorizationError("INVALID_TIME", f"{field} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _expect_keys(value: Mapping[str, object], *, allowed: set[str], required: set[str], name: str) -> None:
    extras = set(value) - allowed
    missing = required - set(value)
    if extras:
        raise AuthorizationError("UNKNOWN_MANIFEST_FIELD", f"{name} contains {sorted(extras)[0]!r}")
    if missing:
        raise AuthorizationError("MISSING_MANIFEST_FIELD", f"{name} requires {sorted(missing)[0]!r}")


def _strings(value: object, field: str, *, nonempty: bool = True) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise AuthorizationError("INVALID_MANIFEST_FIELD", f"{field} must be an array of strings")
    if nonempty and not value:
        raise AuthorizationError("INVALID_MANIFEST_FIELD", f"{field} cannot be empty")
    if len(value) != len(set(value)):
        raise AuthorizationError("INVALID_MANIFEST_FIELD", f"{field} cannot contain duplicates")
    return tuple(value)


def _methods(value: object, field: str, *, nonempty: bool = True) -> tuple[str, ...]:
    methods = _strings(value, field, nonempty=nonempty)
    if any(_HTTP_METHOD.fullmatch(method) is None for method in methods):
        raise AuthorizationError(
            "INVALID_HTTP_METHOD",
            f"{field} must contain exact case-sensitive HTTP method tokens",
        )
    return methods


def _integers(value: object, field: str) -> tuple[int, ...]:
    if not isinstance(value, list) or not value or any(
        not isinstance(item, int) or isinstance(item, bool) for item in value
    ):
        raise AuthorizationError("INVALID_MANIFEST_FIELD", f"{field} must be a non-empty integer array")
    if len(value) != len(set(value)):
        raise AuthorizationError("INVALID_MANIFEST_FIELD", f"{field} cannot contain duplicates")
    return tuple(value)


def _header_names(value: object, field: str) -> tuple[str, ...]:
    names = _strings(value, field, nonempty=False)
    normalized = tuple(name.lower() for name in names)
    if any(_HTTP_METHOD.fullmatch(name) is None for name in names):
        raise AuthorizationError("INVALID_HEADER_NAME", f"{field} contains an invalid field name")
    if len(normalized) != len(set(normalized)):
        raise AuthorizationError(
            "INVALID_HEADER_NAME", f"{field} duplicates a field name case-insensitively"
        )
    return normalized


def _parse_authority(value: str, *, default_port: int | None) -> tuple[str, int | None]:
    if (
        value != value.strip()
        or value.endswith(":")
        or any(ord(character) < 0x21 or ord(character) == 0x7F for character in value)
        or any(character in value for character in "/?#@,\\%")
    ):
        raise AuthorizationError("INVALID_HOST_AUTHORITY", "Host authority is malformed")
    try:
        parsed = urlsplit("//" + value)
        host = _canonical_host(parsed.hostname or "")
        port = parsed.port
    except ValueError as exc:
        raise AuthorizationError("INVALID_HOST_AUTHORITY", "Host authority is malformed") from exc
    if parsed.path or parsed.query or parsed.fragment or parsed.username is not None:
        raise AuthorizationError("INVALID_HOST_AUTHORITY", "Host authority is malformed")
    return host, port if port is not None else default_port


def _authority_text(host: str, port: int, scheme: str) -> str:
    display_host = f"[{host}]" if ":" in host else host
    default_port = 443 if scheme == "https" else 80
    return display_host if port == default_port else f"{display_host}:{port}"


def canonical_host_authority(value: str, scheme: str) -> str:
    """Canonicalize one explicit Host field without applying an IDNA mapping."""
    normalized_scheme = scheme.lower()
    if normalized_scheme not in {"http", "https"}:
        raise AuthorizationError("INVALID_HOST_AUTHORITY", "Host requires an HTTP target scheme")
    default_port = 443 if normalized_scheme == "https" else 80
    host, port = _parse_authority(value, default_port=default_port)
    assert port is not None
    return _authority_text(host, port, normalized_scheme)


@dataclass(frozen=True)
class TargetRule:
    schemes: tuple[str, ...]
    hosts: tuple[str, ...]
    ports: tuple[int, ...]
    path_prefixes: tuple[str, ...]
    methods: tuple[str, ...]
    attempt_kinds: tuple[str, ...]
    cidrs: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]
    maximum_request_body_bytes: int
    maximum_repetitions_by_method: tuple[tuple[str, int], ...]
    require_idempotency_key: tuple[str, ...]
    disposable_environment: bool
    query_policy: QueryPolicy

    def repetition_limit(self, method: str) -> int | None:
        return dict(self.maximum_repetitions_by_method).get(method)


@dataclass(frozen=True)
class ProxyPolicy:
    mode: str
    hosts: tuple[str, ...] = ()
    ports: tuple[int, ...] = ()
    cidrs: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = ()


@dataclass(frozen=True)
class QueryPolicy:
    mode: str
    allowed_keys: tuple[str, ...] = ()
    required_keys: tuple[str, ...] = ()
    forbidden_keys: tuple[str, ...] = ()
    maximum_query_bytes: int = 4096


@dataclass(frozen=True)
class AuthorityPolicy:
    mode: str
    allowed_host_fields: tuple[str, ...]
    allow_host_mutation: bool
    allow_duplicate_host: bool
    sni_policy: str
    proxy_connect_authority_policy: str


@dataclass(frozen=True)
class CrossOriginHeaderPolicy:
    mode: str
    allow: tuple[str, ...]


@dataclass(frozen=True)
class RedirectPolicy:
    mode: str
    maximum_depth: int
    cross_origin_headers: CrossOriginHeaderPolicy


@dataclass(frozen=True)
class HeaderMutationPolicy:
    allow_names: tuple[str, ...]
    deny_names: tuple[str, ...]
    operations: tuple[str, ...]
    maximum_value_bytes: int


@dataclass(frozen=True)
class AuthorizationManifest:
    schema_version: str
    engagement_id: str
    issuer: str
    subject: str
    issued_at: datetime
    expires_at: datetime
    rules: tuple[TargetRule, ...]
    proxy: ProxyPolicy
    authority: AuthorityPolicy
    redirects: RedirectPolicy
    mutation_families: tuple[str, ...]
    mutation_risk_classes: tuple[str, ...]
    header_mutations: HeaderMutationPolicy | None
    organizational_metadata: tuple[tuple[str, str], ...]
    budget: Mapping[str, object]
    digest: str

    def public_summary(self, redactor: object | None = None) -> dict[str, object]:
        def fingerprint(value: str, label: str) -> str:
            method = getattr(redactor, "fingerprint", None)
            if callable(method):
                return str(method(value, label=label))
            return f"sha256:{hashlib.sha256(value.encode()).hexdigest()}"

        return {
            "schema_version": self.schema_version,
            "engagement_fingerprint": fingerprint(self.engagement_id, "authorization-engagement"),
            "issuer_fingerprint": fingerprint(self.issuer, "authorization-issuer"),
            "subject_fingerprint": fingerprint(self.subject, "authorization-subject"),
            "expires_at": self.expires_at.replace(microsecond=0).isoformat(),
            "rule_count": len(self.rules),
            "digest": self.digest,
            "policy_version": AUTHORIZATION_POLICY_VERSION,
            "authority_mode": self.authority.mode,
            "host_mutation_authorized": self.authority.allow_host_mutation,
            "cross_origin_header_mode": self.redirects.cross_origin_headers.mode,
            "query_policy_version": "query-policy/1.0",
            "mutation_policy_version": "header-mutation-policy/1.0",
        }


@dataclass(frozen=True)
class AuthorizationDecision:
    accepted: bool
    code: str
    policy_version: str
    manifest_digest: str
    target_fingerprint: str
    address_set_fingerprint: str
    proxy_address_set_fingerprint: str | None
    host_authority_fingerprint: str
    sni_authority_fingerprint: str | None
    proxy_connect_authority_fingerprint: str | None
    canonical_origin: str = field(repr=False)
    method: str
    attempt_kind: str
    effective_risk: str
    budget_policy_digest: str


@dataclass(frozen=True)
class AuthorizedRequestContext:
    decision: AuthorizationDecision
    canonical_url: str = field(repr=False)
    resolved_addresses: tuple[str, ...] = field(repr=False)
    authorized_at: datetime
    rule_index: int
    request_fingerprint: str
    proxy_url: str | None = field(default=None, repr=False)
    effective_host_authority: str = field(default="", repr=False)

    def __post_init__(self) -> None:
        if not self.decision.accepted:
            raise ValueError("an authorized request context requires an accepted decision")


@dataclass(frozen=True)
class MutationValidation:
    family: str
    baseline_fingerprint: str
    mutation_fingerprint: str
    delta_digest: str
    required_operations: tuple[str, ...]
    changed_dimensions: tuple[str, ...] = ()


@dataclass(frozen=True)
class AuthorizedMutationContext(AuthorizedRequestContext):
    mutation: MutationValidation = field(repr=False, kw_only=True)


def _parse_query_policy(value: object, *, required: bool, field: str) -> QueryPolicy:
    if value is None and not required:
        return QueryPolicy(mode="allow-any")
    if not isinstance(value, dict):
        raise AuthorizationError("INVALID_QUERY_POLICY", f"{field} must be an object")
    keys = {
        "mode",
        "allowed_keys",
        "required_keys",
        "forbidden_keys",
        "maximum_query_bytes",
    }
    _expect_keys(value, allowed=keys, required=keys, name=field)
    mode = value["mode"]
    if mode not in {"deny", "allow-any", "explicit"}:
        raise AuthorizationError("INVALID_QUERY_POLICY", f"{field}.mode is invalid")
    allowed = _strings(value["allowed_keys"], f"{field}.allowed_keys", nonempty=False)
    required_keys = _strings(value["required_keys"], f"{field}.required_keys", nonempty=False)
    forbidden = _strings(value["forbidden_keys"], f"{field}.forbidden_keys", nonempty=False)
    maximum_bytes = value["maximum_query_bytes"]
    if (
        not isinstance(maximum_bytes, int)
        or isinstance(maximum_bytes, bool)
        or not 0 <= maximum_bytes <= 65536
    ):
        raise AuthorizationError(
            "INVALID_QUERY_POLICY", f"{field}.maximum_query_bytes must be in 0..65536"
        )
    if set(forbidden) & (set(allowed) | set(required_keys)):
        raise AuthorizationError(
            "INVALID_QUERY_POLICY", f"{field}.forbidden_keys conflicts with allowed keys"
        )
    if mode != "explicit" and (allowed or required_keys):
        raise AuthorizationError(
            "INVALID_QUERY_POLICY", f"{field} only permits allowed/required keys in explicit mode"
        )
    if mode == "deny" and forbidden:
        raise AuthorizationError(
            "INVALID_QUERY_POLICY", f"{field} deny mode does not accept key lists"
        )
    if mode == "explicit" and any(key not in allowed for key in required_keys):
        raise AuthorizationError(
            "INVALID_QUERY_POLICY", f"{field}.required_keys must also be allowed"
        )
    return QueryPolicy(mode, allowed, required_keys, forbidden, maximum_bytes)


def _parse_rule(value: object, index: int, schema_version: str) -> TargetRule:
    if not isinstance(value, dict):
        raise AuthorizationError("INVALID_MANIFEST_FIELD", f"rules[{index}] must be an object")
    allowed = {
        "schemes",
        "hosts",
        "ports",
        "path_prefixes",
        "methods",
        "attempt_kinds",
        "cidrs",
        "maximum_request_body_bytes",
        "maximum_repetitions_by_method",
        "require_idempotency_key",
        "disposable_environment",
    }
    optional = {"maximum_repetitions_by_method", "require_idempotency_key", "disposable_environment"}
    if schema_version == AUTHORIZATION_SCHEMA_VERSION:
        allowed.add("query_policy")
    required = allowed - optional
    _expect_keys(value, allowed=allowed, required=required, name=f"rules[{index}]")
    schemes = tuple(item.lower() for item in _strings(value["schemes"], "schemes"))
    if any(item not in {"http", "https"} for item in schemes):
        raise AuthorizationError("INVALID_SCHEME", "only http and https can be authorized")
    hosts = tuple(_canonical_host(item) for item in _strings(value["hosts"], "hosts"))
    if len(hosts) != len(set(hosts)):
        raise AuthorizationError("INVALID_HOST", "hosts duplicate after canonicalization")
    ports = _integers(value["ports"], "ports")
    if any(not 1 <= item <= 65535 for item in ports):
        raise AuthorizationError("INVALID_PORT", "authorized ports must be in 1..65535")
    paths = _strings(value["path_prefixes"], "path_prefixes")
    if any(not item.startswith("/") or "#" in item or "?" in item for item in paths):
        raise AuthorizationError("INVALID_PATH_SCOPE", "path prefixes must be absolute paths")
    methods = _methods(value["methods"], "methods")
    attempt_kinds = _strings(value["attempt_kinds"], "attempt_kinds")
    valid_attempt_kinds = {
        "control",
        "mutation",
        "retry",
        "redirect",
        "setup",
        "reset",
        "exploratory",
    }
    if any(item not in valid_attempt_kinds for item in attempt_kinds):
        raise AuthorizationError("INVALID_ATTEMPT_KIND", "rule contains an unknown attempt kind")
    cidrs: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for item in _strings(value["cidrs"], "cidrs"):
        try:
            cidrs.append(ipaddress.ip_network(item, strict=True))
        except ValueError as exc:
            raise AuthorizationError("INVALID_CIDR", f"invalid authorized CIDR {item!r}") from exc
    maximum_body = value["maximum_request_body_bytes"]
    if not isinstance(maximum_body, int) or isinstance(maximum_body, bool) or maximum_body < 0:
        raise AuthorizationError("INVALID_BODY_LIMIT", "maximum_request_body_bytes must be non-negative")
    raw_repetitions = value.get("maximum_repetitions_by_method", {})
    if not isinstance(raw_repetitions, dict) or any(
        not isinstance(key, str)
        or not isinstance(count, int)
        or isinstance(count, bool)
        or count < 1
        for key, count in raw_repetitions.items()
    ):
        raise AuthorizationError(
            "INVALID_METHOD_REPETITIONS",
            "maximum_repetitions_by_method must map methods to positive integers",
        )
    idempotency = _methods(
        value.get("require_idempotency_key", []),
        "require_idempotency_key",
        nonempty=False,
    )
    repetition_methods = _methods(
        list(raw_repetitions),
        "maximum_repetitions_by_method",
        nonempty=False,
    )
    if any(method not in methods for method in (*repetition_methods, *idempotency)):
        raise AuthorizationError(
            "INVALID_METHOD_POLICY",
            "repetition and idempotency methods must be present in methods",
        )
    if any(
        classify_method(method).repeat_requires_explicit_authorization
        and method not in repetition_methods
        for method in methods
    ):
        raise AuthorizationError(
            "INVALID_METHOD_POLICY",
            "risky and extension methods require maximum_repetitions_by_method",
        )
    disposable = value.get("disposable_environment", False)
    if not isinstance(disposable, bool):
        raise AuthorizationError("INVALID_MANIFEST_FIELD", "disposable_environment must be boolean")
    if any(kind in {"setup", "reset"} for kind in attempt_kinds) and not disposable:
        raise AuthorizationError(
            "HOOK_ENVIRONMENT_NOT_DISPOSABLE",
            "setup and reset authorization requires disposable_environment",
        )
    return TargetRule(
        schemes=schemes,
        hosts=hosts,
        ports=ports,
        path_prefixes=paths,
        methods=methods,
        attempt_kinds=attempt_kinds,
        cidrs=tuple(cidrs),
        maximum_request_body_bytes=maximum_body,
        maximum_repetitions_by_method=tuple(
            sorted((key, raw_repetitions[key]) for key in repetition_methods)
        ),
        require_idempotency_key=idempotency,
        disposable_environment=disposable,
        query_policy=_parse_query_policy(
            value.get("query_policy"),
            required=schema_version == AUTHORIZATION_SCHEMA_VERSION,
            field=f"rules[{index}].query_policy",
        ),
    )


def load_authorization_manifest(path: str | Path) -> AuthorizationManifest:
    raw = Path(path).read_bytes()
    try:
        payload = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_strict_object,
            parse_constant=_reject_constant,
        )
    except UnicodeDecodeError as exc:
        raise AuthorizationError("INVALID_MANIFEST_ENCODING", "manifest must be UTF-8") from exc
    except json.JSONDecodeError as exc:
        raise AuthorizationError("INVALID_MANIFEST_JSON", str(exc)) from exc
    if not isinstance(payload, dict):
        raise AuthorizationError("INVALID_MANIFEST", "manifest root must be an object")
    schema_version = payload.get("schema_version")
    if schema_version not in SUPPORTED_AUTHORIZATION_SCHEMAS:
        raise AuthorizationError(
            "UNSUPPORTED_AUTHORIZATION_SCHEMA",
            "expected mrma.authorization/v1 or mrma.authorization/v2",
        )
    allowed = {
        "schema_version",
        "engagement_id",
        "issuer",
        "subject",
        "issued_at",
        "expires_at",
        "rules",
        "proxy",
        "redirects",
        "mutation_families",
        "mutation_risk_classes",
        "budget",
        "authorization_digest",
        "organizational_metadata",
    }
    optional = {"authorization_digest", "organizational_metadata"}
    if schema_version == AUTHORIZATION_SCHEMA_VERSION:
        allowed.update({"authority", "mutation_policy"})
    required = allowed - optional
    _expect_keys(payload, allowed=allowed, required=required, name="manifest")
    for field_name in ("engagement_id", "issuer", "subject", "issued_at", "expires_at"):
        if not isinstance(payload[field_name], str) or not payload[field_name]:
            raise AuthorizationError(
                "INVALID_MANIFEST_FIELD", f"{field_name} must be a non-empty string"
            )
    issued_at = _parse_time(payload["issued_at"], "issued_at")
    expires_at = _parse_time(payload["expires_at"], "expires_at")
    if expires_at <= issued_at:
        raise AuthorizationError("INVALID_VALIDITY_WINDOW", "expires_at must follow issued_at")
    raw_rules = payload["rules"]
    if not isinstance(raw_rules, list) or not raw_rules:
        raise AuthorizationError("INVALID_MANIFEST_FIELD", "rules must be a non-empty array")
    rules = tuple(
        _parse_rule(item, index, str(schema_version)) for index, item in enumerate(raw_rules)
    )

    proxy_value = payload["proxy"]
    if not isinstance(proxy_value, dict):
        raise AuthorizationError("INVALID_MANIFEST_FIELD", "proxy must be an object")
    _expect_keys(
        proxy_value,
        allowed={"mode", "hosts", "ports", "cidrs"},
        required={"mode", "hosts", "ports", "cidrs"},
        name="proxy",
    )
    if proxy_value["mode"] not in {"deny", "allow-explicit"}:
        raise AuthorizationError("INVALID_PROXY_POLICY", "proxy mode must be deny or allow-explicit")
    proxy_cidrs: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for item in _strings(proxy_value["cidrs"], "proxy.cidrs", nonempty=False):
        try:
            proxy_cidrs.append(ipaddress.ip_network(item, strict=True))
        except ValueError as exc:
            raise AuthorizationError("INVALID_CIDR", f"invalid proxy CIDR {item!r}") from exc
    proxy = ProxyPolicy(
        mode=proxy_value["mode"],
        hosts=tuple(_canonical_host(item) for item in _strings(proxy_value["hosts"], "proxy.hosts", nonempty=False)),
        ports=_integers(proxy_value["ports"], "proxy.ports") if proxy_value["ports"] else (),
        cidrs=tuple(proxy_cidrs),
    )
    if proxy.mode == "deny" and (proxy.hosts or proxy.ports or proxy.cidrs):
        raise AuthorizationError("INVALID_PROXY_POLICY", "deny proxy policy cannot list endpoints")
    if proxy.mode == "allow-explicit" and not proxy.cidrs:
        raise AuthorizationError(
            "INVALID_PROXY_POLICY", "explicit proxy policy requires authorized CIDRs"
        )
    if proxy.mode == "allow-explicit" and (not proxy.hosts or not proxy.ports):
        raise AuthorizationError(
            "INVALID_PROXY_POLICY",
            "explicit proxy policy requires exact hosts and ports",
        )

    authority_value = payload.get("authority")
    if schema_version == "mrma.authorization/v1":
        authority = AuthorityPolicy(
            mode="match-target",
            allowed_host_fields=(),
            allow_host_mutation=False,
            allow_duplicate_host=False,
            sni_policy="match-target",
            proxy_connect_authority_policy="match-target",
        )
    else:
        if not isinstance(authority_value, dict):
            raise AuthorizationError("INVALID_AUTHORITY_POLICY", "authority must be an object")
        authority_keys = {
            "mode",
            "allowed_host_fields",
            "allow_host_mutation",
            "allow_duplicate_host",
            "sni_policy",
            "proxy_connect_authority_policy",
        }
        _expect_keys(
            authority_value,
            allowed=authority_keys,
            required=authority_keys,
            name="authority",
        )
        if authority_value["mode"] not in {"match-target", "explicit"}:
            raise AuthorizationError("INVALID_AUTHORITY_POLICY", "unknown authority mode")
        allowed_authorities = _strings(
            authority_value["allowed_host_fields"],
            "authority.allowed_host_fields",
            nonempty=authority_value["mode"] == "explicit",
        )
        canonical_authorities = {
            _parse_authority(item, default_port=None) for item in allowed_authorities
        }
        if len(canonical_authorities) != len(allowed_authorities):
            raise AuthorizationError(
                "INVALID_AUTHORITY_POLICY",
                "allowed_host_fields contains canonically duplicate authorities",
            )
        if authority_value["allow_duplicate_host"] is not False:
            raise AuthorizationError(
                "INVALID_AUTHORITY_POLICY", "duplicate Host fields cannot be authorized"
            )
        for field_name in ("allow_host_mutation", "allow_duplicate_host"):
            if not isinstance(authority_value[field_name], bool):
                raise AuthorizationError(
                    "INVALID_AUTHORITY_POLICY", f"authority.{field_name} must be boolean"
                )
        if authority_value["sni_policy"] != "match-target":
            raise AuthorizationError(
                "INVALID_AUTHORITY_POLICY", "semantic HTTP requires SNI to match the target"
            )
        if authority_value["proxy_connect_authority_policy"] != "match-target":
            raise AuthorizationError(
                "INVALID_AUTHORITY_POLICY", "proxy CONNECT authority must match the target"
            )
        authority = AuthorityPolicy(
            mode=str(authority_value["mode"]),
            allowed_host_fields=allowed_authorities,
            allow_host_mutation=bool(authority_value["allow_host_mutation"]),
            allow_duplicate_host=False,
            sni_policy="match-target",
            proxy_connect_authority_policy="match-target",
        )

    redirect_value = payload["redirects"]
    if not isinstance(redirect_value, dict):
        raise AuthorizationError("INVALID_MANIFEST_FIELD", "redirects must be an object")
    if schema_version == "mrma.authorization/v1":
        redirect_keys = {"mode", "maximum_depth", "forward_credentials_cross_origin"}
    else:
        redirect_keys = {"mode", "maximum_depth", "cross_origin_headers"}
    _expect_keys(redirect_value, allowed=redirect_keys, required=redirect_keys, name="redirects")
    if redirect_value["mode"] not in {"deny", "same-origin", "authorized-targets"}:
        raise AuthorizationError("INVALID_REDIRECT_POLICY", "unknown redirect mode")
    if not isinstance(redirect_value["maximum_depth"], int) or not 0 <= redirect_value["maximum_depth"] <= 20:
        raise AuthorizationError("INVALID_REDIRECT_POLICY", "maximum_depth must be in 0..20")
    if schema_version == "mrma.authorization/v1":
        if not isinstance(redirect_value["forward_credentials_cross_origin"], bool):
            raise AuthorizationError(
                "INVALID_REDIRECT_POLICY", "credential forwarding flag must be boolean"
            )
        cross_origin_headers = CrossOriginHeaderPolicy(
            mode="explicit" if redirect_value["forward_credentials_cross_origin"] else "safe-default",
            allow=("*",) if redirect_value["forward_credentials_cross_origin"] else (),
        )
    else:
        cross_origin_value = redirect_value["cross_origin_headers"]
        if not isinstance(cross_origin_value, dict):
            raise AuthorizationError(
                "INVALID_REDIRECT_POLICY", "redirects.cross_origin_headers must be an object"
            )
        _expect_keys(
            cross_origin_value,
            allowed={"mode", "allow"},
            required={"mode", "allow"},
            name="redirects.cross_origin_headers",
        )
        if cross_origin_value["mode"] not in {"safe-default", "explicit"}:
            raise AuthorizationError("INVALID_REDIRECT_POLICY", "unknown cross-origin header mode")
        header_allow = _header_names(
            cross_origin_value["allow"], "redirects.cross_origin_headers.allow"
        )
        if cross_origin_value["mode"] == "safe-default" and header_allow:
            raise AuthorizationError(
                "INVALID_REDIRECT_POLICY", "safe-default mode does not accept additional headers"
            )
        cross_origin_headers = CrossOriginHeaderPolicy(
            mode=str(cross_origin_value["mode"]),
            allow=header_allow,
        )
    redirects = RedirectPolicy(
        str(redirect_value["mode"]),
        int(redirect_value["maximum_depth"]),
        cross_origin_headers,
    )

    mutation_value = payload.get("mutation_policy")
    header_mutations: HeaderMutationPolicy | None = None
    if schema_version == AUTHORIZATION_SCHEMA_VERSION:
        if not isinstance(mutation_value, dict):
            raise AuthorizationError("INVALID_MUTATION_POLICY", "mutation_policy must be an object")
        _expect_keys(
            mutation_value,
            allowed={"headers"},
            required={"headers"},
            name="mutation_policy",
        )
        header_value = mutation_value["headers"]
        if not isinstance(header_value, dict):
            raise AuthorizationError(
                "INVALID_MUTATION_POLICY", "mutation_policy.headers must be an object"
            )
        header_keys = {"allow_names", "deny_names", "operations", "maximum_value_bytes"}
        _expect_keys(
            header_value,
            allowed=header_keys,
            required=header_keys,
            name="mutation_policy.headers",
        )
        allow_names = _header_names(
            header_value["allow_names"], "mutation_policy.headers.allow_names"
        )
        deny_names = _header_names(
            header_value["deny_names"], "mutation_policy.headers.deny_names"
        )
        if set(allow_names) & set(deny_names):
            raise AuthorizationError(
                "INVALID_MUTATION_POLICY", "allowed and denied header names overlap"
            )
        operations = _strings(
            header_value["operations"], "mutation_policy.headers.operations", nonempty=False
        )
        if any(operation not in {"add", "replace", "remove"} for operation in operations):
            raise AuthorizationError("INVALID_MUTATION_POLICY", "unknown header operation")
        maximum_value_bytes = header_value["maximum_value_bytes"]
        if (
            not isinstance(maximum_value_bytes, int)
            or isinstance(maximum_value_bytes, bool)
            or not 0 <= maximum_value_bytes <= 65536
        ):
            raise AuthorizationError(
                "INVALID_MUTATION_POLICY", "maximum_value_bytes must be in 0..65536"
            )
        header_mutations = HeaderMutationPolicy(
            allow_names, deny_names, operations, maximum_value_bytes
        )

    metadata_value = payload.get("organizational_metadata", {})
    if not isinstance(metadata_value, dict) or any(
        not isinstance(key, str) or not isinstance(value, str)
        for key, value in metadata_value.items()
    ):
        raise AuthorizationError("INVALID_MANIFEST_FIELD", "organizational_metadata must map strings to strings")
    budget = payload["budget"]
    if not isinstance(budget, dict):
        raise AuthorizationError("INVALID_MANIFEST_FIELD", "budget must be an object")
    try:
        BudgetLimits.from_mapping(budget)
    except BudgetError as exc:
        raise AuthorizationError("INVALID_BUDGET", str(exc)) from exc

    mutation_risk_classes = _strings(
        payload["mutation_risk_classes"], "mutation_risk_classes"
    )
    if any(item not in RISK_RANK for item in mutation_risk_classes):
        raise AuthorizationError(
            "INVALID_MANIFEST_FIELD", "mutation_risk_classes contains an unknown class"
        )

    digest_payload = dict(payload)
    supplied_digest = digest_payload.pop("authorization_digest", None)
    digest = "sha256:" + hashlib.sha256(_canonical_json(digest_payload)).hexdigest()
    if supplied_digest is not None and supplied_digest != digest:
        raise AuthorizationError("AUTHORIZATION_DIGEST_MISMATCH", "authorization_digest does not match manifest")
    return AuthorizationManifest(
        schema_version=str(schema_version),
        engagement_id=payload["engagement_id"],
        issuer=payload["issuer"],
        subject=payload["subject"],
        issued_at=issued_at,
        expires_at=expires_at,
        rules=rules,
        proxy=proxy,
        authority=authority,
        redirects=redirects,
        mutation_families=_strings(payload["mutation_families"], "mutation_families"),
        mutation_risk_classes=mutation_risk_classes,
        header_mutations=header_mutations,
        organizational_metadata=tuple(sorted(metadata_value.items())),
        budget=budget,
        digest=digest,
    )


def system_resolver(host: str, port: int) -> tuple[str, ...]:
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        try:
            records = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise AuthorizationError("DNS_RESOLUTION_FAILED", "target name could not be resolved") from exc
        addresses = {str(ipaddress.ip_address(record[4][0])) for record in records}
        if not addresses:
            raise AuthorizationError("DNS_EMPTY_ANSWER", "target name resolved to no A or AAAA addresses")
        return tuple(sorted(addresses))
    return (str(literal),)


def _path_allowed(path: str, prefixes: tuple[str, ...]) -> bool:
    for prefix in prefixes:
        normalized = prefix.rstrip("/") or "/"
        if normalized == "/" or path == normalized or path.startswith(normalized + "/"):
            return True
    return False


def _validate_unambiguous_target(parts: object) -> None:
    path = getattr(parts, "path")
    query = getattr(parts, "query")
    fragment = getattr(parts, "fragment")
    try:
        path.encode("ascii")
        query.encode("ascii")
    except UnicodeEncodeError as exc:
        raise AuthorizationError(
            "AMBIGUOUS_TARGET_ENCODING",
            "request paths and queries must use an ASCII representation",
        ) from exc
    if fragment:
        raise AuthorizationError("URL_FRAGMENT_REJECTED", "request targets cannot contain fragments")
    if "\\" in path or "\\" in query or "%" in path:
        raise AuthorizationError(
            "AMBIGUOUS_TARGET_ENCODING",
            "backslashes and percent-encoded path octets are not accepted",
        )
    if re.search(r"%(?![0-9A-Fa-f]{2})", query):
        raise AuthorizationError("AMBIGUOUS_TARGET_ENCODING", "query contains a malformed escape")
    escaped_octets = [int(match.group(1), 16) for match in re.finditer(r"%([0-9A-Fa-f]{2})", query)]
    if ";" in query or any(
        octet <= 0x20
        or octet == 0x7F
        or octet >= 0x80
        or octet in {ord("%"), ord("&"), ord(";"), ord("="), ord("\\")}
        for octet in escaped_octets
    ):
        raise AuthorizationError(
            "AMBIGUOUS_TARGET_ENCODING",
            "query contains an encoding with parser-dependent semantics",
        )
    for query_field in query.split("&") if query else ():
        key = query_field.split("=", 1)[0]
        if not key or "%" in key or "+" in key or re.fullmatch(r"[A-Za-z0-9._~-]+", key) is None:
            raise AuthorizationError(
                "AMBIGUOUS_QUERY_KEY",
                "query keys must use one literal ASCII representation",
            )


def _query_allowed(query: str, policy: QueryPolicy) -> bool:
    try:
        query_bytes = query.encode("ascii")
    except UnicodeEncodeError:
        return False
    if len(query_bytes) > policy.maximum_query_bytes:
        return False
    if query and re.search(r"%(?![0-9A-Fa-f]{2})", query):
        return False
    if policy.mode == "deny":
        return not query
    try:
        keys = {
            key
            for key, _value in parse_qsl(
                query,
                keep_blank_values=True,
                strict_parsing=False,
                encoding="utf-8",
                errors="strict",
                max_num_fields=128,
            )
        }
    except (UnicodeDecodeError, ValueError):
        return False
    if keys & set(policy.forbidden_keys):
        return False
    if policy.mode == "allow-any":
        return True
    return keys <= set(policy.allowed_keys) and set(policy.required_keys) <= keys


def _target_url(request: RawRequest, base_url: str) -> str:
    if any(
        ord(character) <= 0x20 or ord(character) == 0x7F
        for source in (request.path, base_url)
        for character in source
    ):
        raise AuthorizationError(
            "AMBIGUOUS_TARGET_ENCODING",
            "request targets cannot contain spaces or control characters",
        )
    if request.target_form not in {"absolute", "origin"}:
        raise AuthorizationError(
            "UNSUPPORTED_SEMANTIC_TARGET_FORM",
            f"{request.target_form}-form cannot be sent by semantic-http transport",
        )
    if request.target_form == "origin":
        try:
            origin_base_url(base_url)
        except ValueError as exc:
            raise AuthorizationError(
                "INVALID_BASE_URL",
                "origin-form requests require an HTTP(S) origin without a path, query, or fragment",
            ) from exc
    try:
        raw = semantic_request_url(base_url, request.path, request.target_form)
        parts = urlsplit(raw)
        _validate_unambiguous_target(parts)
        if parts.username is not None or parts.password is not None:
            raise AuthorizationError("URL_USERINFO_REJECTED", "URL userinfo is not supported")
        if not parts.scheme or not parts.hostname:
            raise AuthorizationError("INVALID_TARGET_URL", "target URL lacks scheme or host")
        host = _canonical_host(parts.hostname)
        scheme = parts.scheme.lower()
        port = parts.port or (443 if scheme == "https" else 80 if scheme == "http" else None)
        if port is None:
            raise AuthorizationError("INVALID_TARGET_URL", "target URL has no effective port")
        display_host = f"[{host}]" if ":" in host else host
        netloc = display_host if port == (443 if scheme == "https" else 80) else f"{display_host}:{port}"
        canonical = canonical_uri(urlunsplit((scheme, netloc, parts.path or "/", parts.query, "")))
    except ValueError as exc:
        raise AuthorizationError("INVALID_TARGET_URL", "target URL is malformed") from exc
    return canonical


def request_fingerprint(request: RawRequest, canonical_url: str) -> str:
    payload = {
        "method": request.method,
        "canonical_url": canonical_url,
        "headers": request.headers,
        "body_sha256": hashlib.sha256(request.body).hexdigest(),
        "body_length": len(request.body),
    }
    return "sha256:" + hashlib.sha256(_canonical_json(payload)).hexdigest()


def _raw_request_fingerprint(request: RawRequest) -> str:
    payload = {
        "method": request.method,
        "path": request.path,
        "http_version": request.http_version,
        "target_form": request.target_form,
        "headers": request.headers,
        "body_sha256": hashlib.sha256(request.body).hexdigest(),
        "body_length": len(request.body),
    }
    return "sha256:" + hashlib.sha256(_canonical_json(payload)).hexdigest()


def _changed_request_dimensions(
    baseline: RawRequest,
    mutation: RawRequest,
) -> tuple[str, ...]:
    dimensions = (
        ("method", baseline.method, mutation.method),
        ("target", baseline.path, mutation.path),
        ("http_version", baseline.http_version, mutation.http_version),
        ("target_form", baseline.target_form, mutation.target_form),
        ("headers", baseline.headers, mutation.headers),
        ("body", baseline.body, mutation.body),
    )
    return tuple(name for name, before, after in dimensions if before != after)


def _header_operations(old_values: list[str], new_values: list[str]) -> tuple[str, ...]:
    if old_values == new_values:
        return ()
    old_counts = Counter(old_values)
    new_counts = Counter(new_values)
    common = old_counts & new_counts

    def retained(values: list[str]) -> list[str]:
        remaining = common.copy()
        result: list[str] = []
        for value in values:
            if remaining[value] > 0:
                result.append(value)
                remaining[value] -= 1
        return result

    if retained(old_values) != retained(new_values):
        return ("reorder",)
    removed = sum((old_counts - new_counts).values())
    added = sum((new_counts - old_counts).values())
    replaced = min(removed, added)
    operations: list[str] = []
    if replaced:
        operations.append("replace")
    if added > replaced:
        operations.append("add")
    if removed > replaced:
        operations.append("remove")
    return tuple(operations)


def _ordered_subsequence(
    candidate: list[tuple[str, str]],
    source: list[tuple[str, str]],
) -> bool:
    position = 0
    for item in candidate:
        while position < len(source) and source[position] != item:
            position += 1
        if position == len(source):
            return False
        position += 1
    return True


def _safe_redirect_derivation(mutation: RawRequest, outgoing: RawRequest) -> bool:
    return (
        outgoing.method in {mutation.method, "GET"}
        and outgoing.http_version == mutation.http_version
        and outgoing.body in {mutation.body, b""}
        and _ordered_subsequence(outgoing.headers, mutation.headers)
    )


def _effective_authorities(
    request: RawRequest,
    canonical_url: str,
    policy: AuthorityPolicy,
    *,
    proxy_url: str | None,
    mutation_family: str | None,
) -> tuple[str, str | None, str | None]:
    parsed = urlsplit(canonical_url)
    scheme = parsed.scheme.lower()
    default_port = 443 if scheme == "https" else 80
    target_host = _canonical_host(parsed.hostname or "")
    target_port = parsed.port or default_port
    target_authority = _authority_text(target_host, target_port, scheme)
    host_fields = [value for name, value in request.headers if name.lower() == "host"]
    if len(host_fields) > 1:
        raise AuthorizationError("DUPLICATE_HOST_REJECTED", "multiple Host fields are forbidden")
    if host_fields:
        host, port = _parse_authority(host_fields[0], default_port=default_port)
        assert port is not None
        effective_host = _authority_text(host, port, scheme)
    else:
        host, port = target_host, target_port
        effective_host = target_authority

    target_pair = (target_host, target_port)
    effective_pair = (host, port)
    if policy.mode == "match-target" and effective_pair != target_pair:
        raise AuthorizationError(
            "HOST_AUTHORITY_NOT_AUTHORIZED", "Host authority must match the target URL"
        )
    if policy.mode == "explicit":
        allowed = {
            _parse_authority(item, default_port=default_port)
            for item in policy.allowed_host_fields
        }
        if effective_pair not in allowed:
            raise AuthorizationError(
                "HOST_AUTHORITY_NOT_AUTHORIZED", "Host authority is outside explicit policy"
            )
    if (
        mutation_family == "header"
        and effective_pair != target_pair
        and not policy.allow_host_mutation
    ):
        raise AuthorizationError(
            "HOST_MUTATION_NOT_AUTHORIZED", "Host mutation requires explicit authorization"
        )

    sni_authority = target_host if scheme == "https" else None
    connect_authority = target_authority if proxy_url is not None and scheme == "https" else None
    return effective_host, sni_authority, connect_authority


class ManifestAuthorizationPolicy:
    def __init__(
        self,
        manifest: AuthorizationManifest,
        *,
        resolver: Resolver = system_resolver,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self.manifest = manifest
        self.digest = manifest.digest
        self._resolver = resolver
        self._now = now or (lambda: datetime.now(timezone.utc))
        self._method_counts: dict[tuple[int, str], int] = {}
        self._lock = threading.RLock()

    def _check_validity(self) -> datetime:
        current = self._now().astimezone(timezone.utc)
        if current < self.manifest.issued_at:
            raise AuthorizationError("AUTHORIZATION_NOT_YET_VALID", "authorization is not yet valid")
        if current >= self.manifest.expires_at:
            raise AuthorizationError("AUTHORIZATION_EXPIRED", "authorization has expired")
        return current

    def validate_mutation(
        self,
        baseline: RawRequest,
        mutation: RawRequest,
        *,
        mutation_family: str,
    ) -> MutationValidation:
        if mutation_family != "header":
            raise AuthorizationError(
                "UNSUPPORTED_MUTATION_FAMILY",
                f"mutation family {mutation_family!r} has no dimensional validator",
            )
        changed_dimensions = _changed_request_dimensions(baseline, mutation)
        non_header_dimensions = tuple(
            dimension for dimension in changed_dimensions if dimension != "headers"
        )
        if non_header_dimensions:
            raise AuthorizationError(
                "MUTATION_DIMENSION_NOT_AUTHORIZED",
                "header mutation also changed " + ", ".join(non_header_dimensions),
            )
        required: list[str] = []
        if self.manifest.header_mutations is None:
            return self._mutation_validation(
                baseline,
                mutation,
                mutation_family,
                changed_dimensions,
                required,
            )
        policy = self.manifest.header_mutations
        before: dict[str, list[str]] = {}
        after: dict[str, list[str]] = {}
        for name, value in baseline.headers:
            before.setdefault(name.lower(), []).append(value)
        for name, value in mutation.headers:
            after.setdefault(name.lower(), []).append(value)
        for name in sorted(set(before) | set(after)):
            old_values = before.get(name, [])
            new_values = after.get(name, [])
            if old_values == new_values:
                continue
            if name in policy.deny_names or name not in policy.allow_names:
                raise AuthorizationError(
                    "HEADER_MUTATION_NOT_AUTHORIZED",
                    f"header mutation for {name!r} is outside policy",
                )
            operations = _header_operations(old_values, new_values)
            if "reorder" in operations:
                raise AuthorizationError(
                    "HEADER_MUTATION_REORDER_NOT_AUTHORIZED",
                    f"duplicate values for {name!r} changed order",
                )
            for operation in operations:
                if operation not in policy.operations:
                    raise AuthorizationError(
                        "HEADER_MUTATION_OPERATION_NOT_AUTHORIZED",
                        f"{operation} is outside header mutation policy",
                    )
                required.append(f"{name}:{operation}")
            try:
                value_lengths = [len(value.encode("latin-1")) for value in new_values]
            except UnicodeEncodeError as exc:
                raise AuthorizationError(
                    "INVALID_HEADER_VALUE",
                    f"header mutation for {name!r} is not representable as HTTP/1 field bytes",
                ) from exc
            if any(length > policy.maximum_value_bytes for length in value_lengths):
                raise AuthorizationError(
                    "HEADER_MUTATION_VALUE_TOO_LARGE",
                    f"header mutation for {name!r} exceeds the value limit",
                )
            if name == "host" and not self.manifest.authority.allow_host_mutation:
                raise AuthorizationError(
                    "HOST_MUTATION_NOT_AUTHORIZED", "Host mutation requires explicit authorization"
                )
        return self._mutation_validation(
            baseline,
            mutation,
            mutation_family,
            changed_dimensions,
            required,
        )

    def _mutation_validation(
        self,
        baseline: RawRequest,
        mutation: RawRequest,
        family: str,
        changed_dimensions: tuple[str, ...],
        required_operations: list[str],
    ) -> MutationValidation:
        baseline_fingerprint = _raw_request_fingerprint(baseline)
        mutation_fingerprint = _raw_request_fingerprint(mutation)
        payload = {
            "policy_version": AUTHORIZATION_POLICY_VERSION,
            "manifest_digest": self.manifest.digest,
            "family": family,
            "changed_dimensions": list(changed_dimensions),
            "baseline_fingerprint": baseline_fingerprint,
            "mutation_fingerprint": mutation_fingerprint,
            "required_operations": sorted(required_operations),
        }
        return MutationValidation(
            family=family,
            changed_dimensions=changed_dimensions,
            baseline_fingerprint=baseline_fingerprint,
            mutation_fingerprint=mutation_fingerprint,
            delta_digest="sha256:" + hashlib.sha256(_canonical_json(payload)).hexdigest(),
            required_operations=tuple(sorted(required_operations)),
        )

    def authorize_mutation(
        self,
        baseline: RawRequest,
        mutation: RawRequest,
        outgoing_request: RawRequest,
        *,
        base_url: str,
        attempt_kind: str,
        mutation_family: str,
        risk_class: str | None = None,
        proxy_url: str | None = None,
        consume_repetition: bool = True,
    ) -> AuthorizedMutationContext:
        validation = self.validate_mutation(
            baseline,
            mutation,
            mutation_family=mutation_family,
        )
        outgoing_fingerprint = _raw_request_fingerprint(outgoing_request)
        if outgoing_fingerprint != validation.mutation_fingerprint and (
            attempt_kind not in {"redirect", "retry"}
            or not _safe_redirect_derivation(mutation, outgoing_request)
        ):
            raise AuthorizationError(
                "MUTATION_DERIVATION_NOT_AUTHORIZED",
                "outgoing mutation does not match the validated mutation or a removal-only redirect derivation",
            )
        context = self.authorize(
            outgoing_request,
            base_url=base_url,
            attempt_kind=attempt_kind,
            mutation_family=mutation_family,
            risk_class=risk_class,
            proxy_url=proxy_url,
            consume_repetition=consume_repetition,
        )
        return AuthorizedMutationContext(
            decision=context.decision,
            canonical_url=context.canonical_url,
            resolved_addresses=context.resolved_addresses,
            authorized_at=context.authorized_at,
            rule_index=context.rule_index,
            request_fingerprint=context.request_fingerprint,
            proxy_url=context.proxy_url,
            effective_host_authority=context.effective_host_authority,
            mutation=validation,
        )

    def _authorize_proxy(self, proxy_url: str | None) -> tuple[str, ...]:
        if proxy_url is None:
            return ()
        if self.manifest.proxy.mode != "allow-explicit":
            raise AuthorizationError("PROXY_NOT_AUTHORIZED", "manifest denies proxy use")
        parsed = urlsplit(proxy_url)
        if parsed.username is not None or parsed.password is not None:
            raise AuthorizationError("PROXY_CREDENTIALS_REJECTED", "proxy URL credentials are not accepted")
        if parsed.scheme not in {"http", "https"} or parsed.hostname is None:
            raise AuthorizationError("INVALID_PROXY_URL", "proxy URL must use http or https")
        host = _canonical_host(parsed.hostname)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if host not in self.manifest.proxy.hosts or port not in self.manifest.proxy.ports:
            raise AuthorizationError("PROXY_NOT_AUTHORIZED", "proxy endpoint is outside manifest policy")
        addresses = tuple(sorted(self._resolver(host, port)))
        if not addresses:
            raise AuthorizationError("DNS_EMPTY_ANSWER", "proxy resolved to no addresses")
        try:
            parsed_addresses = tuple(ipaddress.ip_address(item) for item in addresses)
        except ValueError as exc:
            raise AuthorizationError(
                "INVALID_RESOLVER_RESULT", "resolver returned a non-IP proxy address"
            ) from exc
        if any(
            not any(address in network for network in self.manifest.proxy.cidrs)
            for address in parsed_addresses
        ):
            raise AuthorizationError(
                "PROXY_ADDRESS_NOT_AUTHORIZED",
                "at least one current proxy address is outside authorized CIDRs",
            )
        return addresses

    def _resolve_authorized(
        self,
        host: str,
        port: int,
        rule: TargetRule,
    ) -> tuple[str, ...]:
        addresses = tuple(sorted(self._resolver(host, port)))
        if not addresses:
            raise AuthorizationError("DNS_EMPTY_ANSWER", "resolver returned no addresses")
        parsed_addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
        for value in addresses:
            try:
                parsed_addresses.append(ipaddress.ip_address(value))
            except ValueError as exc:
                raise AuthorizationError(
                    "INVALID_RESOLVER_RESULT", "resolver returned a non-IP address"
                ) from exc
        if any(
            not any(address in network for network in rule.cidrs)
            for address in parsed_addresses
        ):
            raise AuthorizationError(
                "RESOLVED_ADDRESS_NOT_AUTHORIZED",
                "at least one current A or AAAA address is outside authorized CIDRs",
            )
        return addresses

    def revalidate(self, context: AuthorizedRequestContext) -> AuthorizedRequestContext:
        """Re-resolve an accepted target immediately before transport handoff."""
        current = self._check_validity()
        parsed = urlsplit(context.canonical_url)
        host = _canonical_host(parsed.hostname or "")
        scheme = parsed.scheme.lower()
        port = parsed.port or (443 if scheme == "https" else 80)
        try:
            rule = self.manifest.rules[context.rule_index]
        except IndexError as exc:
            raise AuthorizationError(
                "AUTHORIZATION_CONTEXT_INVALID", "target rule no longer exists"
            ) from exc
        addresses = self._resolve_authorized(host, port, rule)
        proxy_addresses = self._authorize_proxy(context.proxy_url)
        address_fingerprint = "sha256:" + hashlib.sha256(
            "\n".join(addresses).encode()
        ).hexdigest()
        proxy_address_fingerprint = (
            "sha256:" + hashlib.sha256("\n".join(proxy_addresses).encode()).hexdigest()
            if proxy_addresses
            else None
        )
        changed = (
            addresses != context.resolved_addresses
            or proxy_address_fingerprint
            != context.decision.proxy_address_set_fingerprint
        )
        decision = replace(
            context.decision,
            code="AUTHORIZED_DNS_CHANGED" if changed else "AUTHORIZED_REVALIDATED",
            address_set_fingerprint=address_fingerprint,
            proxy_address_set_fingerprint=proxy_address_fingerprint,
        )
        return replace(
            context,
            decision=decision,
            resolved_addresses=addresses,
            authorized_at=current,
        )

    def authorize(
        self,
        request: RawRequest,
        *,
        base_url: str,
        attempt_kind: str,
        mutation_family: str | None = None,
        risk_class: str | None = None,
        proxy_url: str | None = None,
        consume_repetition: bool = True,
    ) -> AuthorizedRequestContext:
        current = self._check_validity()
        proxy_addresses = self._authorize_proxy(proxy_url)
        canonical = _target_url(request, base_url)
        parsed = urlsplit(canonical)
        host = _canonical_host(parsed.hostname or "")
        scheme = parsed.scheme.lower()
        port = parsed.port or (443 if scheme == "https" else 80)
        method = request.method
        effective_host, sni_authority, connect_authority = _effective_authorities(
            request,
            canonical,
            self.manifest.authority,
            proxy_url=proxy_url,
            mutation_family=mutation_family,
        )
        method_risk = classify_method(method)
        declared_risk = risk_class or "safe"
        if declared_risk not in RISK_RANK:
            raise AuthorizationError(
                "MUTATION_RISK_NOT_AUTHORIZED", "risk class is outside policy"
            )
        effective_risk = max(
            (declared_risk, method_risk.risk_class),
            key=RISK_RANK.__getitem__,
        )
        if mutation_family is not None and mutation_family not in self.manifest.mutation_families:
            raise AuthorizationError("MUTATION_FAMILY_NOT_AUTHORIZED", "mutation family is outside policy")
        if mutation_family is not None and mutation_family != "header":
            raise AuthorizationError(
                "UNSUPPORTED_MUTATION_FAMILY",
                f"mutation family {mutation_family!r} has no dimensional validator",
            )
        if effective_risk not in self.manifest.mutation_risk_classes:
            raise AuthorizationError("MUTATION_RISK_NOT_AUTHORIZED", "risk class is outside policy")

        matched: tuple[int, TargetRule] | None = None
        for index, rule in enumerate(self.manifest.rules):
            if (
                scheme in rule.schemes
                and host in rule.hosts
                and port in rule.ports
                and method in rule.methods
                and attempt_kind in rule.attempt_kinds
                and _path_allowed(parsed.path or "/", rule.path_prefixes)
                and _query_allowed(parsed.query, rule.query_policy)
                and len(request.body) <= rule.maximum_request_body_bytes
            ):
                matched = (index, rule)
                break
        if matched is None:
            raise AuthorizationError(
                "TARGET_NOT_AUTHORIZED",
                "scheme, host, port, path, method, or request-body size is outside policy",
            )
        rule_index, rule = matched
        addresses = self._resolve_authorized(host, port, rule)

        if attempt_kind in {"setup", "reset"} and not rule.disposable_environment:
            raise AuthorizationError(
                "HOOK_ENVIRONMENT_NOT_DISPOSABLE",
                "setup and reset operations require a disposable-environment declaration",
            )

        if method in rule.require_idempotency_key and not any(
            name.lower() == "idempotency-key" and value for name, value in request.headers
        ):
            raise AuthorizationError("IDEMPOTENCY_KEY_REQUIRED", f"{method} requires Idempotency-Key")
        maximum_repetitions = rule.repetition_limit(method)
        with self._lock:
            repetitions = self._method_counts.get((rule_index, method), 0) + 1
            if method_risk.repeat_requires_explicit_authorization and maximum_repetitions is None:
                raise AuthorizationError(
                    "METHOD_REPETITION_NOT_AUTHORIZED",
                    f"{method} requires maximum_repetitions_by_method",
                )
            if maximum_repetitions is not None and repetitions > maximum_repetitions:
                raise AuthorizationError(
                    "METHOD_REPETITION_EXHAUSTED",
                    f"{method} repetition limit exceeded",
                )
            if consume_repetition:
                self._method_counts[(rule_index, method)] = repetitions
        address_fingerprint = hashlib.sha256("\n".join(addresses).encode()).hexdigest()
        proxy_address_fingerprint = (
            "sha256:" + hashlib.sha256("\n".join(proxy_addresses).encode()).hexdigest()
            if proxy_addresses
            else None
        )
        target_fingerprint = hashlib.sha256(canonical.encode()).hexdigest()
        origin = f"{scheme}://{'[' + host + ']' if ':' in host else host}:{port}"
        decision = AuthorizationDecision(
            accepted=True,
            code="AUTHORIZED",
            policy_version=AUTHORIZATION_POLICY_VERSION,
            manifest_digest=self.manifest.digest,
            target_fingerprint=f"sha256:{target_fingerprint}",
            address_set_fingerprint=f"sha256:{address_fingerprint}",
            proxy_address_set_fingerprint=proxy_address_fingerprint,
            host_authority_fingerprint=(
                "sha256:" + hashlib.sha256(effective_host.encode()).hexdigest()
            ),
            sni_authority_fingerprint=(
                "sha256:" + hashlib.sha256(sni_authority.encode()).hexdigest()
                if sni_authority is not None
                else None
            ),
            proxy_connect_authority_fingerprint=(
                "sha256:" + hashlib.sha256(connect_authority.encode()).hexdigest()
                if connect_authority is not None
                else None
            ),
            canonical_origin=origin,
            method=method,
            attempt_kind=attempt_kind,
            effective_risk=effective_risk,
            budget_policy_digest=BudgetLimits.from_mapping(
                self.manifest.budget
            ).policy_digest,
        )
        return AuthorizedRequestContext(
            decision=decision,
            canonical_url=canonical,
            resolved_addresses=addresses,
            authorized_at=current,
            rule_index=rule_index,
            request_fingerprint=request_fingerprint(request, canonical),
            proxy_url=proxy_url,
            effective_host_authority=effective_host,
        )
