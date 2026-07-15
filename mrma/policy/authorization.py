from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import socket
import threading
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin, urlsplit, urlunsplit

from mrma.core.http_semantics import canonical_uri
from mrma.core.raw_request import RawRequest

from .budget import BudgetError, BudgetLimits
from .method_risk import RISK_RANK, classify_method

AUTHORIZATION_SCHEMA_VERSION = "mrma.authorization/v1"
AUTHORIZATION_POLICY_VERSION = "authorization-policy/1.0"

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
    if not host or "*" in host:
        raise AuthorizationError("INVALID_HOST", "authorization hosts must be exact names")
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        try:
            return host.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise AuthorizationError("INVALID_HOST", "host cannot be IDNA-canonicalized") from exc


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

    def repetition_limit(self, method: str) -> int | None:
        return dict(self.maximum_repetitions_by_method).get(method)


@dataclass(frozen=True)
class ProxyPolicy:
    mode: str
    hosts: tuple[str, ...] = ()
    ports: tuple[int, ...] = ()
    cidrs: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = ()


@dataclass(frozen=True)
class RedirectPolicy:
    mode: str
    maximum_depth: int
    forward_credentials_cross_origin: bool


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
    redirects: RedirectPolicy
    mutation_families: tuple[str, ...]
    mutation_risk_classes: tuple[str, ...]
    organizational_metadata: tuple[tuple[str, str], ...]
    budget: Mapping[str, object]
    digest: str

    def public_summary(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "engagement_fingerprint": f"sha256:{hashlib.sha256(self.engagement_id.encode()).hexdigest()}",
            "issuer_fingerprint": f"sha256:{hashlib.sha256(self.issuer.encode()).hexdigest()}",
            "subject_fingerprint": f"sha256:{hashlib.sha256(self.subject.encode()).hexdigest()}",
            "expires_at": self.expires_at.replace(microsecond=0).isoformat(),
            "rule_count": len(self.rules),
            "digest": self.digest,
            "policy_version": AUTHORIZATION_POLICY_VERSION,
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
    canonical_origin: str = field(repr=False)
    method: str
    attempt_kind: str


@dataclass(frozen=True)
class AuthorizedRequestContext:
    decision: AuthorizationDecision
    canonical_url: str = field(repr=False)
    resolved_addresses: tuple[str, ...] = field(repr=False)
    authorized_at: datetime
    rule_index: int
    request_fingerprint: str
    proxy_url: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if not self.decision.accepted:
            raise ValueError("an authorized request context requires an accepted decision")


def _parse_rule(value: object, index: int) -> TargetRule:
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
    required = allowed - {"maximum_repetitions_by_method", "require_idempotency_key", "disposable_environment"}
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
    required = allowed - {"authorization_digest", "organizational_metadata"}
    _expect_keys(payload, allowed=allowed, required=required, name="manifest")
    if payload["schema_version"] != AUTHORIZATION_SCHEMA_VERSION:
        raise AuthorizationError("UNSUPPORTED_AUTHORIZATION_SCHEMA", "expected mrma.authorization/v1")
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
    rules = tuple(_parse_rule(item, index) for index, item in enumerate(raw_rules))

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

    redirect_value = payload["redirects"]
    if not isinstance(redirect_value, dict):
        raise AuthorizationError("INVALID_MANIFEST_FIELD", "redirects must be an object")
    _expect_keys(
        redirect_value,
        allowed={"mode", "maximum_depth", "forward_credentials_cross_origin"},
        required={"mode", "maximum_depth", "forward_credentials_cross_origin"},
        name="redirects",
    )
    if redirect_value["mode"] not in {"deny", "same-origin", "authorized-targets"}:
        raise AuthorizationError("INVALID_REDIRECT_POLICY", "unknown redirect mode")
    if not isinstance(redirect_value["maximum_depth"], int) or not 0 <= redirect_value["maximum_depth"] <= 20:
        raise AuthorizationError("INVALID_REDIRECT_POLICY", "maximum_depth must be in 0..20")
    if not isinstance(redirect_value["forward_credentials_cross_origin"], bool):
        raise AuthorizationError("INVALID_REDIRECT_POLICY", "credential forwarding flag must be boolean")
    redirects = RedirectPolicy(
        redirect_value["mode"],
        redirect_value["maximum_depth"],
        redirect_value["forward_credentials_cross_origin"],
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
        schema_version=AUTHORIZATION_SCHEMA_VERSION,
        engagement_id=payload["engagement_id"],
        issuer=payload["issuer"],
        subject=payload["subject"],
        issued_at=issued_at,
        expires_at=expires_at,
        rules=rules,
        proxy=proxy,
        redirects=redirects,
        mutation_families=_strings(payload["mutation_families"], "mutation_families"),
        mutation_risk_classes=mutation_risk_classes,
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


def _target_url(request: RawRequest, base_url: str) -> str:
    if request.target_form == "absolute":
        raw = request.path
    elif request.target_form == "origin":
        raw = urljoin(base_url.rstrip("/") + "/", request.path.lstrip("/"))
    else:
        raise AuthorizationError(
            "UNSUPPORTED_SEMANTIC_TARGET_FORM",
            f"{request.target_form}-form cannot be sent by semantic-http transport",
        )
    try:
        parts = urlsplit(raw)
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
            canonical_origin=origin,
            method=method,
            attempt_kind=attempt_kind,
        )
        return AuthorizedRequestContext(
            decision=decision,
            canonical_url=canonical,
            resolved_addresses=addresses,
            authorized_at=current,
            rule_index=rule_index,
            request_fingerprint=request_fingerprint(request, canonical),
            proxy_url=proxy_url,
        )
