"""Make retrieved text visible and inert at instruction and execution boundaries."""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from urllib.parse import urlsplit


@dataclass(frozen=True, slots=True)
class InjectionFinding:
    source: str
    indicator: str
    excerpt: str
    start: int
    end: int


@dataclass(frozen=True, slots=True)
class UntrustedText:
    source: str
    text: str
    findings: tuple[InjectionFinding, ...]

    @property
    def suspected_prompt_injection(self) -> bool:
        return bool(self.findings)


class OriginNotAllowedError(ValueError):
    """A URL is not within an explicitly configured origin."""


_INJECTION_PATTERNS = (
    (
        "role_directive",
        re.compile(r"(?im)^\s*(?:system|developer|assistant)\s*:\s*\S"),
    ),
    (
        "instruction_override",
        re.compile(
            r"(?i)\b(?:ignore|disregard|override|forget)\s+"
            r"(?:(?:all|any|the|these)\s+)?(?:previous|prior|above|system)?\s*instructions?\b"
        ),
    ),
    (
        "claimed_authorization",
        re.compile(
            r"(?i)\b(?:the\s+user|andrew|an?\s+administrator)\s+"
            r"(?:has\s+|already\s+)?(?:approved|authorized|permitted)\b"
        ),
    ),
    (
        "instruction_request",
        re.compile(
            r"(?i)\b(?:follow|obey)\s+(?:all\s+|these\s+|the\s+)?instructions?\b|"
            r"\b(?:execute|run)\s+(?:the\s+)?(?:following\s+)?commands?\b"
        ),
    ),
    (
        "identity_override",
        re.compile(r"(?i)\b(?:you\s+are|act\s+as)\s+(?:an?\s+)?(?:ai|assistant|agent|chatgpt|claude|codex)\b"),
    ),
    (
        "encoded_payload",
        re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{100,}={0,2}(?![A-Za-z0-9+/=])"),
    ),
)

_BIDI_CONTROLS = frozenset(
    {
        "\u061c",
        "\u200e",
        "\u200f",
        "\u202a",
        "\u202b",
        "\u202c",
        "\u202d",
        "\u202e",
        "\u2066",
        "\u2067",
        "\u2068",
        "\u2069",
    }
)


def escape_terminal_controls(value: str, *, preserve_layout: bool = True) -> str:
    """Render terminal and bidirectional controls as visible escape text."""

    output: list[str] = []
    for character in value:
        codepoint = ord(character)
        if preserve_layout and character in {"\n", "\t"}:
            output.append(character)
        elif codepoint < 32 or 127 <= codepoint <= 159:
            output.append(f"\\x{codepoint:02x}")
        elif character in _BIDI_CONTROLS or unicodedata.category(character) == "Cf":
            output.append(f"\\u{codepoint:04x}")
        else:
            output.append(character)
    return "".join(output)


def _excerpt(value: str, start: int, end: int, *, radius: int = 70) -> str:
    excerpt = value[max(0, start - radius) : min(len(value), end + radius)]
    return escape_terminal_controls(excerpt, preserve_layout=False)


def scan_prompt_injection(value: str, *, source: str) -> tuple[InjectionFinding, ...]:
    """Flag common instruction-injection indicators without interpreting them."""

    findings: list[InjectionFinding] = []
    for indicator, pattern in _INJECTION_PATTERNS:
        for match in pattern.finditer(value):
            findings.append(
                InjectionFinding(
                    source=escape_terminal_controls(source, preserve_layout=False),
                    indicator=indicator,
                    excerpt=_excerpt(value, match.start(), match.end()),
                    start=match.start(),
                    end=match.end(),
                )
            )
    return tuple(sorted(findings, key=lambda finding: (finding.start, finding.indicator)))


def inspect_untrusted_text(value: str, *, source: str) -> UntrustedText:
    """Prepare untrusted text for display and attach visible tripwire findings."""

    return UntrustedText(
        source=escape_terminal_controls(source, preserve_layout=False),
        text=escape_terminal_controls(value),
        findings=scan_prompt_injection(value, source=source),
    )


def require_allowlisted_value(value: str, allowed_values: set[str] | frozenset[str]) -> str:
    """Permit only a configured value at an executable/query boundary."""

    if value not in allowed_values:
        raise ValueError("value is not configured and allowlisted")
    return value


def _origin(url: str, *, configured_origin: bool = False) -> str:
    parsed = urlsplit(url)
    if parsed.scheme.casefold() not in {"http", "https"} or not parsed.hostname:
        raise OriginNotAllowedError("URL must use an HTTP(S) origin")
    if parsed.username is not None or parsed.password is not None:
        raise OriginNotAllowedError("URL credentials are forbidden")
    if configured_origin and (parsed.path not in {"", "/"} or parsed.query or parsed.fragment):
        message = "configured origins cannot contain paths, queries, or fragments"
        raise OriginNotAllowedError(message)
    if parsed.scheme.casefold() == "http" and parsed.hostname.casefold() not in {
        "127.0.0.1",
        "::1",
        "localhost",
    }:
        raise OriginNotAllowedError("cleartext HTTP is permitted only for loopback origins")
    host = parsed.hostname.casefold()
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    try:
        port = parsed.port
    except ValueError as exc:
        raise OriginNotAllowedError("URL port is invalid") from exc
    default_port = 443 if parsed.scheme.casefold() == "https" else 80
    port_text = "" if port in (None, default_port) else f":{port}"
    return f"{parsed.scheme.casefold()}://{host}{port_text}"


def require_allowed_origin(
    url: str,
    allowed_origins: set[str] | frozenset[str],
    *,
    allow_query: bool = False,
) -> str:
    """Require a fixed configured origin and reject URL exfiltration channels."""

    parsed = urlsplit(url)
    if parsed.fragment:
        raise OriginNotAllowedError("URL fragments are forbidden")
    if parsed.query and not allow_query:
        raise OriginNotAllowedError("URL query strings are forbidden")
    allowed = {_origin(origin, configured_origin=True) for origin in allowed_origins}
    if _origin(url) not in allowed:
        raise OriginNotAllowedError("URL origin is not configured and allowlisted")
    return url
