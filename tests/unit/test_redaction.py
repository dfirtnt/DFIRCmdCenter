from __future__ import annotations

from dfircmdcenter.core.redaction import REDACTED, contains_secret_fields, redact


def test_redacts_secret_shaped_fields_recursively_without_dropping_structure() -> None:
    value = {
        "client_id": "public-identifier",
        "credentials": {
            "api_key": "abc123",
            "password": "hunter2",
        },
        "items": [{"Authorization": "Bearer secret", "name": "safe"}],
    }

    result = redact(value)

    assert result["client_id"] == "public-identifier"
    assert result["credentials"]["api_key"] == REDACTED
    assert result["credentials"]["password"] == REDACTED
    assert result["items"][0]["Authorization"] == REDACTED
    assert contains_secret_fields(value)


def test_redacts_secret_tokens_embedded_in_text() -> None:
    text = "Authorization: Bearer abc.def-123\nmode=read-only"

    result = redact(text)

    assert "abc.def-123" not in result
    assert "mode=read-only" in result


def test_does_not_redact_non_secret_identifiers() -> None:
    value = {"client_id": "C.123", "flow_id": "F.456", "public_key_id": "kid-1"}

    assert redact(value) == value
    assert not contains_secret_fields(value)

