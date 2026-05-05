from pathlib import Path

from safelog.redactor import redact_file, redact_text


def test_redact_text_replaces_single_email() -> None:
    result = redact_text("user=jane@example.com logged in\n")

    assert result == "user=[EMAIL_1] logged in\n"


def test_redact_text_reuses_placeholder_for_repeated_values() -> None:
    result = redact_text("primary=jane@example.com backup=jane@example.com\n")

    assert result == "primary=[EMAIL_1] backup=[EMAIL_1]\n"


def test_redact_text_replaces_multiple_sensitive_types() -> None:
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signature_123"
    text = (
        "user=jane@example.com ip=10.0.0.1 "
        f"jwt={jwt} aws=AKIAABCDEFGHIJKLMNOP "
        "api_key=sk_test_1234567890abcdef "
        "url=https://api.example.com/v1/users domain=internal.example.org "
        "path=/var/log/app.log request=123e4567-e89b-12d3-a456-426614174000\n"
        "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----\n"
    )

    result = redact_text(text)

    assert result == (
        "user=[EMAIL_1] ip=[IP_1] jwt=[JWT_1] aws=[AWS_KEY_1] "
        "api_key=[API_KEY_1] url=[URL_1] domain=[DOMAIN_1] "
        "path=[FILE_PATH_1] request=[UUID_1]\n"
        "[PRIVATE_KEY_1]\n"
    )


def test_redact_text_preserves_no_sensitive_data() -> None:
    text = "2026-05-05 INFO request completed in 15ms\n"

    assert redact_text(text) == text


def test_redact_file_reads_from_path_string(tmp_path: Path) -> None:
    log = tmp_path / "sample.log"
    log.write_text("client=10.0.0.1\n", encoding="utf-8")

    assert redact_file(str(log)) == "client=[IP_1]\n"


def test_redact_text_handles_empty_input() -> None:
    assert redact_text("") == ""


def test_redact_text_handles_large_inputs_deterministically() -> None:
    text = "\n".join(
        f"line {index} user=jane@example.com ip=10.0.0.1" for index in range(1000)
    )

    result = redact_text(text)

    assert "jane@example.com" not in result
    assert "10.0.0.1" not in result
    assert result.count("[EMAIL_1]") == 1000
    assert result.count("[IP_1]") == 1000


def test_redact_file_handles_malformed_bytes(tmp_path: Path) -> None:
    log = tmp_path / "malformed.log"
    log.write_bytes(b"user=jane@example.com\n\xff\xfe\n")

    result = redact_file(str(log))

    assert result.startswith("user=[EMAIL_1]\n")


def test_redact_text_handles_only_sensitive_data() -> None:
    text = (
        "jane@example.com\n"
        "10.0.0.1\n"
        "AKIAABCDEFGHIJKLMNOP\n"
        "sk_test_1234567890abcdef\n"
        "https://api.example.com/v1/users\n"
        "internal.example.org\n"
        "/var/log/app.log\n"
    )

    assert redact_text(text) == (
        "[EMAIL_1]\n"
        "[IP_1]\n"
        "[AWS_KEY_1]\n"
        "[API_KEY_1]\n"
        "[URL_1]\n"
        "[DOMAIN_1]\n"
        "[FILE_PATH_1]\n"
    )
