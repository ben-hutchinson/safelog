from pathlib import Path

from safelog.scanner import scan_file


def write_log(tmp_path: Path, content: str) -> Path:
    log = tmp_path / "sample.log"
    log.write_text(content, encoding="utf-8")
    return log


def test_scan_file_detects_emails(tmp_path: Path) -> None:
    path = write_log(tmp_path, "user=jane@example.com backup=ops@example.org\n")

    assert scan_file(str(path))["emails"] == 2


def test_scan_file_detects_ipv4_addresses(tmp_path: Path) -> None:
    path = write_log(tmp_path, "accepted from 10.0.0.1 rejected from 192.168.1.25\n")

    assert scan_file(str(path))["ips"] == 2


def test_scan_file_detects_urls_and_domains(tmp_path: Path) -> None:
    path = write_log(
        tmp_path,
        "request to https://api.example.com/v1/users fallback internal.example.org\n",
    )

    result = scan_file(str(path))

    assert result["urls"] == 1
    assert result["domains"] == 1


def test_scan_file_detects_jwts(tmp_path: Path) -> None:
    path = write_log(
        tmp_path,
        "token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signature_123\n",
    )

    assert scan_file(str(path))["jwts"] == 1


def test_scan_file_detects_aws_keys(tmp_path: Path) -> None:
    path = write_log(tmp_path, "aws_access_key_id=AKIAABCDEFGHIJKLMNOP\n")

    assert scan_file(str(path))["aws_keys"] == 1


def test_scan_file_detects_api_keys(tmp_path: Path) -> None:
    path = write_log(tmp_path, "api_key=sk_test_1234567890abcdef\n")

    assert scan_file(str(path))["api_keys"] == 1


def test_scan_file_detects_private_key_blocks(tmp_path: Path) -> None:
    path = write_log(
        tmp_path,
        "-----BEGIN PRIVATE KEY-----\nabc123\n-----END PRIVATE KEY-----\n",
    )

    assert scan_file(str(path))["private_keys"] == 1


def test_scan_file_detects_uuids(tmp_path: Path) -> None:
    path = write_log(tmp_path, "request_id=123e4567-e89b-12d3-a456-426614174000\n")

    assert scan_file(str(path))["uuids"] == 1


def test_scan_file_detects_file_paths(tmp_path: Path) -> None:
    path = write_log(tmp_path, "failed to read /var/log/app.log\n")

    assert scan_file(str(path))["file_paths"] == 1


def test_scan_file_returns_structured_counts_for_mixed_logs(tmp_path: Path) -> None:
    path = write_log(
        tmp_path,
        "\n".join(
            [
                "user=jane@example.com from 10.0.0.1",
                "url=https://api.example.com/v1/users domain=internal.example.org",
                "jwt=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signature_123",
                "aws=AKIAABCDEFGHIJKLMNOP",
                "api_key=sk_test_1234567890abcdef",
                "path=/var/log/app.log",
                "request_id=123e4567-e89b-12d3-a456-426614174000",
                "-----BEGIN RSA PRIVATE KEY-----",
                "secret",
                "-----END RSA PRIVATE KEY-----",
            ],
        ),
    )

    assert scan_file(str(path)) == {
        "emails": 1,
        "ips": 1,
        "urls": 1,
        "domains": 1,
        "jwts": 1,
        "aws_keys": 1,
        "api_keys": 1,
        "private_keys": 1,
        "file_paths": 1,
        "uuids": 1,
    }


def test_scan_file_handles_empty_files(tmp_path: Path) -> None:
    path = write_log(tmp_path, "")

    assert scan_file(str(path)) == {
        "emails": 0,
        "ips": 0,
        "urls": 0,
        "domains": 0,
        "jwts": 0,
        "aws_keys": 0,
        "api_keys": 0,
        "private_keys": 0,
        "file_paths": 0,
        "uuids": 0,
    }


def test_scan_file_handles_logs_with_no_matches(tmp_path: Path) -> None:
    path = write_log(tmp_path, "INFO startup complete\nWARN retry scheduled\n")

    assert scan_file(str(path)) == {
        "emails": 0,
        "ips": 0,
        "urls": 0,
        "domains": 0,
        "jwts": 0,
        "aws_keys": 0,
        "api_keys": 0,
        "private_keys": 0,
        "file_paths": 0,
        "uuids": 0,
    }


def test_scan_file_handles_large_inputs_deterministically(tmp_path: Path) -> None:
    path = write_log(
        tmp_path,
        "\n".join(
            f"line {index} user=ops@example.com ip=10.0.0.1" for index in range(1000)
        ),
    )

    assert scan_file(str(path)) == {
        "emails": 1000,
        "ips": 1000,
        "urls": 0,
        "domains": 0,
        "jwts": 0,
        "aws_keys": 0,
        "api_keys": 0,
        "private_keys": 0,
        "file_paths": 0,
        "uuids": 0,
    }


def test_scan_file_handles_malformed_bytes(tmp_path: Path) -> None:
    path = tmp_path / "malformed.log"
    path.write_bytes(b"user=jane@example.com\n\xff\xfe\n")

    assert scan_file(str(path))["emails"] == 1


def test_scan_file_counts_logs_with_only_sensitive_data(tmp_path: Path) -> None:
    path = write_log(
        tmp_path,
        "\n".join(
            [
                "jane@example.com",
                "10.0.0.1",
                "https://api.example.com/v1/users",
                "internal.example.org",
                "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signature_123",
                "AKIAABCDEFGHIJKLMNOP",
                "sk_test_1234567890abcdef",
                "/var/log/app.log",
                "123e4567-e89b-12d3-a456-426614174000",
            ],
        ),
    )

    assert scan_file(str(path)) == {
        "emails": 1,
        "ips": 1,
        "urls": 1,
        "domains": 1,
        "jwts": 1,
        "aws_keys": 1,
        "api_keys": 1,
        "private_keys": 0,
        "file_paths": 1,
        "uuids": 1,
    }
