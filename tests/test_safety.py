from safelog.safety import check_safety


def test_check_safety_returns_safe_when_no_high_risk_findings() -> None:
    result = check_safety({"private_keys": 0, "aws_keys": 0})

    assert result == {
        "status": "safe",
        "reason": "No high-risk secrets detected.",
    }


def test_check_safety_returns_warn_for_aws_keys() -> None:
    result = check_safety({"private_keys": 0, "aws_keys": 1})

    assert result == {
        "status": "warn",
        "reason": "Warning: AWS-style key detected. Review before sharing logs.",
    }


def test_check_safety_returns_block_for_private_keys() -> None:
    result = check_safety({"private_keys": 1, "aws_keys": 0})

    assert result == {
        "status": "block",
        "reason": "Analysis blocked: possible private key detected.",
    }


def test_check_safety_defaults_missing_counts_to_safe() -> None:
    result = check_safety({})

    assert result["status"] == "safe"


def test_check_safety_block_takes_precedence_over_warn() -> None:
    result = check_safety({"private_keys": 1, "aws_keys": 1})

    assert result["status"] == "block"
