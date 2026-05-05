def check_safety(scan_results: dict[str, int]) -> dict[str, str]:
    """Return safety status based on scanner result counts."""
    if scan_results.get("private_keys", 0) > 0:
        return {
            "status": "block",
            "reason": "Analysis blocked: possible private key detected.",
        }

    if scan_results.get("aws_keys", 0) > 0:
        return {
            "status": "warn",
            "reason": "Warning: AWS-style key detected. Review before sharing logs.",
        }

    return {
        "status": "safe",
        "reason": "No high-risk secrets detected.",
    }
