from safelog.rules import CustomRule


def _matching_custom_rule(
    scan_results: dict[str, int],
    custom_rules: list[CustomRule] | None,
    severity: str,
) -> CustomRule | None:
    for rule in custom_rules or []:
        if rule.severity == severity and scan_results.get(rule.key, 0) > 0:
            return rule
    return None


def check_safety(
    scan_results: dict[str, int],
    custom_rules: list[CustomRule] | None = None,
) -> dict[str, str]:
    """Return safety status based on scanner result counts."""
    if scan_results.get("private_keys", 0) > 0:
        return {
            "status": "block",
            "reason": "Analysis blocked: possible private key detected.",
        }

    custom_block = _matching_custom_rule(scan_results, custom_rules, "block")
    if custom_block is not None:
        return {
            "status": "block",
            "reason": f"Analysis blocked: custom rule {custom_block.name} detected.",
        }

    if scan_results.get("aws_keys", 0) > 0:
        return {
            "status": "warn",
            "reason": "Warning: AWS-style key detected. Review before sharing logs.",
        }

    custom_warn = _matching_custom_rule(scan_results, custom_rules, "warn")
    if custom_warn is not None:
        return {
            "status": "warn",
            "reason": f"Warning: custom rule {custom_warn.name} detected. Review before sharing logs.",
        }

    return {
        "status": "safe",
        "reason": "No high-risk secrets detected.",
    }
