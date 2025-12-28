from rules import NON_COMPLIANT_PATTERNS

def score_code(code: str):
    code_lower = code.lower()
    violations = []

    for rule, patterns in NON_COMPLIANT_PATTERNS.items():
        for p in patterns:
            if p.lower() in code_lower:
                violations.append(rule)
                break

    if not violations:
        return {
            "score": 5,
            "status": "Compliant",
            "reason": "No PCI DSS Requirement 6 violations detected."
        }

    if len(violations) == 1:
        return {
            "score": 3,
            "status": "Partially Compliant",
            "reason": f"Minor issue detected: {violations}"
        }

    return {
        "score": 1,
        "status": "Non-Compliant",
        "reason": f"Multiple violations detected: {violations}"
    }