from pci_compliance_checker import PCIComplianceChecker

# Initialize the PCI compliance checker with the trained model
_checker = None

def get_checker():

    global _checker
    if _checker is None:
        _checker = PCIComplianceChecker('pci_rag_model.pkl')
    return _checker

def score_code(code: str):

    checker = get_checker()
    result = checker.check_code(code, detailed=True)
    
    # Map compliance result to score (1-5 scale)
    if result['status'] == 'COMPLIANT':
        score = 5
        status = "Compliant"
        reason = "No PCI DSS Requirement 6 violations detected."
    elif result['critical_violations'] > 0:
        score = 1
        status = "Non-Compliant"
        reason = f"Critical violations detected: {result['critical_violations']} critical, {result['violations']} total"
    elif result['violations'] >= 3:
        score = 2
        status = "Non-Compliant"
        reason = f"Multiple violations detected: {result['violations']}"
    elif result['violations'] >= 1:
        score = 3
        status = "Partially Compliant"
        reason = f"Minor issues detected: {result['violations']} violation(s)"
    else:
        score = 4
        status = "Compliant"
        reason = "No significant violations detected."
    
    # Add detailed information if available
    response = {
        "score": score,
        "status": status,
        "reason": reason,
        "confidence": result.get('confidence', 0),
        "violations": result.get('violations', 0),
        "critical_violations": result.get('critical_violations', 0)
    }
    
    # Add recommendations if available
    if 'recommendations' in result:
        response['recommendations'] = result['recommendations']
    
    return response