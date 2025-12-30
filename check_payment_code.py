from pci_compliance_checker import check_payment_code, is_compliant

# Example 1: Quick check
user_code = """
def process_payment(card):
    api_key = "sk_live_123"
    return charge(card)
"""

result = check_payment_code(user_code)
print(f"Status: {result['status']}")
print(f"Confidence: {result['confidence']}%")

# Example 2: Boolean check
if is_compliant(user_code):
    print("Code is compliant")
else:
    print("Code has violations")