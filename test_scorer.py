from scorer import score_code

# Test with non-compliant code
test_code = 'password = "admin123"'
result = score_code(test_code)

print(f"Score: {result['score']}/5")
print(f"Status: {result['status']}")
print(f"Reason: {result['reason']}")
print(f"Violations: {result['violations']}")
print(f"Confidence: {result['confidence']}%")

if 'recommendations' in result:
    print("\nRecommendations:")
    for rec in result['recommendations']:
        print(f"  - {rec}")
