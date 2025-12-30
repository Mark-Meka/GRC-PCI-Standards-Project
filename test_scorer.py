# -*- coding: utf-8 -*-
import sys
import io

# Fix Windows console encoding for emojis
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

from scorer import score_code

# ============================================
# 3 TEST EXAMPLES - DIFFERENT SCORES
# ============================================

print("="*80)
print("[LOCK] PCI DSS REQUIREMENT 6 - CODE SCORING TESTS")
print("="*80)

# ============================================
# EXAMPLE 1: COMPLIANT CODE (Score 4-5/5)
# ============================================
print("\n" + "="*80)
print("[GREEN] EXAMPLE 1: COMPLIANT CODE - Expected Score 4-5/5")
print("="*80)

compliant_code = '''
import os
import hashlib
import logging
from decimal import Decimal, InvalidOperation
import re

# Configure secure logging (PCI DSS Requirement 10)
# Ensure logs are written to a secure location and do NOT contain Sensitive Authentication Data (SAD)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def process_payment_compliant(cursor, transaction_id: str, amount: str):
    """
    Processes a payment transaction with strict validation and audit logging.
    
    Args:
        cursor: The database cursor (must support parameterized queries).
        transaction_id: Unique identifier for the transaction.
        amount: The monetary amount as a string (to preserve precision).
    """
    
    # 1. Input Validation (OWASP & PCI DSS Requirement 6)
    # Ensure transaction_id is alphanumeric and reasonable length
    if not re.match(r'^[a-zA-Z0-9-]{10,64}$', str(transaction_id)):
        logging.warning(f"Invalid transaction_id format detected: {transaction_id}")
        raise ValueError("Invalid transaction ID format.")

    # 2. Secure Currency Handling (Avoid Floating Point Errors)
    try:
        # Always use Decimal for money. Floats introduce rounding artifacts.
        validated_amount = Decimal(amount)
        if validated_amount <= 0:
            raise ValueError("Amount must be positive.")
        
        # Quantize to 2 decimal places (standard currency format)
        validated_amount = validated_amount.quantize(Decimal("0.01"))
    except (InvalidOperation, ValueError) as e:
        logging.error(f"Invalid amount format for transaction {transaction_id}: {e}")
        return {"success": False, "error": "Invalid amount"}

    try:
        # 3. Secure Environment Variables
        # Ensure the key exists, but DO NOT log it.
        api_key = os.getenv('STRIPE_API_KEY')
        if not api_key:
            logging.critical("Payment Gateway API Key is missing from environment.")
            raise EnvironmentError("Server misconfiguration.")

        # 4. Hashing (Integrity Check)
        # Using SHA-256 is good for integrity. 
        # Note: If transaction_id is a Credit Card PAN, you MUST use a Salt.
        transaction_hash = hashlib.sha256(str(transaction_id).encode('utf-8')).hexdigest()

        # 5. Parameterized Query (Prevention of SQL Injection)
        # The '?' syntax depends on the DB driver (SQLite/ODBC). 
        # Use %s for PostgreSQL/MySQL connectors if needed.
        query = "INSERT INTO transactions (id, amount, hash) VALUES (?, ?, ?)"
        
        # Execute securely
        cursor.execute(query, (transaction_id, str(validated_amount), transaction_hash))
        
        # 6. Audit Logging (Success)
        logging.info(f"Transaction {transaction_id} processed successfully. Hash: {transaction_hash}")
        
        return {"success": True}

    except Exception as e:
        # 7. Secure Error Handling
        # Log the full error internally, but return a generic error to the user
        logging.error(f"Database error processing transaction {transaction_id}: {str(e)}")
        return {"success": False, "error": "Internal processing error."}

'''

print("\n📝 CODE:")
print(compliant_code)
print("\n📊 RESULT:")

result1 = score_code(compliant_code)

print(f"  Score:              {result1['score']}/5")
print(f"  Status:             {result1['status']}")
print(f"  Reason:             {result1['reason']}")
print(f"  Violations:         {result1['violations']}")
print(f"  Critical:           {result1['critical_violations']}")
print(f"  Confidence:         {result1['confidence']:.2f}%")

if 'recommendations' in result1:
    print("\n  💡 Recommendations:")
    for rec in result1['recommendations']:
        print(f"     - {rec}")


# ============================================
# EXAMPLE 2: NON-COMPLIANT CODE (Score 1-2/5)
# ============================================
print("\n\n" + "="*80)
print("[RED] EXAMPLE 2: NON-COMPLIANT CODE - Expected Score 1-2/5")
print("="*80)

non_compliant_code = '''
password = "admin123"
api_key = "sk_live_51H3xYz2eZvKYlo2C"
secret = "my_secret_key"

def get_user(username):
    query = "SELECT * FROM users WHERE name = '" + username + "'"
    result = db.execute(query)
    
    import hashlib
    pwd_hash = hashlib.md5(password.encode()).hexdigest()
    
    return result
'''

print("\n📝 CODE:")
print(non_compliant_code)
print("\n📊 RESULT:")

result2 = score_code(non_compliant_code)

print(f"  Score:              {result2['score']}/5")
print(f"  Status:             {result2['status']}")
print(f"  Reason:             {result2['reason']}")
print(f"  Violations:         {result2['violations']}")
print(f"  Critical:           {result2['critical_violations']}")
print(f"  Confidence:         {result2['confidence']:.2f}%")

if 'recommendations' in result2:
    print("\n  💡 Recommendations:")
    for rec in result2['recommendations']:
        print(f"     - {rec}")


# ============================================
# EXAMPLE 3: PARTIAL COMPLIANCE (Score 2-3/5)
# ============================================
print("\n\n" + "="*80)
print("[YELLOW] EXAMPLE 3: PARTIAL COMPLIANCE - Expected Score 2-3/5")
print("="*80)

partial_code = '''
import os
import hashlib
import logging

# Basic logging setup
logging.basicConfig(level=logging.INFO)

def process_payment_partial(cursor, transaction_id, amount):
    api_key = os.getenv('STRIPE_API_KEY')
    
    # [PARTIAL FIX] Basic check for key, but no specific exception handling
    if not api_key:
        print("Error: API Key missing")
        return

    try:
        # [FAIL] Still using float (Violation of financial data integrity)
        # It validates that it IS a number, but allows precision errors.
        validated_amount = float(amount)
        
        # [PARTIAL FIX] Basic logic check
        if validated_amount <= 0:
            return {"success": False, "error": "Amount must be positive"}

        # [FAIL] Hashing without a Salt
        # Using SHA-256 is "strong", but without a salt, predictable IDs are vulnerable to Rainbow Tables.
        transaction_hash = hashlib.sha256(str(transaction_id).encode()).hexdigest()

        # [PASS] Parameterized Query
        # This fixes the SQL Injection vulnerability. This is the "Strong" part.
        query = "INSERT INTO transactions (id, amount, hash) VALUES (?, ?, ?)"
        cursor.execute(query, (transaction_id, validated_amount, transaction_hash))
        
        # [FAIL] Logging Sensitive Data (PCI DSS Requirement 10 Violation)
        # Logging the Transaction ID connects the log to a specific user inappropriately if not masked.
        logging.info(f"Success: Processed {transaction_id} with hash {transaction_hash}")

        return {"success": True}

    except Exception as e:
        # [FAIL] Information Disclosure
        # Returning the raw error string (str(e)) gives hackers clues about your DB schema.
        logging.error(f"DB Error: {str(e)}")
        return {"success": False, "error": str(e)}
'''

print("\n📝 CODE:")
print(partial_code)
print("\n📊 RESULT:")

result3 = score_code(partial_code)

print(f"  Score:              {result3['score']}/5")
print(f"  Status:             {result3['status']}")
print(f"  Reason:             {result3['reason']}")
print(f"  Violations:         {result3['violations']}")
print(f"  Critical:           {result3['critical_violations']}")
print(f"  Confidence:         {result3['confidence']:.2f}%")

if 'recommendations' in result3:
    print("\n  💡 Recommendations:")
    for rec in result3['recommendations']:
        print(f"     - {rec}")


# ============================================
# SUMMARY COMPARISON
# ============================================
print("\n\n" + "="*80)
print("[SUMMARY] - COMPARISON TABLE")
print("="*80)

print(f"\n{'Example':<12} {'Score':<8} {'Status':<18} {'Violations':<12} {'Critical':<10}")
print("-"*80)
print(f"{'Compliant':<12} {result1['score']:<8} {result1['status']:<18} {result1['violations']:<12} {result1['critical_violations']:<10}")
print(f"{'Non-Compliant':<12} {result2['score']:<8} {result2['status']:<18} {result2['violations']:<12} {result2['critical_violations']:<10}")
print(f"{'Partial':<12} {result3['score']:<8} {result3['status']:<18} {result3['violations']:<12} {result3['critical_violations']:<10}")
print("="*80)

# ============================================
# VALIDATE DIFFERENT OUTPUTS
# ============================================
print("\n[VALIDATION]:")
scores = [result1['score'], result2['score'], result3['score']]
if len(scores) == len(set(scores)):
    print("[OK] SUCCESS: All 3 examples have DIFFERENT scores!")
else:
    print("[!] WARNING: Some scores are the same - check your scorer.py")

print("\n[OK] Test complete!\n")