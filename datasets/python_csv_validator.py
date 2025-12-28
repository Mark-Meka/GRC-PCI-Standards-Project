"""
CSV Dataset Validator for PCI DSS Project
Validates your compliant and non-compliant datasets before running RAG
"""

import pandas as pd
import sys
import os

# Fix UTF-8 encoding for Windows console to display emoji characters
if sys.platform == 'win32':
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
    sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')

# File paths for PCI DSS datasets
COMPLIANT_CSV_PATH = r"c:\Users\marco\Downloads\GRC-PCI-Standards-Project\pci_dss_req6_compliant_code_dataset.csv"
NON_COMPLIANT_CSV_PATH = r"c:\Users\marco\Downloads\GRC-PCI-Standards-Project\pci_dss_req6_non_compliant_code_dataset.csv"

def validate_csv(file_path: str, expected_label: str):
    """Validate CSV structure and content"""
    print(f"\n{'='*60}")
    print(f"Validating: {file_path}")
    print(f"{'='*60}")
    
    try:
        # Load CSV
        df = pd.read_csv(file_path)
        print(f"✅ File loaded successfully")
        print(f"   Rows: {len(df)}")
        print(f"   Columns: {len(df.columns)}")
        
        # Check columns
        print(f"\n📋 Columns found:")
        for col in df.columns:
            print(f"   - {col}")
        
        # Check for code column
        code_columns = ['code', 'Code', 'code_snippet', 'source_code', 'snippet', 'code_example']
        code_col = None
        for col in code_columns:
            if col in df.columns:
                code_col = col
                break
        
        if code_col:
            print(f"\n✅ Code column found: '{code_col}'")
            
            # Show sample
            sample = df[code_col].iloc[0] if len(df) > 0 else "N/A"
            print(f"\n📄 Sample code (first 200 chars):")
            print(f"   {sample[:200]}...")
            
            # Check for empty values
            empty_count = df[code_col].isna().sum()
            if empty_count > 0:
                print(f"\n⚠️  Warning: {empty_count} empty code entries found")
            else:
                print(f"\n✅ No empty code entries")
        else:
            print(f"\n❌ ERROR: No code column found!")
            print(f"   Available columns: {list(df.columns)}")
            print(f"   Expected one of: {code_columns}")
            return False
        
        # Check for requirement_id column
        if 'requirement_id' in df.columns:
            print(f"\n✅ Requirement ID column found")
            unique_reqs = df['requirement_id'].nunique()
            print(f"   Unique requirements: {unique_reqs}")
        else:
            print(f"\n⚠️  Warning: No 'requirement_id' column (optional)")
        
        # Dataset-specific checks
        if expected_label == 'compliant':
            print(f"\n✅ COMPLIANT dataset validated")
        else:
            print(f"\n✅ NON-COMPLIANT dataset validated")
            if 'violation_type' in df.columns:
                print(f"   Violation types found:")
                for vtype in df['violation_type'].unique()[:5]:
                    count = (df['violation_type'] == vtype).sum()
                    print(f"      - {vtype}: {count} examples")
        
        # Summary
        print(f"\n{'='*60}")
        print(f"VALIDATION SUMMARY")
        print(f"{'='*60}")
        print(f"✅ File is valid and ready for RAG system")
        print(f"   Total examples: {len(df)}")
        print(f"   Code column: '{code_col}'")
        print(f"   Empty entries: {empty_count}")
        
        return True
        
    except FileNotFoundError:
        print(f"❌ ERROR: File not found: {file_path}")
        return False
    except pd.errors.EmptyDataError:
        print(f"❌ ERROR: File is empty")
        return False
    except Exception as e:
        print(f"❌ ERROR: {e}")
        return False


def generate_sample_csv():
    """Generate sample CSV files for testing"""
    print(f"\n{'='*60}")
    print("GENERATING SAMPLE CSV FILES")
    print(f"{'='*60}")
    
    # Sample compliant code
    compliant_data = {
        'code': [
            """def process_payment(card_data):
    # Use parameterized query
    query = "SELECT * FROM transactions WHERE card_id = ?"
    result = db.execute(query, (card_data['id'],))
    
    # Strong encryption
    from cryptography.fernet import Fernet
    encrypted = Fernet.encrypt(card_data['number'])
    
    return result""",
            
            """def authenticate_user(username, password):
    # Secure password hashing
    import bcrypt
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    
    # Input validation
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        raise ValueError("Invalid username")
    
    return verify_credentials(username, hashed)""",
            
            """def log_transaction(transaction):
    # Proper error handling
    try:
        db.insert(transaction)
        logger.info(f"Transaction {transaction.id} logged")
    except Exception as e:
        logger.error(f"Failed to log transaction: {e}")
        raise"""
        ],
        'requirement_id': ['REQ_6.2.4', 'REQ_6.2.4', 'REQ_6.2.1'],
        'description': [
            'Uses parameterized queries and strong encryption',
            'Secure password hashing with input validation',
            'Proper error handling and logging'
        ]
    }
    
    # Sample non-compliant code
    non_compliant_data = {
        'code': [
            """def process_payment(card_number, cvv):
    # SQL Injection vulnerability
    query = "SELECT * FROM cards WHERE number = '" + card_number + "'"
    return db.execute(query)""",
            
            """def connect_api():
    # Hardcoded credentials
    api_key = "sk_live_1234567890abcdef"
    password = "admin123"
    return requests.post(url, auth=(api_key, password))""",
            
            """def encrypt_data(data):
    # Weak cryptography
    import hashlib
    return hashlib.md5(data.encode()).hexdigest()""",
            
            """def get_user_data(user_id):
    # No input validation
    data = request.GET['user_data']
    return eval(data)  # Dangerous!""",
            
            """def payment_handler():
    # Debug mode enabled
    DEBUG = True
    if DEBUG:
        print(f"Card number: {card_number}")"""
        ],
        'requirement_id': ['REQ_6.2.4', 'REQ_6.2.4', 'REQ_6.2.4', 'REQ_6.2.4', 'REQ_6.5.1'],
        'violation_type': [
            'sql_injection',
            'hardcoded_credentials',
            'weak_crypto',
            'no_input_validation',
            'debug_mode'
        ],
        'description': [
            'SQL injection vulnerability',
            'Hardcoded API credentials',
            'Weak MD5 hashing',
            'Missing input validation',
            'Debug mode in production'
        ]
    }
    
    # Create DataFrames
    compliant_df = pd.DataFrame(compliant_data)
    non_compliant_df = pd.DataFrame(non_compliant_data)
    
    # Save to CSV
    compliant_df.to_csv('pci_dss_req6_compliant_code_dataset.csv', index=False)
    non_compliant_df.to_csv('pci_dss_req6_non_compliant_code_dataset.csv', index=False)
    
    print(f"✅ Generated: pci_dss_req6_compliant_code_dataset.csv ({len(compliant_df)} examples)")
    print(f"✅ Generated: pci_dss_req6_non_compliant_code_dataset.csv ({len(non_compliant_df)} examples)")
    print(f"\n💡 You can now run the RAG system with these sample files!")


def main():
    print("="*60)
    print("PCI DSS DATASET VALIDATOR")
    print("="*60)
    
    # Check if files exist
    import os
    
    compliant_exists = os.path.exists(COMPLIANT_CSV_PATH)
    non_compliant_exists = os.path.exists(NON_COMPLIANT_CSV_PATH)
    
    if not compliant_exists and not non_compliant_exists:
        print("\n❌ No dataset files found!")
        print("\n💡 Would you like to generate sample CSV files? (y/n)")
        choice = input("> ").strip().lower()
        
        if choice == 'y':
            generate_sample_csv()
            print("\n✅ Sample files generated! Re-running validation...\n")
            compliant_exists = True
            non_compliant_exists = True
        else:
            print("\n📋 Please create these files:")
            print("   1. pci_dss_req6_compliant_code_dataset.csv")
            print("   2. pci_dss_req6_non_compliant_code_dataset.csv")
            sys.exit(1)
    
    # Validate files
    compliant_valid = False
    non_compliant_valid = False
    
    if compliant_exists:
        compliant_valid = validate_csv(
            COMPLIANT_CSV_PATH,
            'compliant'
        )
    
    if non_compliant_exists:
        non_compliant_valid = validate_csv(
            NON_COMPLIANT_CSV_PATH,
            'non_compliant'
        )
    
    # Final summary
    print(f"\n{'='*60}")
    print("FINAL VALIDATION STATUS")
    print(f"{'='*60}")
    
    if compliant_valid and non_compliant_valid:
        print("✅ Both datasets are valid!")
        print("\n🚀 Ready to run RAG system!")
        print("\nNext steps:")
        print("   1. Upload CSV files to Kaggle")
        print("   2. Copy the RAG system code to Kaggle notebook")
        print("   3. Run compliance checks on user code")
    else:
        print("❌ Some datasets have issues. Please fix them before running RAG.")


if __name__ == "__main__":
    main()