"""
PCI DSS Requirement 6 Compliance Checker - GUI Application
A modern graphical interface for checking code compliance with PCI DSS standards
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import sys
from datetime import datetime

# Import our compliance modules
from pci_compliance_checker import PCIComplianceChecker
from scorer import score_code

# Example codes for testing
EXAMPLE_CODES = {
    "Compliant Code": '''import os
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
''',
    
    "Non-Compliant Code": '''# WARNING: Multiple PCI violations below!
password = "admin123"
api_key = "sk_live_51H3xYz2eZvKYlo2C"
secret = "my_secret_key"

def get_user(username):
    # SQL Injection vulnerability
    query = "SELECT * FROM users WHERE name = '" + username + "'"
    result = db.execute(query)
    
    # Weak hashing algorithm
    import hashlib
    pwd_hash = hashlib.md5(password.encode()).hexdigest()
    
    return result
''',
    
    "Mixed Code": '''import hashlib

def hash_cvv(cvv):
    # Using MD5 (weak hashing)
    return hashlib.md5(cvv.encode()).hexdigest()

def store_payment(card_id, amount):
    # Good: Parameterized query
    query = "INSERT INTO payments (card, amount) VALUES (?, ?)"
    cursor.execute(query, (card_id, amount))
    
    return True
'''
}


class PCIComplianceGUI:
    """Main GUI application for PCI compliance checking"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("PCI DSS Requirement 6 - Code Compliance Checker")
        self.root.geometry("1200x800")
        self.root.minsize(900, 600)
        
        # Initialize checker
        try:
            self.checker = PCIComplianceChecker('pci_rag_model.pkl')
            self.checker_loaded = True
        except Exception as e:
            self.checker_loaded = False
            messagebox.showerror("Error", f"Failed to load PCI model: {str(e)}")
        
        # Store last results
        self.last_result = None
        
        # Configure colors
        self.colors = {
            'bg': '#1e1e2e',
            'fg': '#cdd6f4',
            'accent': '#89b4fa',
            'success': '#a6e3a1',
            'warning': '#f9e2af',
            'error': '#f38ba8',
            'surface': '#313244',
            'surface_light': '#45475a',
            'text': '#cdd6f4',
            'text_dim': '#a6adc8'
        }
        
        # Configure root window
        self.root.configure(bg=self.colors['bg'])
        
        # Setup UI
        self.create_widgets()
        
    def create_widgets(self):
        """Create all GUI widgets"""
        
        # Header
        header_frame = tk.Frame(self.root, bg=self.colors['accent'], height=80)
        header_frame.pack(fill='x', padx=0, pady=0)
        header_frame.pack_propagate(False)
        
        header_label = tk.Label(
            header_frame,
            text="🔒 PCI DSS Requirement 6 - Code Compliance Checker",
            font=('Segoe UI', 20, 'bold'),
            bg=self.colors['accent'],
            fg='#1e1e2e'
        )
        header_label.pack(pady=20)
        
        subtitle = tk.Label(
            header_frame,
            text="Automated code analysis for payment card industry data security standards",
            font=('Segoe UI', 10),
            bg=self.colors['accent'],
            fg='#313244'
        )
        subtitle.pack()
        
        # Main container
        main_frame = tk.Frame(self.root, bg=self.colors['bg'])
        main_frame.pack(fill='both', expand=True, padx=20, pady=20)
        
        # Create notebook (tabs)
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure tab styles
        style.configure('TNotebook', background=self.colors['bg'], borderwidth=0)
        style.configure('TNotebook.Tab', 
                       background=self.colors['surface'],
                       foreground=self.colors['text'],
                       padding=[20, 10],
                       font=('Segoe UI', 10, 'bold'))
        style.map('TNotebook.Tab',
                 background=[('selected', self.colors['accent'])],
                 foreground=[('selected', '#1e1e2e')])
        
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill='both', expand=True)
        
        # Create tabs
        self.create_checker_tab()
        self.create_scorer_tab()
        self.create_examples_tab()
        
    def create_checker_tab(self):
        """Create the code checker tab"""
        tab = tk.Frame(self.notebook, bg=self.colors['bg'])
        self.notebook.add(tab, text='Code Checker')
        
        # Left panel - Code input
        left_panel = tk.Frame(tab, bg=self.colors['bg'])
        left_panel.pack(side='left', fill='both', expand=True, padx=(0, 10))
        
        tk.Label(
            left_panel,
            text="Enter Code to Check:",
            font=('Segoe UI', 12, 'bold'),
            bg=self.colors['bg'],
            fg=self.colors['text']
        ).pack(anchor='w', pady=(0, 10))
        
        # Code input area
        self.checker_code_input = scrolledtext.ScrolledText(
            left_panel,
            wrap=tk.WORD,
            font=('Consolas', 10),
            bg=self.colors['surface'],
            fg=self.colors['text'],
            insertbackground=self.colors['accent'],
            relief='flat',
            padx=10,
            pady=10
        )
        self.checker_code_input.pack(fill='both', expand=True, pady=(0, 10))
        
        # Buttons frame
        btn_frame = tk.Frame(left_panel, bg=self.colors['bg'])
        btn_frame.pack(fill='x')
        
        self.create_button(
            btn_frame,
            "Check Compliance",
            self.check_compliance,
            self.colors['accent']
        ).pack(side='left', padx=(0, 10))
        
        self.create_button(
            btn_frame,
            "Load Example",
            lambda: self.load_example('checker'),
            self.colors['surface_light']
        ).pack(side='left', padx=(0, 10))
        
        self.create_button(
            btn_frame,
            "Clear",
            lambda: self.checker_code_input.delete('1.0', tk.END),
            self.colors['surface_light']
        ).pack(side='left')
        
        # Right panel - Results
        right_panel = tk.Frame(tab, bg=self.colors['bg'])
        right_panel.pack(side='right', fill='both', expand=True, padx=(10, 0))
        
        tk.Label(
            right_panel,
            text="Compliance Results:",
            font=('Segoe UI', 12, 'bold'),
            bg=self.colors['bg'],
            fg=self.colors['text']
        ).pack(anchor='w', pady=(0, 10))
        
        # Results display
        self.checker_results = scrolledtext.ScrolledText(
            right_panel,
            wrap=tk.WORD,
            font=('Segoe UI', 10),
            bg=self.colors['surface'],
            fg=self.colors['text'],
            relief='flat',
            padx=15,
            pady=15,
            state='disabled'
        )
        self.checker_results.pack(fill='both', expand=True, pady=(0, 10))
        
        # Export button
        self.create_button(
            right_panel,
            "Export Results",
            lambda: self.export_results('checker'),
            self.colors['success']
        ).pack(anchor='e')
        
    def create_scorer_tab(self):
        """Create the code scorer tab"""
        tab = tk.Frame(self.notebook, bg=self.colors['bg'])
        self.notebook.add(tab, text='Code Scorer')
        
        # Left panel - Code input
        left_panel = tk.Frame(tab, bg=self.colors['bg'])
        left_panel.pack(side='left', fill='both', expand=True, padx=(0, 10))
        
        tk.Label(
            left_panel,
            text="Enter Code to Score:",
            font=('Segoe UI', 12, 'bold'),
            bg=self.colors['bg'],
            fg=self.colors['text']
        ).pack(anchor='w', pady=(0, 10))
        
        # Code input area
        self.scorer_code_input = scrolledtext.ScrolledText(
            left_panel,
            wrap=tk.WORD,
            font=('Consolas', 10),
            bg=self.colors['surface'],
            fg=self.colors['text'],
            insertbackground=self.colors['accent'],
            relief='flat',
            padx=10,
            pady=10
        )
        self.scorer_code_input.pack(fill='both', expand=True, pady=(0, 10))
        
        # Buttons frame
        btn_frame = tk.Frame(left_panel, bg=self.colors['bg'])
        btn_frame.pack(fill='x')
        
        self.create_button(
            btn_frame,
            "Score Code",
            self.score_code_gui,
            self.colors['accent']
        ).pack(side='left', padx=(0, 10))
        
        self.create_button(
            btn_frame,
            "Load Example",
            lambda: self.load_example('scorer'),
            self.colors['surface_light']
        ).pack(side='left', padx=(0, 10))
        
        self.create_button(
            btn_frame,
            "Clear",
            lambda: self.scorer_code_input.delete('1.0', tk.END),
            self.colors['surface_light']
        ).pack(side='left')
        
        # Right panel - Score display
        right_panel = tk.Frame(tab, bg=self.colors['bg'])
        right_panel.pack(side='right', fill='both', expand=True, padx=(10, 0))
        
        tk.Label(
            right_panel,
            text="Compliance Score:",
            font=('Segoe UI', 12, 'bold'),
            bg=self.colors['bg'],
            fg=self.colors['text']
        ).pack(anchor='w', pady=(0, 10))
        
        # Score display frame
        score_frame = tk.Frame(right_panel, bg=self.colors['surface'], relief='flat')
        score_frame.pack(fill='x', pady=(0, 15))
        
        self.score_label = tk.Label(
            score_frame,
            text="--/5",
            font=('Segoe UI', 48, 'bold'),
            bg=self.colors['surface'],
            fg=self.colors['text']
        )
        self.score_label.pack(pady=20)
        
        self.score_stars = tk.Label(
            score_frame,
            text="☆☆☆☆☆",
            font=('Segoe UI', 24),
            bg=self.colors['surface'],
            fg=self.colors['warning']
        )
        self.score_stars.pack(pady=(0, 20))
        
        # Results display
        self.scorer_results = scrolledtext.ScrolledText(
            right_panel,
            wrap=tk.WORD,
            font=('Segoe UI', 10),
            bg=self.colors['surface'],
            fg=self.colors['text'],
            relief='flat',
            padx=15,
            pady=15,
            state='disabled'
        )
        self.scorer_results.pack(fill='both', expand=True, pady=(0, 10))
        
        # Export button
        self.create_button(
            right_panel,
            "Export Results",
            lambda: self.export_results('scorer'),
            self.colors['success']
        ).pack(anchor='e')
        
    def create_examples_tab(self):
        """Create the test examples tab"""
        tab = tk.Frame(self.notebook, bg=self.colors['bg'])
        self.notebook.add(tab, text='Test Examples')
        
        # Top section - Example selector
        top_frame = tk.Frame(tab, bg=self.colors['bg'])
        top_frame.pack(fill='x', pady=(0, 20))
        
        tk.Label(
            top_frame,
            text="Select Example Code:",
            font=('Segoe UI', 12, 'bold'),
            bg=self.colors['bg'],
            fg=self.colors['text']
        ).pack(side='left', padx=(0, 10))
        
        self.example_var = tk.StringVar(value="Compliant Code")
        example_dropdown = ttk.Combobox(
            top_frame,
            textvariable=self.example_var,
            values=list(EXAMPLE_CODES.keys()),
            state='readonly',
            font=('Segoe UI', 10),
            width=30
        )
        example_dropdown.pack(side='left', padx=(0, 10))
        
        self.create_button(
            top_frame,
            "Run Test",
            self.run_example_test,
            self.colors['accent']
        ).pack(side='left', padx=(0, 10))
        
        self.create_button(
            top_frame,
            "Run All Tests",
            self.run_all_tests,
            self.colors['success']
        ).pack(side='left')
        
        # Code display
        tk.Label(
            tab,
            text="Example Code:",
            font=('Segoe UI', 11, 'bold'),
            bg=self.colors['bg'],
            fg=self.colors['text']
        ).pack(anchor='w', pady=(0, 10))
        
        self.example_code_display = scrolledtext.ScrolledText(
            tab,
            wrap=tk.WORD,
            font=('Consolas', 9),
            bg=self.colors['surface'],
            fg=self.colors['text'],
            relief='flat',
            padx=10,
            pady=10,
            height=12
        )
        self.example_code_display.pack(fill='x', pady=(0, 20))
        
        # Results display
        tk.Label(
            tab,
            text="Test Results:",
            font=('Segoe UI', 11, 'bold'),
            bg=self.colors['bg'],
            fg=self.colors['text']
        ).pack(anchor='w', pady=(0, 10))
        
        self.example_results = scrolledtext.ScrolledText(
            tab,
            wrap=tk.WORD,
            font=('Segoe UI', 10),
            bg=self.colors['surface'],
            fg=self.colors['text'],
            relief='flat',
            padx=15,
            pady=15,
            state='disabled'
        )
        self.example_results.pack(fill='both', expand=True)
        
    def create_button(self, parent, text, command, bg_color):
        """Create a styled button"""
        btn = tk.Button(
            parent,
            text=text,
            command=command,
            font=('Segoe UI', 10, 'bold'),
            bg=bg_color,
            fg='#1e1e2e' if bg_color in [self.colors['accent'], self.colors['success'], self.colors['warning']] else self.colors['text'],
            activebackground=bg_color,
            relief='flat',
            padx=20,
            pady=10,
            cursor='hand2',
            borderwidth=0
        )
        return btn
        
    def check_compliance(self):
        """Check code compliance"""
        if not self.checker_loaded:
            messagebox.showerror("Error", "Compliance checker not loaded!")
            return
            
        code = self.checker_code_input.get('1.0', tk.END).strip()
        if not code:
            messagebox.showwarning("Warning", "Please enter code to check!")
            return
            
        try:
            # Get detailed results
            result = self.checker.check_code(code, detailed=True)
            self.last_result = result
            
            # Format results
            self.checker_results.config(state='normal')
            self.checker_results.delete('1.0', tk.END)
            
            # Status header
            status = result['status']
            status_color = self.colors['success'] if status == 'COMPLIANT' else self.colors['error']
            
            self.checker_results.insert(tk.END, f"{'='*60}\n", 'header')
            self.checker_results.insert(tk.END, f"COMPLIANCE STATUS: {status}\n", 'status')
            self.checker_results.insert(tk.END, f"{'='*60}\n\n", 'header')
            
            # Confidence
            conf = result['confidence']
            self.checker_results.insert(tk.END, f"Confidence: {conf:.1f}%\n", 'bold')
            self.checker_results.insert(tk.END, f"{'█' * int(conf/5)}\n\n", 'progress')
            
            # Violations
            violations = result.get('violations', 0)
            critical = result.get('critical_violations', 0)
            
            self.checker_results.insert(tk.END, f"Total Violations: {violations}\n", 'bold')
            self.checker_results.insert(tk.END, f"Critical Violations: {critical}\n\n", 'critical')
            
            # Recommendations
            if 'recommendations' in result and result['recommendations']:
                self.checker_results.insert(tk.END, "Recommendations:\n", 'header')
                self.checker_results.insert(tk.END, f"{'-'*60}\n", 'header')
                for i, rec in enumerate(result['recommendations'], 1):
                    self.checker_results.insert(tk.END, f"{i}. {rec}\n\n", 'rec')
            else:
                self.checker_results.insert(tk.END, "✓ No violations found. Code appears compliant.\n", 'success')
            
            # Configure tags
            self.checker_results.tag_config('header', foreground=self.colors['text_dim'])
            self.checker_results.tag_config('status', foreground=status_color, font=('Segoe UI', 14, 'bold'))
            self.checker_results.tag_config('bold', font=('Segoe UI', 10, 'bold'))
            self.checker_results.tag_config('critical', foreground=self.colors['error'], font=('Segoe UI', 10, 'bold'))
            self.checker_results.tag_config('success', foreground=self.colors['success'], font=('Segoe UI', 10, 'bold'))
            self.checker_results.tag_config('rec', foreground=self.colors['text'])
            self.checker_results.tag_config('progress', foreground=self.colors['accent'])
            
            self.checker_results.config(state='disabled')
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to check compliance: {str(e)}")
            
    def score_code_gui(self):
        """Score code and display results"""
        code = self.scorer_code_input.get('1.0', tk.END).strip()
        if not code:
            messagebox.showwarning("Warning", "Please enter code to score!")
            return
            
        try:
            result = score_code(code)
            self.last_result = result
            
            # Update score display
            score = result['score']
            self.score_label.config(text=f"{score}/5")
            
            # Color code the score
            if score >= 4:
                score_color = self.colors['success']
            elif score >= 3:
                score_color = self.colors['warning']
            else:
                score_color = self.colors['error']
            self.score_label.config(fg=score_color)
            
            # Update stars
            stars = '★' * score + '☆' * (5 - score)
            self.score_stars.config(text=stars, fg=score_color)
            
            # Format detailed results
            self.scorer_results.config(state='normal')
            self.scorer_results.delete('1.0', tk.END)
            
            self.scorer_results.insert(tk.END, f"{'='*60}\n", 'header')
            self.scorer_results.insert(tk.END, f"SCORE BREAKDOWN\n", 'header')
            self.scorer_results.insert(tk.END, f"{'='*60}\n\n", 'header')
            
            self.scorer_results.insert(tk.END, f"Status: {result['status']}\n\n", 'bold')
            self.scorer_results.insert(tk.END, f"Reason:\n{result['reason']}\n\n", 'normal')
            
            self.scorer_results.insert(tk.END, f"Violations: {result['violations']}\n", 'bold')
            self.scorer_results.insert(tk.END, f"Critical: {result['critical_violations']}\n", 'bold')
            self.scorer_results.insert(tk.END, f"Confidence: {result['confidence']:.1f}%\n\n", 'bold')
            
            if 'recommendations' in result and result['recommendations']:
                self.scorer_results.insert(tk.END, "Recommendations:\n", 'header')
                self.scorer_results.insert(tk.END, f"{'-'*60}\n", 'header')
                for i, rec in enumerate(result['recommendations'], 1):
                    self.scorer_results.insert(tk.END, f"{i}. {rec}\n\n", 'rec')
            
            # Configure tags
            self.scorer_results.tag_config('header', foreground=self.colors['text_dim'], font=('Segoe UI', 10, 'bold'))
            self.scorer_results.tag_config('bold', font=('Segoe UI', 10, 'bold'))
            self.scorer_results.tag_config('normal', foreground=self.colors['text'])
            self.scorer_results.tag_config('rec', foreground=self.colors['text'])
            
            self.scorer_results.config(state='disabled')
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to score code: {str(e)}")
            
    def run_example_test(self):
        """Run test on selected example"""
        example_name = self.example_var.get()
        code = EXAMPLE_CODES[example_name]
        
        # Display code
        self.example_code_display.delete('1.0', tk.END)
        self.example_code_display.insert('1.0', code)
        
        try:
            # Get both compliance and score
            compliance = self.checker.check_code(code, detailed=True)
            score_result = score_code(code)
            
            # Format results
            self.example_results.config(state='normal')
            self.example_results.delete('1.0', tk.END)
            
            self.example_results.insert(tk.END, f"{'='*70}\n", 'header')
            self.example_results.insert(tk.END, f"TEST RESULTS: {example_name}\n", 'title')
            self.example_results.insert(tk.END, f"{'='*70}\n\n", 'header')
            
            # Score
            score = score_result['score']
            stars = '★' * score + '☆' * (5 - score)
            self.example_results.insert(tk.END, f"SCORE: {score}/5 {stars}\n\n", 'score')
            
            # Compliance
            status = compliance['status']
            self.example_results.insert(tk.END, f"Status: {status}\n", 'bold')
            self.example_results.insert(tk.END, f"Confidence: {compliance['confidence']:.1f}%\n", 'bold')
            self.example_results.insert(tk.END, f"Violations: {compliance['violations']}\n", 'bold')
            self.example_results.insert(tk.END, f"Critical: {compliance['critical_violations']}\n\n", 'bold')
            
            self.example_results.insert(tk.END, f"Reason: {score_result['reason']}\n\n", 'normal')
            
            if 'recommendations' in compliance and compliance['recommendations']:
                self.example_results.insert(tk.END, "Recommendations:\n", 'header')
                for i, rec in enumerate(compliance['recommendations'], 1):
                    self.example_results.insert(tk.END, f"  {i}. {rec}\n", 'rec')
            
            # Configure tags
            self.example_results.tag_config('header', foreground=self.colors['text_dim'])
            self.example_results.tag_config('title', foreground=self.colors['accent'], font=('Segoe UI', 12, 'bold'))
            self.example_results.tag_config('score', foreground=self.colors['warning'], font=('Segoe UI', 14, 'bold'))
            self.example_results.tag_config('bold', font=('Segoe UI', 10, 'bold'))
            self.example_results.tag_config('normal', foreground=self.colors['text'])
            self.example_results.tag_config('rec', foreground=self.colors['text'])
            
            self.example_results.config(state='disabled')
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to run test: {str(e)}")
            
    def run_all_tests(self):
        """Run all example tests and show comparison"""
        try:
            results = {}
            for name, code in EXAMPLE_CODES.items():
                compliance = self.checker.check_code(code, detailed=True)
                score_result = score_code(code)
                results[name] = {
                    'score': score_result['score'],
                    'status': compliance['status'],
                    'confidence': compliance['confidence'],
                    'violations': compliance['violations'],
                    'critical': compliance['critical_violations']
                }
            
            # Display comparison
            self.example_code_display.delete('1.0', tk.END)
            self.example_code_display.insert('1.0', "Running all tests... See results below.")
            
            self.example_results.config(state='normal')
            self.example_results.delete('1.0', tk.END)
            
            self.example_results.insert(tk.END, f"{'='*70}\n", 'header')
            self.example_results.insert(tk.END, "COMPARISON: ALL TEST EXAMPLES\n", 'title')
            self.example_results.insert(tk.END, f"{'='*70}\n\n", 'header')
            
            # Table header
            self.example_results.insert(tk.END, f"{'Example':<20} {'Score':<8} {'Status':<18} {'Violations':<12}\n", 'bold')
            self.example_results.insert(tk.END, f"{'-'*70}\n", 'header')
            
            # Table rows
            for name, res in results.items():
                score_str = f"{res['score']}/5"
                viol_str = f"{res['violations']} ({res['critical']} crit)"
                self.example_results.insert(tk.END, 
                    f"{name:<20} {score_str:<8} {res['status']:<18} {viol_str:<12}\n", 
                    'normal')
            
            self.example_results.insert(tk.END, f"\n{'='*70}\n\n", 'header')
            
            # Validation
            scores = [r['score'] for r in results.values()]
            if len(scores) == len(set(scores)):
                self.example_results.insert(tk.END, "✓ SUCCESS: All examples have different scores!\n", 'success')
            else:
                self.example_results.insert(tk.END, "⚠ WARNING: Some scores are the same\n", 'warning')
            
            # Configure tags
            self.example_results.tag_config('header', foreground=self.colors['text_dim'])
            self.example_results.tag_config('title', foreground=self.colors['accent'], font=('Segoe UI', 12, 'bold'))
            self.example_results.tag_config('bold', font=('Segoe UI', 10, 'bold'))
            self.example_results.tag_config('normal', foreground=self.colors['text'], font=('Consolas', 9))
            self.example_results.tag_config('success', foreground=self.colors['success'], font=('Segoe UI', 11, 'bold'))
            self.example_results.tag_config('warning', foreground=self.colors['warning'], font=('Segoe UI', 11, 'bold'))
            
            self.example_results.config(state='disabled')
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to run tests: {str(e)}")
            
    def load_example(self, target):
        """Load example code into specified input area"""
        # Simple dialog to select example
        example_window = tk.Toplevel(self.root)
        example_window.title("Select Example")
        example_window.geometry("400x200")
        example_window.configure(bg=self.colors['bg'])
        example_window.transient(self.root)
        example_window.grab_set()
        
        tk.Label(
            example_window,
            text="Choose an example:",
            font=('Segoe UI', 11, 'bold'),
            bg=self.colors['bg'],
            fg=self.colors['text']
        ).pack(pady=20)
        
        for name in EXAMPLE_CODES.keys():
            self.create_button(
                example_window,
                name,
                lambda n=name: self._insert_example(n, target, example_window),
                self.colors['surface_light']
            ).pack(pady=5)
            
    def _insert_example(self, name, target, window):
        """Insert selected example into target input"""
        code = EXAMPLE_CODES[name]
        
        if target == 'checker':
            self.checker_code_input.delete('1.0', tk.END)
            self.checker_code_input.insert('1.0', code)
        elif target == 'scorer':
            self.scorer_code_input.delete('1.0', tk.END)
            self.scorer_code_input.insert('1.0', code)
            
        window.destroy()
        
    def export_results(self, source):
        """Export results to file"""
        if not self.last_result:
            messagebox.showwarning("Warning", "No results to export!")
            return
            
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialfile=f"pci_compliance_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        )
        
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write("PCI DSS REQUIREMENT 6 - COMPLIANCE REPORT\n")
                    f.write("="*60 + "\n")
                    f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write("="*60 + "\n\n")
                    
                    for key, value in self.last_result.items():
                        f.write(f"{key}: {value}\n")
                        
                messagebox.showinfo("Success", f"Results exported to:\n{filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export: {str(e)}")


def main():
    """Main entry point"""
    root = tk.Tk()
    app = PCIComplianceGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
