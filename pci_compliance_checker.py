import pickle # for loading the model
import re # for regular expressions
import os # for file path handling
import warnings # suppress scikit-learn warnings
from typing import Dict, List # for type hints
import numpy as np # for vectorization
from sklearn.metrics.pairwise import cosine_similarity # for similarity calculation


warnings.filterwarnings('ignore', category=UserWarning, module='sklearn')

class PCIComplianceChecker:
    
    def __init__(self, model_path='pci_rag_model.pkl'):
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model not found: {model_path}")
        
        with open(model_path, 'rb') as f:
            data = pickle.load(f)
        
        self.vectorizer = data['vectorizer']
        self.classifier = data['classifier']
        self.violation_patterns = data['violation_patterns']
    
    def check_code(self, code: str, detailed=False) -> Dict: 
        code = str(code)
        
        # AI prediction
        vec = self.vectorizer.transform([code]) # vectorize the code
        pred = self.classifier.predict(vec)[0] # predict the class
        proba = self.classifier.predict_proba(vec)[0] # get the probability
        
        ai_status = 'COMPLIANT' if pred == 1 else 'NON_COMPLIANT'
        ai_conf = max(proba) * 100
        
        # Pattern violations
        violations = self._detect_violations(code)
        critical = sum(1 for v in violations if v['severity'] == 'CRITICAL')
        
        # Final decision
        if critical > 0:
            status, conf = 'NON_COMPLIANT', 95
        elif len(violations) >= 2:
            status, conf = 'NON_COMPLIANT', 85
        else:
            status, conf = ai_status, ai_conf
        
        result = {
            'status': status,
            'confidence': round(conf, 2),
            'violations': len(violations),
            'critical_violations': critical
        }
        
        if detailed:
            result['recommendations'] = self._get_recommendations(violations)
        
        return result
    
    def _detect_violations(self, code: str) -> List[Dict]:
        violations = []
        for vtype, config in self.violation_patterns.items():
            for pattern in config['patterns']:
                if re.search(pattern, code, re.IGNORECASE | re.MULTILINE):
                    violations.append({
                        'type': vtype,
                        'severity': config['severity'],
                        'pci_requirement': config['pci_requirement'],
                        'fix': config['fix']
                    })
                    break
        return violations
    
    def _get_recommendations(self, violations: List[Dict]) -> List[str]:
        if not violations:
            return ["Code appears compliant."]
        return [f"{v['pci_requirement']}: {v['fix']}" for v in violations]

# Global instance
_checker = None

def check_payment_code(code: str, detailed=False) -> Dict:
    global _checker
    if _checker is None:
        _checker = PCIComplianceChecker()
    return _checker.check_code(code, detailed)

def is_compliant(code: str) -> bool:
    return check_payment_code(code)['status'] == 'COMPLIANT'

def get_violations(code: str) -> List[Dict]:
    return check_payment_code(code, detailed=True).get('recommendations', [])