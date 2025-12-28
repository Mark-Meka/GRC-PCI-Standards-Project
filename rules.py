NON_COMPLIANT_PATTERNS = {
    "hardcoded_secret": ["password =", "DB_PASSWORD =", "admin123"],
    "sql_injection": ["SELECT * FROM", "+ user", "$_GET"],
    "dangerous_exec": ["eval(", "Runtime.getRuntime()", "exec("],
    "weak_hash": ["md5(", "sha1("],
    "waf_disabled": ["modsecurity off", "SecRuleEngine Off"]
}