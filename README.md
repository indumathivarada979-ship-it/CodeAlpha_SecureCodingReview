# Task 3: Secure Coding Review

Secure code review of a Python Flask application: vulnerabilities identified, fixed and documented.

## Contents
- `vulnerable_app.py`: intentionally vulnerable app (audit target)
- `secure_app.py`: remediated version
- `mini_scan.py`: simple AST-based static analyzer
- `bandit_vulnerable.txt` / `bandit_secure.txt`: Bandit scan results
- `Secure_Coding_Review_Report.pdf`: full report

## Methodology
1. Manual code review (tracing user input to dangerous sinks)
2. Static analysis with Bandit
3. Fixes and re-scan

## Vulnerabilities Found
SQL Injection, Command Injection, Insecure Deserialization (pickle, YAML), Template Injection/XSS, Path Traversal, Hard-coded Secrets, Weak Password Hashing (MD5), Debug Mode Enabled

## Result
After remediation, Bandit reports 0 High and 0 Medium issues.

## Run
pip install flask pyyaml bandit
python -m bandit vulnerable_app.py
python -m bandit secure_app.py

Note: vulnerable_app.py is for learning only. Do not deploy it.