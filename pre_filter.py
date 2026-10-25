import re

PATTERNS = {
    "AWS Access Key": r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
    "Generic Private Key": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
    "Generic Bearer Token": r"(?i)bearer\s+[a-z0-9_\-\.=:_\+\/]{20,}",
    "Hardcoded Password/Secret": r'(?i)(?:password|passwd|pwd|secret)\s*=\s*["\'][^"\']{4,}["\']'
}

def scan_secrets(file_path: str):
    findings = []
    with open(file_path, "r", encoding="utf-8") as f:
        for idx, line in enumerate(f, 1):
            for name, pattern in PATTERNS.items():
                if re.search(pattern, line):
                    findings.append({
                        "vulnerability_type": name,
                        "line": idx,
                        "flagged_code": line.strip()
                    })
    return findings

if __name__ == "__main__":
    target = "test_samples/leaked_secret.py"
    print(f"Scanning {target} for hardcoded secrets...")
    results = scan_secrets(target)
    for issue in results:
        print(f"-> [Line {issue['line']}] {issue['vulnerability_type']}: {issue['flagged_code']}")