import os
import re
import json
from dotenv import load_dotenv
from google import genai
from google.genai import types
from pydantic import BaseModel, Field

load_dotenv()

# ==========================================
# 1. LOCAL REGEX SECRET SCANNER
# ==========================================
SECRET_PATTERNS = {
    "AWS Access Key": r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
    "Generic Private Key": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
    "Generic Bearer Token": r"(?i)bearer\s+[a-z0-9_\-\.=:_\+\/]{20,}",
    "Hardcoded Password/Secret": r'(?i)(?:password|passwd|pwd|secret)\s*=\s*["\'][^"\']{4,}["\']'
}

def scan_local_secrets(code_content: str):
    """Scans code for leaked credentials without external API calls."""
    findings = []
    lines = code_content.splitlines()
    for idx, line in enumerate(lines, 1):
        for name, pattern in SECRET_PATTERNS.items():
            if re.search(pattern, line):
                findings.append({
                    "vulnerability_type": f"Exposed Secret ({name})",
                    "cwe_id": "CWE-798",
                    "owasp_category": "A07:2021-Identification and Authentication Failures",
                    "severity": "Critical",
                    "flagged_line_number": idx,
                    "explanation": f"Hardcoded credential detected matching pattern for {name}.",
                    "refactored_code": "# Use environment variables or a secret vault instead of hardcoding credentials"
                })
    return findings

# ==========================================
# 2. AI STATIC CODE AUDITOR (GEMINI)
# ==========================================
class VulnerabilityItem(BaseModel):
    vulnerability_type: str = Field(description="Name of flaw, e.g. SQL Injection")
    cwe_id: str = Field(description="CWE identifier, e.g. CWE-89")
    owasp_category: str = Field(description="OWASP category, e.g. A03:2021-Injection")
    severity: str = Field(description="Critical, High, Medium, or Low")
    flagged_line_number: int = Field(description="Approximate line number")
    explanation: str = Field(description="Why this code is insecure")
    refactored_code: str = Field(description="Secure, corrected version of the code")

class AuditReport(BaseModel):
    language: str
    total_issues: int
    vulnerabilities: list[VulnerabilityItem]

def scan_with_gemini(code_content: str, model_name: str = "gemini-3.8-flash") -> list[dict]:
    """Sends code to Gemini for deep semantic vulnerability analysis."""
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        raise ValueError("Missing GEMINI_API_KEY in .env file!")

    client = genai.Client(api_key=api_key)

    system_instruction = (
        "You are a Senior Application Security Engineer and Static Code Auditor. "
        "Analyze the provided source code for vulnerabilities and OWASP flaws. "
        "Adhere strictly to the requested JSON schema. If the code is secure, return total_issues = 0."
    )

    prompt = f"Audit this source code for vulnerabilities:\n```\n{code_content}\n```"

    response = client.models.generate_content(
        model=model_name,
        contents=prompt,
        config=types.GenerateContentConfig(
            system_instruction=system_instruction,
            temperature=0.1,
            response_mime_type="application/json",
            response_schema=AuditReport,
        ),
    )

    parsed = json.loads(response.text)
    return [v.model_dump() if hasattr(v, "model_dump") else v for v in parsed.get("vulnerabilities", [])]

# ==========================================
# 3. UNIFIED SCANNING PIPELINE
# ==========================================
def full_code_audit(file_path: str):
    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()

    # Step A: Local secret pre-filter
    local_findings = scan_local_secrets(content)

    # Step B: AI semantic analysis
    ai_findings = scan_with_gemini(content)

    all_vulnerabilities = local_findings + ai_findings

    return {
        "file_name": os.path.basename(file_path),
        "total_issues": len(all_vulnerabilities),
        "vulnerabilities": all_vulnerabilities
    }

if __name__ == "__main__":
    test_target = "test_samples/vulnerable_sql.py"
    print(f"Running full audit on: {test_target}...")
    report = full_code_audit(test_target)
    print(json.dumps(report, indent=2))