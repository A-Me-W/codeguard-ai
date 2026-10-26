import os
import re
import json
from dotenv import load_dotenv
from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse
from google import genai
from google.genai import types
from pydantic import BaseModel, Field

load_dotenv()

# =======================================================
# 1. FASTAPI INITIALIZATION (Resolves Uvicorn Error)
# =======================================================
app = FastAPI(title="CodeGuard AI", description="Automated Vulnerability Scanner & Remediation Engine")

# =======================================================
# 2. LOCAL REGEX PRE-FILTER (SECRETS DETECTION)
# =======================================================
SECRET_PATTERNS = {
    "AWS Access Key": r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
    "Generic Private Key": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
    "Generic Bearer Token": r"(?i)bearer\s+[a-z0-9_\-\.=:_\+\/]{20,}",
    "Hardcoded Password/Secret": r'(?i)(?:password|passwd|pwd|secret)\s*=\s*["\'][^"\']{4,}["\']'
}

def scan_local_secrets(code_content: str) -> list[dict]:
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
                    "explanation": f"Hardcoded credential matching pattern for {name}.",
                    "refactored_code": "# Use environment variables (os.getenv) or a secret vault instead of hardcoded strings."
                })
    return findings

# =======================================================
# 3. AI STATIC CODE AUDITOR (GEMINI API)
# =======================================================
class VulnerabilityItem(BaseModel):
    vulnerability_type: str = Field(description="Name of flaw, e.g. SQL Injection, Buffer Overflow")
    cwe_id: str = Field(description="CWE identifier, e.g. CWE-89, CWE-120")
    owasp_category: str = Field(description="OWASP category, e.g. A03:2021-Injection")
    severity: str = Field(description="Critical, High, Medium, or Low")
    flagged_line_number: int = Field(description="Line number of the issue")
    explanation: str = Field(description="Why this code is insecure")
    refactored_code: str = Field(description="Secure, corrected version of the code snippet")

class AuditReport(BaseModel):
    language: str
    total_issues: int
    vulnerabilities: list[VulnerabilityItem]

def scan_with_gemini(code_content: str) -> list[dict]:
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        raise ValueError("Missing GEMINI_API_KEY in .env file!")

    client = genai.Client(api_key=api_key)
    model_name = os.getenv("GEMINI_MODEL", "gemini-3.8-flash")

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
    return parsed.get("vulnerabilities", [])

# =======================================================
# 4. WEB INTERFACE ROUTES
# =======================================================
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>CodeGuard AI | Security Dashboard</title>
  <style>
    :root {
      --bg: #0f172a;
      --card-bg: #1e293b;
      --accent: #38bdf8;
      --text: #f8fafc;
      --muted: #94a3b8;
      --border: #334155;
      --critical: #ef4444;
      --high: #f97316;
    }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: var(--bg); color: var(--text); margin: 0; padding: 2rem; }
    .container { max-width: 960px; margin: 0 auto; }
    h1 { font-size: 2rem; margin-bottom: 0.25rem; }
    p.sub { color: var(--muted); margin-bottom: 1.5rem; }
    textarea { width: 100%; height: 200px; background: #090d16; color: #e2e8f0; border: 1px solid var(--border); border-radius: 8px; padding: 1rem; font-family: monospace; font-size: 0.95rem; box-sizing: border-box; }
    button { background: var(--accent); color: var(--bg); border: none; padding: 0.75rem 1.75rem; border-radius: 6px; font-weight: 700; cursor: pointer; margin-top: 1rem; font-size: 1rem; }
    button:hover { opacity: 0.9; }
    .results { margin-top: 2rem; }
    .card { background: var(--card-bg); border: 1px solid var(--border); border-radius: 8px; padding: 1.5rem; margin-bottom: 1rem; }
    .badge { display: inline-block; padding: 0.2rem 0.6rem; border-radius: 4px; font-size: 0.8rem; font-weight: bold; text-transform: uppercase; }
    .badge-Critical { background: rgba(239, 68, 68, 0.2); color: var(--critical); border: 1px solid var(--critical); }
    .badge-High { background: rgba(249, 115, 22, 0.2); color: var(--high); border: 1px solid var(--high); }
    pre { background: #090d16; padding: 1rem; border-radius: 6px; overflow-x: auto; color: #a5f3fc; border: 1px solid var(--border); }
  </style>
</head>
<body>
  <div class="container">
    <h1>CodeGuard AI</h1>
    <p class="sub">Automated static code vulnerability detection and remediation pipeline.</p>
    
    <form method="post" action="/scan">
      <label for="code"><strong>Input Source Code:</strong></label><br><br>
      <textarea id="code" name="code" placeholder="Paste source code (Python, C++, SQL, etc.) here...">{{ code_content }}</textarea><br>
      <button type="submit">Run Security Audit</button>
    </form>

    {% if total_issues is not none %}
    <div class="results">
      <h2>Audit Findings ({{ total_issues }} Issue{% if total_issues != 1 %}s{% endif %} Detected)</h2>
      {% if total_issues == 0 %}
        <div class="card" style="border-color: #22c55e;">
          <p style="color: #4ade80; margin: 0; font-weight: bold;">✔ No security flaws or hardcoded secrets detected in the submitted snippet.</p>
        </div>
      {% endif %}
      {% for vuln in vulnerabilities %}
        <div class="card">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
            <h3 style="margin: 0;">{{ vuln.vulnerability_type }} ({{ vuln.cwe_id }})</h3>
            <span class="badge badge-{{ vuln.severity }}">{{ vuln.severity }}</span>
          </div>
          <p style="color: var(--muted); margin: 0.25rem 0;"><strong>OWASP Category:</strong> {{ vuln.owasp_category }} | <strong>Flagged Line:</strong> {{ vuln.flagged_line_number }}</p>
          <p>{{ vuln.explanation }}</p>
          <strong>Remediated Implementation:</strong>
          <pre><code>{{ vuln.refactored_code }}</code></pre>
        </div>
      {% endfor %}
    </div>
    {% endif %}
  </div>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    # Render empty dashboard on initial load
    from jinja2 import Template
    t = Template(HTML_TEMPLATE)
    return t.render(code_content="", total_issues=None, vulnerabilities=[])

@app.post("/scan", response_class=HTMLResponse)
async def run_scan(code: str = Form(...)):
    # 1. Fast local regex detection
    local_findings = scan_local_secrets(code)
    
    # 2. Semantic Gemini analysis
    ai_findings = scan_with_gemini(code) if code.strip() else []
    
    all_findings = local_findings + ai_findings

    from jinja2 import Template
    t = Template(HTML_TEMPLATE)
    return t.render(
        code_content=code,
        total_issues=len(all_findings),
        vulnerabilities=all_findings
    )