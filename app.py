import os
import re
import json
from dotenv import load_dotenv
from fastapi import FastAPI, Form, File, UploadFile
from fastapi.responses import HTMLResponse
from google import genai
from google.genai import types
from pydantic import BaseModel, Field
from jinja2 import Template

load_dotenv()

app = FastAPI(title="CodeGuard AI", description="Automated Vulnerability Scanner & Remediation Engine")

# =======================================================
# 1. LAYER 1: LOCAL REGEX PRE-FILTER
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
                    "explanation": f"Hardcoded credential detected matching pattern for {name}.",
                    "refactored_code": "# Retrieve secrets dynamically from environment variables\nimport os\napi_key = os.getenv('SECRET_KEY_NAME')"
                })
    return findings

# =======================================================
# 2. LAYER 2: AI SEMANTIC AUDITOR (GEMINI)
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
# 3. INTERACTIVE WEB DASHBOARD UI
# =======================================================
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>CodeGuard AI | Security Dashboard</title>
  <style>
    :root {
      --bg: #0b1120;
      --card-bg: #1e293b;
      --accent: #38bdf8;
      --accent-hover: #0ea5e9;
      --text: #f8fafc;
      --muted: #94a3b8;
      --border: #334155;
      --critical: #ef4444;
      --high: #f97316;
      --btn-export: #10b981;
    }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: var(--bg); color: var(--text); margin: 0; padding: 2.5rem 1rem; }
    .container { max-width: 960px; margin: 0 auto; }
    .header { margin-bottom: 2rem; border-bottom: 1px solid var(--border); padding-bottom: 1rem; }
    h1 { font-size: 2.2rem; margin: 0 0 0.5rem 0; color: var(--text); }
    p.sub { color: var(--muted); margin: 0; font-size: 1rem; }
    .input-panel { background: var(--card-bg); border: 1px solid var(--border); border-radius: 10px; padding: 1.5rem; margin-bottom: 2rem; }
    .field-group { margin-bottom: 1.25rem; }
    label { display: block; font-weight: 600; margin-bottom: 0.5rem; color: #cbd5e1; }
    textarea { width: 100%; height: 180px; background: #070c18; color: #e2e8f0; border: 1px solid var(--border); border-radius: 6px; padding: 1rem; font-family: 'Consolas', monospace; font-size: 0.92rem; box-sizing: border-box; }
    input[type="file"] { background: #070c18; border: 1px dashed var(--border); padding: 0.8rem; border-radius: 6px; width: 100%; color: var(--muted); box-sizing: border-box; }
    .btn-submit { background: var(--accent); color: #04101e; border: none; padding: 0.85rem 2rem; border-radius: 6px; font-weight: 700; cursor: pointer; font-size: 1rem; transition: background 0.2s; }
    .btn-submit:hover { background: var(--accent-hover); }
    .export-bar { display: flex; gap: 0.75rem; margin-top: 1rem; margin-bottom: 1.5rem; }
    .btn-export { background: transparent; color: var(--btn-export); border: 1px solid var(--btn-export); padding: 0.5rem 1rem; border-radius: 6px; cursor: pointer; font-weight: 600; font-size: 0.85rem; }
    .btn-export:hover { background: rgba(16, 185, 129, 0.1); }
    .card { background: var(--card-bg); border: 1px solid var(--border); border-radius: 8px; padding: 1.5rem; margin-bottom: 1.25rem; }
    .badge { display: inline-block; padding: 0.25rem 0.6rem; border-radius: 4px; font-size: 0.75rem; font-weight: 800; text-transform: uppercase; }
    .badge-Critical { background: rgba(239, 68, 68, 0.2); color: var(--critical); border: 1px solid var(--critical); }
    .badge-High { background: rgba(249, 115, 22, 0.2); color: var(--high); border: 1px solid var(--high); }
    pre { background: #070c18; padding: 1rem; border-radius: 6px; overflow-x: auto; color: #a5f3fc; border: 1px solid var(--border); font-family: 'Consolas', monospace; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>CodeGuard AI</h1>
      <p class="sub">Automated Static Code Analysis, Vulnerability Auditing & Remediation Pipeline</p>
    </div>
    
    <div class="input-panel">
      <form method="post" action="/scan" enctype="multipart/form-data">
        <div class="field-group">
          <label for="code">Option A: Paste Source Code</label>
          <textarea id="code" name="code" placeholder="Paste source code (Python, C++, Java, JS, SQL) here...">{{ code_content }}</textarea>
        </div>

        <div class="field-group">
          <label for="file_upload">Option B: Or Upload Source File (.py, .cpp, .c, .js, .sql, .txt)</label>
          <input type="file" id="file_upload" name="file_upload" accept=".py,.cpp,.c,.js,.ts,.java,.cs,.sql,.txt">
        </div>

        <button type="submit" class="btn-submit">Run Security Audit</button>
      </form>
    </div>

    {% if total_issues is not none %}
    <div class="results">
      <div style="display: flex; justify-content: space-between; align-items: center;">
        <h2 style="margin: 0;">Audit Findings ({{ total_issues }} Issue{% if total_issues != 1 %}s{% endif %} Flagged)</h2>
        {% if total_issues > 0 %}
        <div class="export-bar">
          <button class="btn-export" onclick="exportMarkdown()">Download Report (.md)</button>
          <button class="btn-export" onclick="exportJSON()">Download Report (.json)</button>
        </div>
        {% endif %}
      </div>

      {% if total_issues == 0 %}
        <div class="card" style="border-color: #22c55e; margin-top: 1rem;">
          <p style="color: #4ade80; margin: 0; font-weight: bold;">✔ Clean Scan: No OWASP vulnerabilities or hardcoded secrets detected.</p>
        </div>
      {% endif %}

      {% for vuln in vulnerabilities %}
        <div class="card" style="margin-top: 1rem;">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
            <h3 style="margin: 0;">{{ vuln.vulnerability_type }} ({{ vuln.cwe_id }})</h3>
            <span class="badge badge-{{ vuln.severity }}">{{ vuln.severity }}</span>
          </div>
          <p style="color: var(--muted); margin: 0.25rem 0;">
            <strong>OWASP Category:</strong> {{ vuln.owasp_category }} | <strong>Line:</strong> {{ vuln.flagged_line_number }}
          </p>
          <p>{{ vuln.explanation }}</p>
          <label><strong>Recommended Remediation:</strong></label>
          <pre><code>{{ vuln.refactored_code }}</code></pre>
        </div>
      {% endfor %}
    </div>
    {% endif %}
  </div>

  <script>
    const reportData = {{ report_json | safe if report_json else "null" }};

    function exportJSON() {
      if (!reportData) return;
      const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "codeguard_audit_report.json";
      a.click();
      URL.revokeObjectURL(url);
    }

    function exportMarkdown() {
      if (!reportData) return;
      let md = `# CodeGuard AI - Security Audit Report\\n\\n`;
      md += `**Target:** ${reportData.target}\\n`;
      md += `**Total Issues Detected:** ${reportData.total_issues}\\n\\n`;
      md += `## Findings\\n\\n`;
      reportData.vulnerabilities.forEach((v, i) => {
        md += `### ${i + 1}. ${v.vulnerability_type} (${v.cwe_id})\\n`;
        md += `- **Severity:** ${v.severity}\\n`;
        md += `- **OWASP:** ${v.owasp_category}\\n`;
        md += `- **Flagged Line:** ${v.flagged_line_number}\\n\\n`;
        md += `**Explanation:**\\n${v.explanation}\\n\\n`;
        md += `**Remediation:**\\n\`\`\`\\n${v.refactored_code}\\n\`\`\`\\n\\n---\\n\\n`;
      });

      const blob = new Blob([md], { type: "text/markdown" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "codeguard_audit_report.md";
      a.click();
      URL.revokeObjectURL(url);
    }
  </script>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    t = Template(HTML_TEMPLATE)
    return t.render(code_content="", total_issues=None, vulnerabilities=[], report_json=None)

@app.post("/scan", response_class=HTMLResponse)
async def run_scan(code: str = Form(""), file_upload: UploadFile = File(None)):
    target_name = "Pasted Snippet"
    
    # Priority: If a file is uploaded, read its contents
    if file_upload and file_upload.filename:
        file_bytes = await file_upload.read()
        code = file_bytes.decode("utf-8", errors="ignore")
        target_name = file_upload.filename

    # Step 1: Local regex secret detection
    local_findings = scan_local_secrets(code) if code.strip() else []

    # Step 2: Semantic AI analysis
    ai_findings = scan_with_gemini(code) if code.strip() else []

    all_findings = local_findings + ai_findings

    report_payload = {
        "target": target_name,
        "total_issues": len(all_findings),
        "vulnerabilities": all_findings
    }

    t = Template(HTML_TEMPLATE)
    return t.render(
        code_content=code,
        total_issues=len(all_findings),
        vulnerabilities=all_findings,
        report_json=json.dumps(report_payload)
    )