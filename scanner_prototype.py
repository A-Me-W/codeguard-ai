import os
import json
from dotenv import load_dotenv
from google import genai
from google.genai import types
from pydantic import BaseModel, Field

# Load GEMINI_API_KEY from .env
load_dotenv()

# Define strict JSON schema for the audit report
class VulnerabilityItem(BaseModel):
    vulnerability_type: str = Field(description="Name of flaw, e.g. SQL Injection")
    cwe_id: str = Field(description="CWE identifier, e.g. CWE-89")
    owasp_category: str = Field(description="OWASP category, e.g. A03:2021-Injection")
    severity: str = Field(description="Critical, High, Medium, or Low")
    flagged_line_number: int = Field(description="Approximate line number where the issue occurs")
    explanation: str = Field(description="Why this code is insecure")
    refactored_code: str = Field(description="Secure, corrected version of the code snippet")

class AuditReport(BaseModel):
    language: str
    total_issues: int
    vulnerabilities: list[VulnerabilityItem]

def scan_file(file_path: str):
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        raise ValueError("Missing GEMINI_API_KEY in .env file! Please add it before running.")

    client = genai.Client(api_key=api_key)

    with open(file_path, "r", encoding="utf-8") as f:
        code_content = f.read()

    system_instruction = (
        "You are a Senior Application Security Engineer and Static Code Auditor. "
        "Analyze the provided source code delimited by triple backticks for security flaws, "
        "OWASP vulnerabilities, and unsafe practices. "
        "Adhere strictly to the requested JSON schema. If the code is secure, return total_issues = 0."
    )

    prompt = f"Audit this source code for vulnerabilities:\n```\n{code_content}\n```"

    response = client.models.generate_content(
        model="gemini-3.5-flash-lite",
        contents=prompt,
        config=types.GenerateContentConfig(
            system_instruction=system_instruction,
            temperature=0.1,
            response_mime_type="application/json",
            response_schema=AuditReport,
        ),
    )

    return json.loads(response.text)

if __name__ == "__main__":
    target = "test_samples/vulnerable_sql.py"
    target = "test_samples/buffer_risk.cpp"
    result = scan_file(target)
    print(json.dumps(result, indent=2))