# CodeGuard AI: Automated Static Code Vulnerability Scanner & Remediation Engine

**Course:** CS4500 Senior Capstone  
**Developer:** Ameen Walker  
**Environment:** Antigravity IDE / Python 3.10+ / Windows 11  

---

## 1. Executive Summary & Problem Statement
In modern software engineering, the cost to remediate a software defect or security vulnerability during late-stage deployment or post-release can be up to **100 times greater** than addressing it during initial development. Furthermore, relying on commercial software with unvetted codebases exposes organizations to zero-day exploits, SQL injection attacks, and credential leakages.

**CodeGuard AI** is a static application security testing (SAST) tool that provides automated vulnerability identification, OWASP Top 10 categorization, CWE mapping, and refactored secure code snippets.

---

## 2. System Architecture & Two-Tier Inspection

CodeGuard AI utilizes a hybrid inspection pipeline:

│      Source Code Input       │
              │  (Pasted Code / File Upload) │
              └──────────────┬───────────────┘
                             │
             ┌───────────────┴───────────────┐
             ▼                               ▼
   [Layer 1: Local Regex]          [Layer 2: Gemini API]
  Instant Secret Detection        Semantic Vulnerability Audit
   - AWS Credentials (CWE-798)     - SQL Injection (CWE-89)
   - Bearer Tokens                 - Buffer Overflow (CWE-120)
   - Private Keys                  - OWASP Top 10 Classification
             │                               │
             └───────────────┬───────────────┘
                             ▼
              ┌──────────────────────────────┐
              │   Aggregated Audit Report    │
              │  - Severity & Line Numbers   │
              │  - Security Explanations     │
              │  - Refactored Source Code    │
              │  - Export to JSON & Markdown │
              └──────────────────────────────┘

1. **Layer 1: Local Pattern Matching (Pre-Filter)**
   * Line-by-line regex pattern evaluation catches leaked secrets, bearer tokens, and private keys locally without consuming tokens or exposing sensitive keys to external APIs.
2. **Layer 2: Semantic AI Code Auditor (`gemini-3.8-flash`)**
   * Employs the Google GenAI SDK with strict Pydantic JSON schemas to perform semantic code analysis across multiple languages (Python, C++, SQL, JavaScript), classifying flaws against Common Weakness Enumerations (CWE) and OWASP standards.

---

## 3. Tech Stack
* **Backend:** Python, FastAPI, Uvicorn (ASGI)
* **AI Model:** Google Gemini (`gemini-3.8-flash`) via `google-genai` SDK
* **Data Validation:** Pydantic v2 (Strict Schema Enforcement)
* **Frontend:** Jinja2 Template Engine, HTML5/CSS3 (Dark-Mode Dashboard)
* **Configuration:** `python-dotenv` for secure environment variable isolation

---

## 4. Installation & Local Setup

### Prerequisites
* Python 3.10 or higher
* Git for Windows

### Setup Instructions
```powershell
# 1. Clone repository
git clone [https://github.com/a-me-w/codeguard-ai.git](https://github.com/a-me-w/codeguard-ai.git)
cd codeguard-ai

# 2. Activate Python virtual environment
.\venv\Scripts\Activate

# 3. Install required dependencies
python -m pip install fastapi uvicorn jinja2 python-multipart google-genai pydantic python-dotenv

# 4. Configure Environment Variables
# Create a .env file in the root directory:
GEMINI_API_KEY="your-google-ai-studio-api-key"
GEMINI_MODEL="gemini-3.8-flash"

# 5. Launch the Web Dashboard
python -m uvicorn app:app --reload --port 8000