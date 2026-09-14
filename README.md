“”” Personal Security Reporter
## Personal Security Reporter (PSR) is a macOS security monitoring project that detects #changes on a host, turns them into readable security findings, and uses AI to help investigate #suspicious activity without giving the model control over the system.

I built PSR to explore a personal security question:

# How can an AI assist with security analysis without being trusted to make security decisions?
PSR combines local host monitoring, baseline comparison, an audit trail, AI assisted triage, and prompt injection testing in one project.

## What PSR Does
PSR collects security-relevant information from a Mac and compares it against previously observed behavior.

## It can:
- Detect new network-accessible listening ports.
- Detect ports that disappeared or services that moved.
- Track which processes own listening ports.
- Monitor disk usage and basic host information.
- Compare each run against a saved baseline.
- Generate structured JSON and human-readable reports.
- Store run history and AI review data in SQLite.
- Display findings in a local web dashboard.
- Use an LLM to explain higher-priority findings and suggest investigation steps.
- Record whether a human reviewer considered an AI response accurate.
- Test the AI triage layer against prompt-injection attempts.

# The result is closer to a small host-monitoring and security-review pipeline than a one-off system information script.
--------------------------------------------------------------------------------
How It Works
macOS host
    │
    ▼
Collect system state
    │
    ▼
Compare against baseline
    │
    ▼
Create security findings
    │
    ├──► Text / JSON reports
    │
    ├──► SQLite audit history
    │
    └──► AI triage for eligible findings
                  │
                  ▼
          Local review dashboard


# A typical run might notice that a new process has started listening on a network-accessible port.
Instead of simply printing the port number, PSR creates a structured finding containing the evidence, severity, process ownership, and a stable finding ID.
If the finding is eligible for AI triage, the model can provide:
- An explanation of what the finding may mean.
- Whether it appears likely to be benign.
- Suggested investigation steps.
- A confidence level.

The AI response is advisory only. It does not change the finding, update the baseline, acknowledge alerts, or perform remediation.
--------------------------------------------------------------------------------

# Local Security Dashboard

PSR includes a FastAPI/Jinja2 dashboard for reviewing previous security runs.
python serve.py
Then open:
http://127.0.0.1:8765

# The dashboard provides:
- The latest security status.
- Critical, warning, and informational findings.
- Run history.
- Host and finding evidence.
- AI triage results.
- Human accuracy verdicts.
- Finding acknowledgement.
- The interface is intentionally local only. It binds to 127.0.0.1 rather than exposing host security information over the network.
- The browser also cannot launch scans or execute collectors. Collection remains a CLI operation while the dashboard is used for review.

--------------------------------------------------------------------------------

# AI With Limited Authority

One of the main design goals of PSR is keeping the AI layer separated from security state.

The model receives evidence and returns a structured annotation, but the annotation does not become the finding itself.

AI triage is restricted to eligible unresolved warning or critical findings and returns a defined schema containing:
{
  "explanation": "Why this finding may matter",
  "likely_benign": false,
  "investigation_steps": [
    "Confirm the process that owns the listener."
  ],
  "confidence": "medium"
}
Annotations are stored with a hash of the exact prompt and model configuration used to generate them.

If the prompt or configured model changes, PSR treats the result as a different annotation rather than silently replacing the old one.
Human reviewers can mark an annotation as:
Accurate
Wrong
Unsure
Those verdicts are appended to the audit history instead of overwriting the original model response.

Prompt-Injection Testing
Host data is untrusted data.
A process name, command, or other collected value could theoretically contain text designed to manipulate an LLM. PSR therefore includes a separate prompt-injection evaluation harness for the AI triage layer.
The harness tests whether attacker-controlled host data can cause behavior such as:
Changing a benign/malicious assessment.
Claiming that system state was changed.
Leaking protected instructions.
Recommending destructive investigation actions.
Breaking or refusing the required output format.
python injection_testbed.py
By default, the harness uses a deterministic offline fixture so evaluation logic can be tested without making external API calls.
A live evaluation requires explicit opt-in and a call limit:
python injection_testbed.py --live --repeat 5 --max-calls 40
Evaluation results are written as JSON and Markdown reports under output/.
The test harness is deliberately separate from normal host collection and does not write its results into the production triage ledger.

Security Design
Because PSR handles host information, several controls are built into the web interface and data flow.
Local-only access
The dashboard binds to 127.0.0.1 and validates allowed hosts.
No browser-triggered collection
HTTP routes cannot launch scans, execute collectors, send reports, or directly update the baseline.
CSRF protection
State-changing forms use per-session CSRF tokens and same-origin validation.
XSS protection
Host-derived content is treated as untrusted and rendered through Jinja2 autoescaping. The dashboard also sends a restrictive Content Security Policy.
Path validation
Historical report files are only opened when they resolve inside PSR's configured output directory and match the expected report format.
Secret separation
The dashboard does not load SMTP credentials or OpenAI API credentials.
Append-only AI review history
Model annotations are preserved, while human verdicts are recorded separately as an audit trail.

Tech Stack
Area
Technology
Language
Python
Platform
macOS
Web
FastAPI
Templates
Jinja2
Database
SQLite
AI
OpenAI API
Testing
pytest
Host inspection
macOS system utilities / lsof / ps
Reports
JSON and plain text

The dashboard uses server-rendered HTML and CSS. There is no frontend JavaScript framework or separate frontend build process.

Running the Project
1. Install dependencies
python -m pip install -r requirements.txt
2. Run PSR
python main.py
The first run establishes the information PSR needs to begin tracking host activity. Baseline changes are intentionally controlled rather than silently accepted.
3. Start the dashboard
python serve.py
Open:
http://127.0.0.1:8765
Optional configuration
Email reporting uses:
REPORT_EMAIL
REPORT_APP_PASSWORD
REPORT_RECIPIENT
REPORT_RECIPIENT can be omitted when reports should be sent to the sender account.
AI triage uses:
OPENAI_API_KEY
Additional triage settings can control the model, timeout, and maximum number of findings sent for analysis during a run.

Testing
Run the automated test suite with:
pytest -q
The tests cover both normal behavior and security boundaries, including:
Baseline creation and update controls.
Network-listener comparison.
Finding generation and acknowledgement.
AI response validation.
AI caching and prompt hashing.
Immutable annotations and verdict history.
API failure handling.
Cross-site scripting protection.
CSRF protection.
Untrusted Host headers.
Unsafe report paths.
Deleted or unavailable historical reports.
Prompt-injection scoring and evaluation behavior.

Project Structure
.
main.py  —-------------------- >  # Main collection/reporting CLI
collectors.py —-------------------- >  # Host data collection
Listener_parsers.py —-------------------- >   # Network listener parsing
process_parsers.py —-------------------- >   # Process parsing
analysis.py —-------------------- >  # Baseline comparison and finding analysis
findings.py  —-------------------- >  # Structured security findings
baseline.py —-------------------- >   # Baseline storage and acknowledgement
ledger.py   —-------------------- >  # SQLite audit history
triage.py   —-------------------- >   # AI-assisted finding analysis
report.py —-------------------- >    # Text and JSON reports
injection_eval/ —-------------------- >  # Prompt-injection evaluation
web/
app.py   —-------------------- > # FastAPI dashboard
data.py   —-------------------- >    # Dashboard data access
static/
templates/
tests/
data/
output/


## Why I Built It
PSR started as a host-monitoring project and grew into an experiment in building security tooling around AI without assuming the AI is trustworthy.
The project focuses on problems I wanted to understand more deeply:
Host and network monitoring.
Baseline-based detection.
Defensive security engineering.
Auditability and evidence preservation.
Secure local web application design.
Human-in-the-loop AI.
Prompt-injection resistance and evaluation.
Failure-safe behavior when data, APIs, or reports are unavailable.
The goal is to give a human reviewer better context while keeping the evidence, security state, and final decisions under deterministic program control.
Current Scope
PSR currently targets macOS and is designed as a local, single-user security project.
It is not intended to replace an EDR, antivirus product, or enterprise monitoring platform. The project is primarily an exploration of host monitoring, secure software design, and bounded AI-assisted security analysis.
“””

