# Setup Guide

## Purpose

This guide explains how to set up, run, test, and validate the IOC Detection Engine in a local Linux environment.

The engine currently supports:

- Ubuntu SSH authentication logs
- Cowrie honeypot JSONL events
- local lifecycle-aware IOC intelligence
- five-minute event correlation
- cross-source incidents
- explainable risk scoring
- CSV and JSON outputs
- persistent incident deduplication

---

## Prerequisites

Required:

- Python 3.10 or later
- Git
- Linux environment recommended
- basic terminal access

No external Python packages are required.

Check Python:

```bash
python3 --version
```

Check Git:

```bash
git --version
```

Expected Python version:

```text
Python 3.10.x or later
```

---

## Clone the Repository

```bash
git clone <repository-url>
cd ioc-detection-engine
```

Confirm the current location:

```bash
pwd
```

Example:

```text
/home/ubuntu/ioc-detection-engine
```

---

## Project Structure

```text
ioc-detection-engine/
├── alerts/
├── data/
│   └── iocs.json
├── docs/
│   ├── architecture.md
│   ├── lessons-learned.md
│   ├── setup-guide.md
│   └── testing.md
├── logs/
│   ├── sample-auth.log
│   ├── sample-cowrie.jsonl
│   └── v2-test-auth.log
├── notes/
├── src/
│   ├── main.py
│   └── normalization.py
├── tests/
│   ├── test_main.py
│   └── test_normalization.py
├── .gitignore
├── PROJECT_MASTER.md
└── README.md
```

Some local backup files, generated alert files, and private logs may also exist but are not required to run the sample workflow.

---

## Input Files

### Ubuntu Authentication Log

Default sample source:

```text
logs/sample-auth.log
```

The file contains controlled SSH authentication activity such as:

- failed password attempts
- invalid-user attempts
- successful logins
- malformed timestamps for error-handling tests
- one Ubuntu event aligned with Cowrie for cross-source correlation

### Cowrie Honeypot Events

Default sample source:

```text
logs/sample-cowrie.jsonl
```

The file contains supported Cowrie events such as:

- `cowrie.login.failed`
- `cowrie.login.success`
- `cowrie.command.input`
- `cowrie.session.closed`

### IOC Feed

Default source:

```text
data/iocs.json
```

The IOC file stores lifecycle-aware indicators with fields such as:

- value
- type
- source
- confidence
- source reliability
- tags
- first seen
- last seen
- expiry
- active status

Validate the file before running:

```bash
python3 -m json.tool data/iocs.json
```

---

## Run the Engine

From the project root:

```bash
python3 -m src.main
```

Expected startup summary:

```text
========== IOC Detection Engine v2 ==========

Ubuntu log source: logs/sample-auth.log
Cowrie log source: logs/sample-cowrie.jsonl
Normalized events: 24
IOC source: data/iocs.json
Observed IPs: 7
```

Expected completion summary:

```text
Detection completed
Alerts generated: 11
CSV output: alerts/alerts.csv
JSON output: alerts/incidents.json
Duplicates suppressed: 0
```

Alert totals may change if sample data or detection logic is modified.

---

## Generated Outputs

### Terminal Alerts

The terminal output includes:

- source IP
- IOC match status
- IOC source and confidence
- failed and successful login counts
- severity
- classification
- MITRE ATT&CK mapping
- supporting evidence

### CSV Alerts

Output:

```text
alerts/alerts.csv
```

View it with:

```bash
cat alerts/alerts.csv
```

For wider output:

```bash
column -s, -t < alerts/alerts.csv | less -S
```

Press `q` to exit.

### JSON Incidents

Output:

```text
alerts/incidents.json
```

Pretty-print it:

```bash
python3 -m json.tool alerts/incidents.json
```

Inspect the live cross-source incident:

```bash
python3 -m json.tool alerts/incidents.json | grep -A30 '"cross_source": true'
```

Expected fields include:

```json
{
  "sources": [
    "cowrie",
    "ubuntu_auth"
  ],
  "cross_source": true,
  "risk": {
    "score": 100,
    "level": "CRITICAL"
  }
}
```

### Deduplication State

Output:

```text
alerts/dedup-state.json
```

This file stores incident fingerprints used to suppress repeated alerts across runs.

---

## Reset Deduplication for Testing

To force the engine to regenerate all sample incidents:

```bash
rm -f alerts/dedup-state.json
python3 -m src.main
```

Use this only for controlled testing.

In normal operation, keep the deduplication state so repeated incidents can be suppressed correctly.

---

## Run the Test Suite

Run all tests:

```bash
python3 -m unittest discover -s tests -v
```

Current expected result:

```text
Ran 57 tests
OK
```

The suite covers:

- Ubuntu timestamp parsing
- Ubuntu SSH normalisation
- Cowrie JSONL parsing
- Cowrie event normalisation
- malformed-data handling
- grouping by source IP
- five-minute correlation
- out-of-order event handling
- cross-source correlation
- authentication event counting
- behavioural classification
- IOC lifecycle validation
- IOC enrichment
- incident JSON generation
- explainable risk scoring
- deduplication
- CSV output

---

## Compile Checks

Before running the full suite, individual files can be checked for syntax errors:

```bash
python3 -m py_compile src/main.py
python3 -m py_compile src/normalization.py
python3 -m py_compile tests/test_main.py
python3 -m py_compile tests/test_normalization.py
```

No output means the compile check passed.

---

## Using a Real Ubuntu Authentication Log

System source:

```text
/var/log/auth.log
```

Copy it into the project:

```bash
sudo cp /var/log/auth.log logs/real-auth.log
sudo chown "$USER":"$USER" logs/real-auth.log
```

Do not commit real authentication logs to a public repository.

They may contain:

- usernames
- internal and external IP addresses
- timestamps
- authentication records
- host details
- operational activity

The current engine is configured for the sample sources. If you switch to a real source, update the relevant log-path constant in `src/main.py`, run tests afterward, and avoid committing the local path change unless it is intentional.

---

## Common Issues

### `IndentationError`

Example:

```text
IndentationError: unexpected indent
```

Inspect the relevant lines:

```bash
nl -ba src/main.py | sed -n 'START,ENDp'
```

Open at the failing line:

```bash
nano +LINE_NUMBER src/main.py
```

Align the block with the surrounding function scope, then run:

```bash
python3 -m py_compile src/main.py
```

### `RecursionError`

A function may be calling itself unintentionally.

Inspect the referenced line and confirm helper functions are called from the correct parent function rather than from inside themselves.

### Test module import failure

Run:

```bash
python3 -m py_compile src/main.py
python3 -m py_compile tests/test_main.py
```

Fix the first syntax or indentation error before rerunning the full suite.

### Log file not found

Check available files:

```bash
ls -l logs/
```

Confirm the configured path in `src/main.py` matches the actual filename.

### Invalid IOC JSON

Validate:

```bash
python3 -m json.tool data/iocs.json
```

### Malformed IOC schema

The top-level IOC structure must match the schema expected by the engine.

If the engine reports:

```text
Error: Invalid IOC file: 'indicators' must be a list
```

confirm that the file contains an `indicators` list and that each indicator includes the required fields.

### Permission denied reading `auth.log`

Use a copied lab version:

```bash
sudo cp /var/log/auth.log logs/real-auth.log
sudo chown "$USER":"$USER" logs/real-auth.log
```

Do not run the entire engine as root unless there is a justified lab requirement.

### Duplicate alerts are not appearing

The deduplication state may be suppressing them.

For a controlled rerun:

```bash
rm -f alerts/dedup-state.json
python3 -m src.main
```

### Generated files appear in `git status`

Check:

```bash
git status
```

Restore tracked generated outputs when you do not intend to commit them:

```bash
git restore alerts/alerts.csv alerts/incidents.json alerts/dedup-state.json
```

Only restore files that are already tracked and that you intentionally want to discard.

---

## Git Workflow

Check changes:

```bash
git status
```

Stage only intended files:

```bash
git add <file1> <file2>
```

Commit:

```bash
git commit -m "Describe the change"
```

Push:

```bash
git push
```

Avoid using `git add .` when generated outputs or private logs may be present.

Review the commit:

```bash
git log --oneline -5
```

---

## Security and Privacy

Use this project only in an authorised lab or defensive environment.

Do not:

- expose the SSH lab directly to the public internet
- commit real authentication logs
- commit passwords, tokens, API keys, or secrets
- treat an IOC match as confirmed compromise
- enable automatic blocking without safeguards
- test against systems without authorisation

Review alerts manually before taking response action.

Any future automated response should include:

- allowlisting
- confidence thresholds
- approval controls
- rollback capability
- audit logging

---

## Current Limitations

- batch processing rather than continuous ingestion
- local JSON IOC feed
- correlation based primarily on source IP and time
- rule-based risk weights
- no direct MISP or OpenCTI integration
- no STIX 2.1 or TAXII support
- no external enrichment APIs
- no dashboard
- no automated containment
- only Ubuntu SSH and selected Cowrie event types are supported

---

## Validation Checklist

Before considering the local setup complete, confirm:

```text
[ ] Python 3.10 or later is installed
[ ] Repository is cloned
[ ] Sample Ubuntu log exists
[ ] Sample Cowrie JSONL exists
[ ] IOC JSON validates
[ ] Source files compile
[ ] 57 tests pass
[ ] Engine runs successfully
[ ] CSV output is generated
[ ] JSON output is generated
[ ] Cross-source incident is present
[ ] Explainable risk score is present
[ ] Git working tree contains only intended changes
```
