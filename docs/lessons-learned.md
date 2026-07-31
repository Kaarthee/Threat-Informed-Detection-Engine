# Lessons Learned

## Overview

The IOC Detection Engine began as a simple SSH log and IOC-matching project. It evolved into a multi-source detection pipeline that ingests Ubuntu authentication logs and Cowrie honeypot events, normalises telemetry, correlates activity, enriches incidents with IOC context, calculates explainable risk, and produces structured outputs.

The most important lesson was that useful detection is not created by a single rule or indicator. It depends on context, correlation, evidence quality, and the ability to explain why an incident matters.

---

## Technical Lessons

### 1. Detection quality depends on context

A failed SSH login by itself does not always indicate a serious attack.

Risk increases when additional evidence is present, such as:

- repeated failures
- multiple usernames targeted
- a later successful login
- an active malicious IOC match
- activity across multiple telemetry sources
- post-authentication command execution

This showed that effective detection requires correlation rather than isolated log matching.

---

### 2. IOC matching alone is not enough

A source IP appearing in an IOC feed is useful context, but it should not automatically be treated as confirmed compromise.

IOC data can be outdated, inactive, expired, inaccurate, reused by legitimate infrastructure, or missing behavioural context.

The engine therefore combines IOC intelligence with observed behaviour, time correlation, source context, and event evidence.

---

### 3. Normalisation is the foundation of multi-source detection

Ubuntu authentication logs and Cowrie JSONL events use different formats and fields.

Without normalisation, each source would require separate correlation and detection logic.

The shared `SecurityEvent` model allowed both sources to be processed consistently using:

- timestamp
- source IP
- event type
- username
- source
- destination port
- protocol
- raw evidence

This made the detection logic independent of the original telemetry format and created a foundation for adding more sources later.

---

### 4. Timestamp handling is harder than it first appears

Ubuntu timestamps were parsed as timezone-naive values, while Cowrie timestamps were timezone-aware UTC values.

Attempting to sort them directly caused failures.

The solution was to convert timezone-aware timestamps to naive UTC before correlation.

This highlighted several important lessons:

- timestamp formats must be standardised before sorting
- timezone assumptions must be explicit
- out-of-order events must be handled
- malformed timestamps should be isolated rather than crash the pipeline

Time handling is a core detection-engineering problem, not a minor parsing detail.

---

### 5. Correlation windows require clear semantics

The engine uses five-minute incident windows.

This helped separate related activity from unrelated events, but it also revealed important design decisions:

- events exactly five minutes apart may remain in one window
- events beyond the boundary start a new incident
- events from the same IP months apart must not be merged
- malformed or missing timestamps need separate handling

The correlation window improved alert quality, but the value is still a rule-based choice that may need configuration in production.

---

### 6. Cross-source correlation increases confidence

The same source IP was observed in both Ubuntu and Cowrie telemetry inside the same five-minute window.

This produced a real cross-source incident containing:

- Ubuntu failed-login evidence
- Cowrie failed-login evidence
- Cowrie successful-login evidence
- Cowrie command execution
- Cowrie session closure

Cross-source confirmation increased confidence because the activity was supported by independent telemetry sources.

---

### 7. Grouping events improves alert quality

Early versions of the engine treated events too independently.

Grouping activity by source IP and incident window allowed the engine to produce consolidated incidents containing:

- failed-login count
- successful-login count
- source context
- IOC enrichment
- severity
- classification
- risk score
- ATT&CK mapping
- supporting evidence

This reduced alert noise and improved analyst readability.

---

### 8. Successful login after failures is a high-value detection pattern

Repeated failures followed by a successful login may indicate that an attacker discovered or compromised valid credentials.

The engine classified this pattern as critical and mapped it to:

- T1110 Brute Force
- T1078 Valid Accounts

This pattern was more meaningful than treating every failed login with the same severity.

---

### 9. Explainable risk scoring is better than an unexplained label

Severity labels alone do not show why an incident was prioritised.

The engine added an explainable numeric score based on:

- failed authentication attempts
- successful login after failures
- active IOC match
- cross-source activity
- post-authentication command execution

Example:

```json
{
  "score": 100,
  "level": "CRITICAL",
  "factors": [
    "3 failed authentication attempts: +30",
    "Successful login after failures: +30",
    "Active IOC match: +25",
    "Activity observed across 2 sources: +15",
    "Post-authentication command activity: +10"
  ]
}
```

This makes the decision easier to defend in an investigation or interview.

---

### 10. Malformed data should be isolated, not allowed to crash the engine

Real telemetry is rarely clean.

The engine encountered:

- malformed Ubuntu timestamps
- missing timestamps
- malformed Cowrie JSON
- unsupported Cowrie event types
- missing source IP values
- invalid IOC schema
- expired and inactive IOC records

These are isolated or rejected safely while valid events continue through the pipeline.

---

### 11. Persistent deduplication is essential for reducing alert fatigue

Without state, the same incident can be generated every time the engine runs.

The engine now creates stable incident fingerprints and stores deduplication state.

This allows it to suppress repeated incidents inside a cooldown period and generate new alerts after the cooldown expires.

Detection quality includes noise reduction, not only detection coverage.

---

### 12. Evidence preservation matters

The engine displays only recent evidence entries in terminal output to maintain readability, while raw evidence remains available in structured outputs.

This creates a balance between concise analyst review and full investigation context.

---

### 13. Sample data and real data serve different purposes

Sample data was useful for deterministic testing, reproducing scenarios, validating boundaries, and proving cross-source correlation.

Real logs were useful for exposing unexpected formats, parser assumptions, and operational noise.

Both were necessary, but automated tests should rely on controlled and repeatable data.

---

### 14. Tests made safe refactoring possible

The project now has 57 automated tests.

Coverage includes:

- timestamp parsing
- Ubuntu normalisation
- Cowrie normalisation
- event grouping
- five-minute correlation
- cross-source correlation
- IOC lifecycle validation
- enrichment
- risk scoring
- deduplication
- CSV and JSON output

The test suite became both a development safety net and a portfolio proof point.

---

### 15. Documentation is part of engineering

Updating the README, architecture, and testing documents showed that technical work is easier to explain when decisions are recorded.

Useful documentation includes architecture, setup instructions, testing evidence, lessons learned, screenshots, Git history, limitations, and roadmap.

---

## Troubleshooting Lessons

### Indentation errors can block the entire test suite

A misplaced indentation inside `build_incident_record` caused an `IndentationError` and prevented the test module from importing.

The fix required inspecting exact line numbers and aligning the new block with the surrounding function scope.

### Function placement matters

The call to `calculate_risk_score()` was accidentally placed inside `calculate_risk_score()` itself.

This caused infinite recursion and a `RecursionError`.

The correct design was to define the scoring function separately and call it from `build_incident_record`.

### Shell commands and Python code are different execution contexts

Python assignments entered directly into the shell caused command errors.

This reinforced the difference between shell commands, Python statements, configuration values, and file content.

### Real authentication logs require careful permission handling

Instead of running the whole engine as root, the restricted authentication log was copied into the project and ownership was adjusted for lab analysis.

### Generated files should not be committed accidentally

Running the engine modifies generated alert and state files.

The workflow therefore included checking `git status`, staging only intended source files, restoring generated outputs, and reviewing `.gitignore`.

---

## Security Lessons

### Detection does not equal confirmation

An alert indicates suspicious activity, not guaranteed compromise. Analyst validation is still required.

### Severity should be evidence-based

Severity should consider event volume, successful authentication, IOC confidence, cross-source confirmation, targeted username, post-login activity, asset importance, and whether the source is trusted.

### Response should be proportional

Potential actions include monitoring, further investigation, searching other systems for the IOC, password reset, account disablement, session termination, IP blocking, and forensic review.

### Automatic response creates operational risk

Automated blocking can cause administrator lockout, false-positive impact, or disruption of legitimate traffic.

Future response capability should include allowlisting, confidence thresholds, approval options, rollback capability, and audit logging.

---

## CTI and SOC Lessons

### Threat intelligence should support a decision

IOC enrichment is most useful when it changes how an incident is prioritised or investigated.

Useful CTI should help answer:

- why does this matter?
- what should the analyst investigate?
- what evidence supports the assessment?
- what detection opportunity exists?
- what action is appropriate?

The current engine supports this partially through correlation, evidence preservation, ATT&CK mapping, and explainable risk scoring.

A future actionable-intelligence layer should add:

- `why_it_matters`
- investigation steps
- recommended actions
- detection opportunities
- organisational relevance

### Generic recommendations are not enough

Guidance should be based on actual incident evidence.

| Signal | Analyst implication |
|---|---|
| One failed login | Monitor for repetition |
| Repeated failures | Review targeted accounts and source history |
| IOC match | Search the environment for the indicator |
| Success after failures | Investigate possible credential compromise |
| Cross-source activity | Increase confidence and priority |
| Command execution | Review post-authentication behaviour |
| Privileged account | Increase organisational impact |
| Critical asset | Escalate investigation priority |

---

## Design Trade-Offs

### Batch processing versus real-time ingestion

Batch processing made the project easier to test and reproduce, but it does not provide immediate detection.

### Rule-based scoring versus adaptive scoring

Rule-based scoring is transparent, testable, and explainable, but the weights may not fit every environment.

### Source IP correlation versus broader entity correlation

Source IP is useful for SSH scenarios, but future correlation may also include username, session ID, destination host, asset identity, and command behaviour.

### Local IOC feed versus integrated intelligence platforms

The local JSON feed is deterministic and testable, but lacks automatic enrichment and sharing.

Future phases may include STIX 2.1, TAXII, MISP, OpenCTI, and external reputation sources.

---

## Future Improvements Identified

### Version 1.0 Completion

- final setup-guide update
- `.gitignore` review
- repository cleanup
- screenshots
- final regression test
- release tag

### Version 1.1 Actionable Intelligence

- incident priority
- `why_it_matters`
- investigation guidance
- recommended actions
- detection opportunities
- evidence-driven guidance tests

### Version 2.0 Organisational Context and Integrations

- high-value account context
- critical asset context
- trusted networks
- environment-specific risk
- STIX and TAXII support
- MISP integration
- OpenCTI integration
- external enrichment
- alert lifecycle
- dashboard visualisation
- controlled response playbooks

---

## Interview Summary

The project evolved from basic SSH and IOC matching into a multi-source detection pipeline that:

- normalises Ubuntu and Cowrie telemetry
- correlates activity into five-minute windows
- creates cross-source incidents
- validates IOC lifecycle state
- enriches incidents with threat context
- maps behaviour to MITRE ATT&CK
- suppresses duplicates
- calculates explainable risk
- preserves investigation evidence
- produces structured CSV and JSON outputs
- is validated by 57 automated tests

The next step beyond detection is actionable intelligence: helping an analyst understand why an incident matters, what to investigate, and what decision to make.
