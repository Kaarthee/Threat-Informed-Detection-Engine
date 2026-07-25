# System Architecture

## Overview

The IOC Detection Engine is a Python-based, multi-source security detection pipeline that ingests Ubuntu SSH authentication logs and Cowrie honeypot JSONL events, normalises them into a shared event model, correlates related behaviour, enriches incidents with IOC intelligence, calculates explainable risk, and generates analyst-ready alerts.

The architecture is designed around separation of concerns:

- collection handles source-specific telemetry
- normalisation converts different formats into a common schema
- correlation groups related events into incident windows
- detection evaluates behaviour and threat intelligence
- scoring explains incident risk
- output produces human-readable and machine-readable alerts

---

## High-Level Architecture

```text
 Ubuntu SSH Authentication Logs         Cowrie Honeypot JSONL
              |                                   |
              v                                   v
    Ubuntu Event Normalisation          Cowrie Event Normalisation
              |                                   |
              +-----------------+-----------------+
                                |
                                v
                    Shared SecurityEvent Model
                                |
                                v
                     Group Events by Source IP
                                |
                                v
                   Five-Minute Incident Windows
                                |
                  +-------------+-------------+
                  |                           |
                  v                           v
        Behavioural Detection          IOC Intelligence Match
                  |                           |
                  +-------------+-------------+
                                |
                                v
                    Explainable Risk Scoring
                                |
                                v
                 Severity and ATT&CK Classification
                                |
                                v
                    Persistent Deduplication
                                |
                  +-------------+-------------+
                  |             |             |
                  v             v             v
               Terminal        CSV           JSON
```

---

## Core Components

### 1. Ubuntu Authentication Log Ingestion

Source:

```text
logs/sample-auth.log
```

The Ubuntu parser processes SSH authentication events such as:

- failed password attempts
- invalid-user authentication attempts
- successful SSH logins

The parser extracts:

- timestamp
- source IP address
- username
- authentication outcome
- destination port
- protocol
- raw evidence

---

### 2. Cowrie Honeypot Ingestion

Source:

```text
logs/sample-cowrie.jsonl
```

The Cowrie parser processes JSONL events including:

- `cowrie.login.failed`
- `cowrie.login.success`
- `cowrie.command.input`
- `cowrie.session.closed`

The parser extracts:

- timestamp
- source IP address
- username
- authentication outcome
- destination port
- executed command
- session activity
- raw JSON evidence

Malformed JSON lines and unsupported event types are skipped without stopping the full pipeline.

---

### 3. Shared Security Event Model

Both Ubuntu and Cowrie events are converted into a shared `SecurityEvent` structure.

```python
SecurityEvent(
    timestamp,
    source_ip,
    event_type,
    username,
    source,
    destination_port,
    protocol,
    raw_log,
)
```

Supported normalised event types include:

- `authentication_failure`
- `authentication_success`
- `command_executed`
- `session_closed`

Normalisation allows source-specific parsing to remain separate from correlation and detection logic.

---

### 4. Event Grouping

Normalised events are grouped by source IP address.

```text
source IP
   |
   +-- Ubuntu events
   |
   +-- Cowrie events
```

This allows activity from different telemetry sources to contribute to the same investigation context.

---

### 5. Five-Minute Incident Correlation

Events for each source IP are sorted by timestamp and divided into five-minute incident windows.

The correlation layer handles:

- out-of-order events
- timezone-aware and timezone-naive timestamps
- malformed timestamps
- missing timestamps
- multiple incidents from the same source IP
- cross-source activity

Events with invalid or missing timestamps are isolated instead of crashing the pipeline.

A cross-source incident is created when Ubuntu and Cowrie events from the same source IP occur inside the same incident window.

Example:

```json
{
  "source_ip": "45.141.215.90",
  "sources": [
    "cowrie",
    "ubuntu_auth"
  ],
  "cross_source": true
}
```

---

## Detection Layer

### Repeated Authentication Failures

The engine counts failed authentication events inside each incident window.

Repeated failures may indicate:

- password guessing
- credential stuffing
- brute-force activity

### Successful Login After Failures

A successful authentication following failed attempts is treated as a higher-confidence compromise pattern.

Classification:

```text
Brute Force → Successful Login
```

MITRE ATT&CK:

- T1110 Brute Force
- T1078 Valid Accounts

### IOC-Matched Activity

Each observed source IP is compared against the active IOC feed in:

```text
data/iocs.json
```

An IOC match increases incident confidence and risk, but is not treated as proof of compromise by itself.

### Post-Authentication Command Activity

Cowrie command events provide evidence of activity after authentication.

Example:

```text
uname -a
```

This contributes to the incident risk score because it shows attacker behaviour beyond the login stage.

---

## IOC Intelligence Layer

The IOC feed supports:

- indicator value
- indicator type
- intelligence source
- confidence
- source reliability
- tags
- first-seen timestamp
- last-seen timestamp
- active status
- expiry timestamp

The engine rejects indicators that are:

- inactive
- expired
- incorrectly structured
- missing required fields
- using invalid expiry values

Example:

```json
{
  "value": "45.141.215.90",
  "type": "ipv4",
  "source": "External Threat Feed",
  "confidence": 90,
  "source_reliability": "A",
  "active": true,
  "tags": [
    "ssh",
    "brute-force",
    "internet-scanner"
  ]
}
```

---

## Explainable Risk Scoring

Each incident receives a numeric score based on observable evidence.

| Risk factor | Points |
|---|---:|
| Failed authentication attempts | +10 each, capped at +30 |
| Successful login after failures | +30 |
| Active IOC match | +25 |
| Activity across multiple telemetry sources | +15 |
| Post-authentication command activity | +10 |

The score is capped at 100.

| Score | Risk level |
|---:|---|
| 0 to 9 | LOW |
| 10 to 29 | MEDIUM |
| 30 to 49 | HIGH |
| 50 to 100 | CRITICAL |

Example:

```json
{
  "risk": {
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
}
```

This allows an analyst to understand why the incident received its score.

---

## Severity and ATT&CK Classification

The engine generates:

- severity
- behavioural classification
- ATT&CK technique mapping

Current mappings:

| Technique | ID | Detection context |
|---|---|---|
| Brute Force | T1110 | Repeated failed SSH authentication attempts |
| Valid Accounts | T1078 | Successful authentication after suspicious failures |

---

## Persistent Deduplication

The engine creates a stable fingerprint for each incident and stores previous detection state in:

```text
alerts/dedup-state.json
```

Repeated incidents inside the configured cooldown period are suppressed.

This prevents the same activity from producing repeated duplicate alerts while allowing similar activity to create a new incident after the cooldown expires.

---

## Output Layer

### Terminal Output

Human-readable alerts include:

- source IP
- IOC status
- IOC source and confidence
- failed and successful login counts
- severity
- classification
- ATT&CK techniques
- evidence

### CSV Output

File:

```text
alerts/alerts.csv
```

CSV output supports filtering, review, and spreadsheet analysis.

### JSON Output

File:

```text
alerts/incidents.json
```

JSON incidents include:

- incident ID
- generation timestamp
- source IP
- telemetry sources
- cross-source status
- risk score and factors
- IOC context
- time window
- event counts
- severity
- classification
- ATT&CK mapping
- raw evidence

---

## Current Data Flow

```text
1. Read Ubuntu authentication logs
2. Read Cowrie JSONL events
3. Normalise both sources
4. Merge normalised events
5. Group events by source IP
6. Sort events by timestamp
7. Create five-minute incident windows
8. Count failed and successful authentication events
9. Detect suspicious authentication behaviour
10. Match the source IP against active IOC intelligence
11. identify cross-source context
12. calculate explainable risk
13. assign severity and ATT&CK techniques
14. suppress duplicate incidents
15. write terminal, CSV, and JSON outputs
```

---

## Security Boundaries

The current implementation is a defensive lab project.

Controls include:

- sample telemetry for demonstrations
- real authentication logs excluded from Git
- generated local alert files excluded where appropriate
- no automatic blocking
- no credential or API-key storage
- no direct changes to production infrastructure
- malformed input isolation
- separation between detection and response

Automated containment is intentionally excluded because incorrect blocking logic could cause denial of service or administrative lockout.

---

## Current Limitations

- batch processing rather than continuous ingestion
- local JSON IOC feed
- correlation based primarily on source IP and time
- rule-based risk weights
- no direct MISP or OpenCTI integration
- no STIX 2.1 or TAXII support
- no external enrichment API
- no analyst dashboard
- no alert assignment or investigation status
- no automated containment
- support currently limited to Ubuntu SSH and selected Cowrie events

---

## Planned Architecture Extensions

```text
Additional Telemetry Sources
            |
            v
Expanded Normalisation Layer
            |
            v
Configurable Correlation Rules
            |
            +------------------------+
            |                        |
            v                        v
STIX/TAXII Ingestion         MISP/OpenCTI Integration
            |                        |
            +------------+-----------+
                         |
                         v
             External IOC Enrichment
                         |
                         v
              Alert Lifecycle Management
                         |
                         v
             Dashboard and Analyst Workflow
                         |
                         v
             Controlled Response Playbooks
```

Planned extensions include:

- STIX 2.1 indicator ingestion
- TAXII collection support
- MISP integration
- OpenCTI integration
- external IOC enrichment
- configurable risk weights
- broader identity-abuse detections
- continuous monitoring
- CI test automation
- dashboard visualisation
- analyst status and alert lifecycle
- controlled response playbooks

---

## Design Goal

The architecture demonstrates an end-to-end defensive security workflow:

```text
Collection
    ↓
Normalisation
    ↓
Correlation
    ↓
Detection
    ↓
Threat Intelligence
    ↓
Risk Scoring
    ↓
Alerting
    ↓
Investigation
```
