# Testing and Validation

## Testing Objective

The IOC Detection Engine is tested to confirm that it can:

- ingest Ubuntu SSH authentication logs
- ingest Cowrie honeypot JSONL events
- normalise different telemetry formats into a shared event model
- group events by source IP
- correlate activity into five-minute incident windows
- handle out-of-order and malformed timestamps
- detect repeated authentication failures
- detect successful login after failures
- match source IPs against lifecycle-aware IOC intelligence
- correlate Ubuntu and Cowrie activity into a single cross-source incident
- calculate an explainable risk score
- map incidents to MITRE ATT&CK
- suppress duplicate incidents
- generate terminal, CSV, and JSON outputs

---

## Test Environment

### Detection System

- Operating system: Ubuntu Linux
- Hostname: `Ubuntu-SSH-Lab`
- Project path:

```text
/home/ubuntu/ioc-detection-engine
```

### Supporting Lab Environment

A Kali Linux virtual machine was used during earlier SSH testing to generate controlled authentication activity against the Ubuntu system.

The current automated test suite uses deterministic sample data and unit tests so results do not depend on a live attacker system.

---

## Test Data Sources

### Ubuntu Authentication Logs

Files used include:

```text
logs/sample-auth.log
logs/v2-test-auth.log
```

Purpose:

- test predictable SSH authentication scenarios
- validate failed and successful login parsing
- test invalid-user events
- verify timestamp handling
- support five-minute correlation tests
- demonstrate cross-source correlation with Cowrie

### Cowrie Honeypot Events

File:

```text
logs/sample-cowrie.jsonl
```

Purpose:

- test Cowrie JSONL ingestion
- validate supported Cowrie event mappings
- test malformed JSON handling
- test authentication and command events
- preserve raw JSON evidence
- support live cross-source correlation

Supported events include:

- `cowrie.login.failed`
- `cowrie.login.success`
- `cowrie.command.input`
- `cowrie.session.closed`

### IOC Feed

File:

```text
data/iocs.json
```

Purpose:

- test IOC matching
- validate lifecycle fields
- verify inactive and expired indicators are rejected
- test source, confidence, reliability, and tag enrichment

---

## Running the Test Suite

From the project root:

```bash
python3 -m unittest discover -s tests -v
```

Current status:

```text
57 automated tests passing
```

---

## Test Coverage Summary

### 1. Ubuntu Timestamp Parsing

Validated behaviour:

- valid Ubuntu timestamps are converted to ISO format
- invalid timestamps return `None`
- malformed timestamps do not stop processing

Result:

```text
PASS
```

### 2. Ubuntu Authentication Normalisation

Validated behaviour:

- failed SSH logins are normalised
- invalid-user login failures are normalised
- successful SSH logins are normalised
- unrelated log lines are ignored
- raw evidence is preserved
- malformed timestamps are retained safely

Result:

```text
PASS
```

### 3. Cowrie JSONL Parsing

Validated behaviour:

- valid JSONL records are read
- malformed JSON lines are skipped
- unsupported Cowrie events are ignored
- missing source IP values are rejected safely

Result:

```text
PASS
```

### 4. Cowrie Event Normalisation

Validated mappings:

| Cowrie event | Normalised event type |
|---|---|
| `cowrie.login.failed` | `authentication_failure` |
| `cowrie.login.success` | `authentication_success` |
| `cowrie.command.input` | `command_executed` |
| `cowrie.session.closed` | `session_closed` |

Result:

```text
PASS
```

### 5. Shared Security Event Model

Validated behaviour:

- normalised events convert to dictionaries
- source, username, destination port, protocol, and raw evidence are preserved
- Ubuntu and Cowrie data can be processed through the same event model

Result:

```text
PASS
```

### 6. Event Grouping

Validated behaviour:

- events are grouped by source IP
- activity from multiple sources can appear in the same source-IP group
- unrelated IP activity remains separated

Result:

```text
PASS
```

### 7. Five-Minute Incident Correlation

Validated behaviour:

- events inside the same five-minute window are grouped
- events after the window create a new incident
- out-of-order events are sorted before correlation
- malformed or missing timestamps are isolated
- multiple incidents from the same source IP remain separate

Result:

```text
PASS
```

### 8. Cross-Source Correlation

Validated behaviour:

- Ubuntu and Cowrie events from the same source IP can share one incident window
- incident source names are deduplicated and sorted
- single-source incidents return `cross_source: false`
- multi-source incidents return `cross_source: true`

Live sample result:

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

Result:

```text
PASS
```

### 9. Authentication Event Counting

Validated behaviour:

- failed authentication events are counted
- successful authentication events are counted
- repeated messages are handled correctly
- non-authentication Cowrie events remain available as evidence without incorrectly changing authentication totals

Result:

```text
PASS
```

### 10. Behavioural Classification

Validated scenarios:

#### Repeated Login Failures

Expected:

- failed attempts counted
- incident classified as suspicious login failure activity
- MITRE ATT&CK T1110 applied

#### Successful Login After Failures

Expected:

- failures and later success correlated
- classification set to:

```text
Brute Force → Successful Login
```

- severity set to `CRITICAL`
- MITRE ATT&CK T1110 and T1078 applied

Result:

```text
PASS
```

### 11. IOC Lifecycle Validation

Validated behaviour:

- active future-dated indicators are loaded
- expired indicators are skipped
- inactive indicators are skipped
- invalid expiry timestamps are rejected
- invalid indicator schema is rejected safely

Result:

```text
PASS
```

### 12. IOC Enrichment

Validated output fields:

- indicator value
- indicator type
- intelligence source
- confidence
- source reliability
- first seen
- last seen
- expiry
- active status
- tags

Validated behaviour:

- IOC context enters JSON incidents
- non-IOC incidents receive an empty IOC context
- CSV headers include enrichment fields

Result:

```text
PASS
```

### 13. Explainable Risk Scoring

Validated scoring rules:

| Risk factor | Points |
|---|---:|
| Failed authentication attempts | +10 each, capped at +30 |
| Successful login after failures | +30 |
| Active IOC match | +25 |
| Activity across multiple sources | +15 |
| Post-authentication command activity | +10 |

Validated risk levels:

| Score | Level |
|---:|---|
| 0 to 9 | LOW |
| 10 to 29 | MEDIUM |
| 30 to 49 | HIGH |
| 50 to 100 | CRITICAL |

Validated scenarios include:

- two basic failures produce a medium-risk score
- one IOC-matched failure produces a high-risk score
- failure points are capped
- cross-source compromise activity reaches critical risk
- risk factors explain every score contribution

Live sample result:

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

Result:

```text
PASS
```

### 14. Incident JSON Model

Validated fields:

- incident ID
- generation time
- source IP
- telemetry sources
- cross-source status
- IOC context
- time window
- event counts
- severity
- classification
- MITRE ATT&CK techniques
- raw evidence
- explainable risk score

Result:

```text
PASS
```

### 15. Persistent Deduplication

Validated behaviour:

- incident fingerprints are stable
- first detections are not marked as duplicates
- repeated detections inside the cooldown are suppressed
- incidents after the cooldown can generate new alerts

Result:

```text
PASS
```

### 16. CSV Output

Validated behaviour:

- CSV output is generated
- enrichment columns are present
- alert data is written in a structured format
- output can be opened in spreadsheet or analysis tools

Output:

```text
alerts/alerts.csv
```

Result:

```text
PASS
```

### 17. JSON Output

Validated behaviour:

- structured incidents are written to JSON
- cross-source context is preserved
- IOC enrichment is included
- risk score and factors are included
- evidence remains available for investigation

Output:

```text
alerts/incidents.json
```

Result:

```text
PASS
```

---

## Live End-to-End Validation

The engine was run against the combined Ubuntu and Cowrie sample sources.

Observed startup summary:

```text
Normalized events: 24
Observed IPs: 7
```

Observed output:

```text
Alerts generated: 11
Duplicates suppressed: 0
```

A live cross-source incident for `45.141.215.90` contained:

- Ubuntu failed-login evidence
- Cowrie failed-login evidence
- Cowrie successful-login evidence
- Cowrie command execution
- Cowrie session closure
- active IOC enrichment
- MITRE ATT&CK T1110 and T1078
- `cross_source: true`
- risk score `100`
- risk level `CRITICAL`

Result:

```text
PASS
```

---

## Error Handling Validation

The test suite confirms that the engine handles:

- malformed Ubuntu timestamps
- missing timestamps
- out-of-order events
- malformed Cowrie JSON
- unsupported Cowrie event types
- missing source IP values
- expired IOC records
- inactive IOC records
- invalid IOC expiry values
- invalid IOC schema

These conditions are isolated or rejected safely instead of causing the entire detection pipeline to fail.

---

## Current Testing Limitations

- no real-time streaming test
- no performance or load testing at production scale
- no fuzz testing
- no direct MISP or OpenCTI integration tests
- no STIX or TAXII interoperability tests
- no external IOC-enrichment API tests
- no dashboard tests
- no automated response testing
- no multi-host distributed deployment tests
- no CI pipeline currently executes the suite automatically

---

## Overall Result

The IOC Detection Engine has successfully demonstrated:

- multi-source ingestion
- event normalisation
- Ubuntu and Cowrie parsing
- five-minute correlation
- cross-source incident creation
- behavioural detection
- IOC lifecycle validation
- IOC enrichment
- explainable risk scoring
- MITRE ATT&CK mapping
- persistent deduplication
- CSV and JSON incident generation
- malformed-data isolation
- automated regression testing

Overall status:

```text
57 TESTS PASSING
CORE DETECTION PIPELINE VALIDATED
```
