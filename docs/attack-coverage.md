# MITRE ATT&CK Detection Coverage

This matrix documents the ATT&CK techniques currently represented by the engine's behavioural detections.

Coverage is intentionally conservative. `Detected` indicates stronger telemetry support, while `Partial` indicates contextual or incomplete coverage.

| Detection | Behaviour | ATT&CK | Technique | Mapping | Coverage |
|---|---|---|---|---|---|
| D001 | Repeated Authentication Failures | T1110 | Brute Force | Supported | Detected |
| D002 | Successful Authentication After Failures | T1078 | Valid Accounts | Contextual | Partial |
| D003 | Multi-Account Authentication Probing | T1110.003 | Password Spraying | Contextual | Partial |
| D004 | Privileged Account Targeting | T1110 | Brute Force | Contextual | Partial |
| D005 | Persistent Authentication Probing | T1110 | Brute Force | Contextual | Partial |
| D006 | Post-Authentication Command Execution | T1059 | Command and Scripting Interpreter | Contextual | Partial |
| D007 | System Reconnaissance | T1082 | System Information Discovery | Contextual | Partial |
| D008 | External File or Tool Download | T1105 | Ingress Tool Transfer | Contextual | Partial |
| D009 | Privilege Escalation Attempt | T1548 | Abuse Elevation Control Mechanism | Contextual | Partial |
| D010 | SSH Authorized Key Persistence Attempt | T1098.004 | SSH Authorized Keys | Supported | Detected |

## Interpretation

- **Detected**: telemetry and detection logic provide comparatively direct support for the ATT&CK mapping.
- **Partial**: observed behaviour is consistent with the ATT&CK technique, but available telemetry does not justify claiming complete coverage.
- **Unsupported**: the engine currently lacks sufficient telemetry or detection logic.

ATT&CK enrichment is loaded from the local MITRE Enterprise ATT&CK STIX dataset.
