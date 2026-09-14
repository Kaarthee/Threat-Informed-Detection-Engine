import csv
import datetime
import hashlib
import json
import re
from collections import defaultdict
from pathlib import Path

try:
    from src.normalization import (
        count_normalized_events,
        create_normalized_event_windows,
        group_events_by_source_ip,
        normalize_cowrie_logs,
        normalize_ubuntu_auth_logs,
        normalized_events_to_raw_logs,
    )
except ModuleNotFoundError:
    from normalization import (
        count_normalized_events,
        create_normalized_event_windows,
        group_events_by_source_ip,
        normalize_cowrie_logs,
        normalize_ubuntu_auth_logs,
        normalized_events_to_raw_logs,
    )


try:
    from src.detections import (
        detect_repeated_authentication_failures,
        detect_success_after_failures,
        detect_multi_account_authentication_probing,
        detect_privileged_account_targeting,
        detect_persistent_authentication_probing,
        detect_post_authentication_command_execution,
        detect_system_reconnaissance,
        detect_external_file_download,
        detect_privilege_escalation_attempt,
        detect_ssh_authorized_key_persistence,
    )
except ModuleNotFoundError:
    from detections import (
        detect_repeated_authentication_failures,
        detect_success_after_failures,
        detect_multi_account_authentication_probing,
        detect_privileged_account_targeting,
        detect_persistent_authentication_probing,
        detect_post_authentication_command_execution,
        detect_system_reconnaissance,
        detect_external_file_download,
        detect_privilege_escalation_attempt,
        detect_ssh_authorized_key_persistence,
    )

try:
    from src.attack import (
        load_attack_knowledge_base,
    )
except ModuleNotFoundError:
    from attack import (
        load_attack_knowledge_base,
    )

# -------- COLORS --------
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"

# -------- CONFIG --------
IOC_FILE = Path("data/iocs.json")
LOG_FILE = Path("logs/sample-auth.log")
COWRIE_LOG_FILE = Path("logs/sample-cowrie.jsonl")
ALERT_FILE = Path("alerts/alerts.csv")
INCIDENT_FILE = Path("alerts/incidents.json")
DEDUP_STATE_FILE = Path("alerts/dedup-state.json")

MAX_LOG_DISPLAY = 5
BRUTE_FORCE_THRESHOLD = 5
CORRELATION_WINDOW_MINUTES = 5
DEDUP_COOLDOWN_MINUTES = 30


def load_iocs(ioc_file: Path) -> dict[str, dict]:
    """Load active, non-expired IOC records from the local JSON feed."""
    try:
        with ioc_file.open("r", encoding="utf-8") as file:
            data = json.load(file)

        indicators = data.get("indicators", [])

        if not isinstance(indicators, list):
            raise ValueError("'indicators' must be a list")

        active_iocs: dict[str, dict] = {}
        current_time = datetime.datetime.now()

        for indicator in indicators:
            if not isinstance(indicator, dict):
                continue

            value = indicator.get("value")

            if not value or not indicator.get("active", False):
                continue

            expires_at = indicator.get("expires_at")

            if expires_at:
                try:
                    expiry_time = datetime.datetime.fromisoformat(
                        expires_at
                    )
                except ValueError:
                    continue

                if expiry_time < current_time:
                    continue

            active_iocs[value] = indicator

        return active_iocs

    except FileNotFoundError:
        print(
            f"{RED}Error: IOC file not found: "
            f"{ioc_file}{RESET}"
        )
        raise SystemExit(1)

    except (json.JSONDecodeError, ValueError) as error:
        print(
            f"{RED}Error: Invalid IOC file: "
            f"{error}{RESET}"
        )
        raise SystemExit(1)


def read_logs(log_file: Path) -> list[str]:
    """Read authentication log lines."""
    try:
        with log_file.open(
            "r",
            encoding="utf-8",
            errors="replace",
        ) as file:
            return file.readlines()

    except FileNotFoundError:
        print(
            f"{RED}Error: Log file not found: "
            f"{log_file}{RESET}"
        )
        raise SystemExit(1)


def extract_ip_logs(
    log_lines: list[str],
) -> dict[str, list[str]]:
    """Group relevant authentication log entries by source IP."""
    ip_pattern = re.compile(
        r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)"
        r"(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b"
    )

    grouped_logs: dict[str, list[str]] = defaultdict(list)

    for line in log_lines:
        if (
            "Failed password" not in line
            and "Accepted password" not in line
        ):
            continue

        for ip in ip_pattern.findall(line):
            grouped_logs[ip].append(line.strip())

    return grouped_logs


def parse_log_timestamp(
    log: str,
) -> datetime.datetime | None:
    """Parse a standard Ubuntu syslog timestamp."""
    pattern = re.compile(
        r"^(?P<month>[A-Z][a-z]{2})\s+"
        r"(?P<day>\d{1,2})\s+"
        r"(?P<time>\d{2}:\d{2}:\d{2})"
    )

    match = pattern.search(log)

    if not match:
        return None

    timestamp_text = (
        f"{datetime.datetime.now().year} "
        f"{match.group('month')} "
        f"{match.group('day')} "
        f"{match.group('time')}"
    )

    try:
        return datetime.datetime.strptime(
            timestamp_text,
            "%Y %b %d %H:%M:%S",
        )
    except ValueError:
        return None


def create_incident_windows(
    logs: list[str],
) -> list[list[str]]:
    """Group log entries into fixed five-minute incidents."""
    parsed_logs: list[
        tuple[datetime.datetime, str]
    ] = []

    unparsed_logs: list[str] = []

    for log in logs:
        timestamp = parse_log_timestamp(log)

        if timestamp is None:
            unparsed_logs.append(log)
        else:
            parsed_logs.append(
                (
                    timestamp,
                    log,
                )
            )

    parsed_logs.sort(
        key=lambda item: item[0]
    )

    incidents: list[list[str]] = []
    current_incident: list[str] = []
    window_start: datetime.datetime | None = None

    for timestamp, log in parsed_logs:
        if window_start is None:
            window_start = timestamp
            current_incident = [log]
            continue

        time_difference = (
            timestamp - window_start
        )

        if time_difference <= datetime.timedelta(
            minutes=CORRELATION_WINDOW_MINUTES
        ):
            current_incident.append(log)
        else:
            incidents.append(current_incident)
            current_incident = [log]
            window_start = timestamp

    if current_incident:
        incidents.append(current_incident)

    for log in unparsed_logs:
        incidents.append([log])

    return incidents


def count_events(
    logs: list[str],
) -> tuple[int, int]:
    """Count failed and successful SSH authentication events."""
    failed = 0
    successful = 0

    repeat_pattern = re.compile(
        r"message repeated (\d+) times"
    )

    for log in logs:
        if "Failed password" in log:
            match = repeat_pattern.search(log)

            if match:
                failed += int(match.group(1))
            else:
                failed += 1

        if "Accepted password" in log:
            successful += 1

    return failed, successful


def classify_activity(
    failed: int,
    successful: int,
    is_ioc_match: bool,
    detected_behaviors: list[dict] | None = None,
) -> tuple[str, str, str, str]:
    """Return severity, classification, MITRE mapping and colour."""

    behaviors = detected_behaviors or []

    technique_ids = sorted(
        {
            behavior["attack"]["technique_id"]
            for behavior in behaviors
            if (
                behavior.get("attack")
                and behavior["attack"].get("technique_id")
            )
        }
    )

    behavior_mitre = (
        ", ".join(technique_ids)
        if technique_ids
        else "N/A"
    )

    detection_ids = {
        behavior.get("detection_id")
        for behavior in behaviors
    }

    if "D010" in detection_ids:
        return (
            "HIGH",
            "SSH Authorized Key Persistence Attempt",
            behavior_mitre,
            RED,
        )

    if "D009" in detection_ids:
        return (
            "HIGH",
            "Privilege Escalation Attempt",
            behavior_mitre,
            RED,
        )

    if "D008" in detection_ids:
        return (
            "HIGH",
            "External File or Tool Download",
            behavior_mitre,
            RED,
        )

    if "D002" in detection_ids:
        return (
            "CRITICAL",
            "Successful Authentication After Failures",
            behavior_mitre,
            YELLOW,
        )

    if "D006" in detection_ids:
        return (
            "HIGH",
            "Post-Authentication Command Execution",
            behavior_mitre,
            RED,
        )

    if "D005" in detection_ids:
        return (
            "HIGH",
            "Persistent Authentication Probing",
            behavior_mitre,
            RED,
        )

    if "D001" in detection_ids:
        return (
            "HIGH",
            "Repeated Authentication Failures",
            behavior_mitre,
            RED,
        )

    if "D007" in detection_ids:
        return (
            "MEDIUM",
            "System Reconnaissance",
            behavior_mitre,
            CYAN,
        )

    if "D004" in detection_ids:
        return (
            "MEDIUM",
            "Privileged Account Targeting",
            behavior_mitre,
            CYAN,
        )

    if "D003" in detection_ids:
        return (
            "MEDIUM",
            "Multi-Account Authentication Probing",
            behavior_mitre,
            CYAN,
        )

    # Backward-compatible classification for callers/tests
    # that do not yet supply the behaviour catalogue.
    if failed > 0 and successful > 0:
        return (
            "CRITICAL",
            "Brute Force → Successful Login",
            "T1110, T1078",
            YELLOW,
        )

    if failed >= BRUTE_FORCE_THRESHOLD:
        return (
            "HIGH",
            "SSH Brute Force",
            "T1110",
            RED,
        )

    if successful > 0 and is_ioc_match:
        return (
            "CRITICAL",
            "Known IOC Successful Login",
            "T1078",
            YELLOW,
        )

    if successful > 0:
        return (
            "LOW",
            "Successful Login",
            "T1078",
            GREEN,
        )

    if failed > 0 and is_ioc_match:
        return (
            "HIGH",
            "IOC-Matched Login Failures",
            "T1110",
            RED,
        )

    if failed > 0:
        return (
            "MEDIUM",
            "Login Failures",
            "T1110",
            CYAN,
        )

    return (
        "INFO",
        "No Relevant Activity",
        "N/A",
        CYAN,
    )

def should_alert(
    failed: int,
    successful: int,
    is_ioc_match: bool,
    detected_behaviors: list[dict] | None = None,
) -> bool:
    """Determine whether activity should generate an alert."""

    return (
        failed > 0
        or is_ioc_match
        or bool(detected_behaviors)
    )

def write_csv_header(
    alert_file: Path,
) -> None:
    """Create the alert CSV file and write its header."""
    alert_file.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with alert_file.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as csvfile:
        writer = csv.writer(csvfile)

        writer.writerow(
            [
                "Alert ID",
                "Timestamp",
                "IP",
                "IOC Match",
                "IOC Source",
                "IOC Confidence",
                "Source Reliability",
                "IOC Tags",
                "First Seen",
                "Last Seen",
                "Expires At",
                "Failed Attempts",
                "Successful Logins",
                "Severity",
                "Classification",
                "MITRE ATT&CK",
                "Evidence",
            ]
        )


def append_alert(
    alert_file: Path,
    alert_id: int,
    timestamp: str,
    ip: str,
    is_ioc_match: bool,
    failed: int,
    successful: int,
    severity: str,
    classification: str,
    mitre: str,
    logs: list[str],
    ioc_record: dict | None = None,
) -> None:
    """Append a structured enriched alert to the CSV file."""
    ioc_record = ioc_record or {}
    tags = ioc_record.get("tags", [])

    with alert_file.open(
        "a",
        newline="",
        encoding="utf-8",
    ) as csvfile:
        writer = csv.writer(csvfile)

        writer.writerow(
            [
                alert_id,
                timestamp,
                ip,
                "Yes" if is_ioc_match else "No",
                ioc_record.get(
                    "source",
                    "N/A",
                ),
                ioc_record.get(
                    "confidence",
                    "N/A",
                ),
                ioc_record.get(
                    "source_reliability",
                    "N/A",
                ),
                (
                    ", ".join(tags)
                    if tags
                    else "N/A"
                ),
                ioc_record.get(
                    "first_seen",
                    "N/A",
                ),
                ioc_record.get(
                    "last_seen",
                    "N/A",
                ),
                ioc_record.get(
                    "expires_at",
                    "N/A",
                ),
                failed,
                successful,
                severity,
                classification,
                mitre,
                " | ".join(logs),
            ]
        )


def print_alert(
    alert_id: int,
    ip: str,
    is_ioc_match: bool,
    failed: int,
    successful: int,
    severity: str,
    classification: str,
    mitre: str,
    colour: str,
    logs: list[str],
    ioc_record: dict | None = None,
) -> None:
    """Display an enriched alert in the terminal."""
    print(
        f"{colour}"
        f"{'=' * 60}"
        f"{RESET}"
    )

    print(
        f"{colour}"
        f"ALERT #{alert_id}"
        f"{RESET}"
    )

    print(
        f"{colour}"
        f"{'-' * 60}"
        f"{RESET}"
    )

    print(
        f"{CYAN}Source IP:{RESET} "
        f"{ip}"
    )

    print(
        f"{CYAN}IOC Match:{RESET} "
        f"{'Yes' if is_ioc_match else 'No'}"
    )

    if ioc_record:
        print(
            f"{CYAN}IOC Source:{RESET} "
            f"{ioc_record.get('source', 'N/A')}"
        )

        print(
            f"{CYAN}IOC Confidence:{RESET} "
            f"{ioc_record.get('confidence', 'N/A')}"
        )

        print(
            f"{CYAN}Source Reliability:{RESET} "
            f"{ioc_record.get('source_reliability', 'N/A')}"
        )

        print(
            f"{CYAN}IOC Tags:{RESET} "
            f"{', '.join(ioc_record.get('tags', [])) or 'N/A'}"
        )

        print(
            f"{CYAN}First Seen:{RESET} "
            f"{ioc_record.get('first_seen', 'N/A')}"
        )

        print(
            f"{CYAN}Last Seen:{RESET} "
            f"{ioc_record.get('last_seen', 'N/A')}"
        )

        print(
            f"{CYAN}Expires At:{RESET} "
            f"{ioc_record.get('expires_at', 'N/A')}"
        )
    else:
        print(
            f"{CYAN}IOC Source:{RESET} "
            f"N/A"
        )

    print(
        f"{CYAN}Failed Attempts:{RESET} "
        f"{failed}"
    )

    print(
        f"{CYAN}Successful Logins:{RESET} "
        f"{successful}"
    )

    print(
        f"{CYAN}Severity:{RESET} "
        f"{severity}"
    )

    print(
        f"{CYAN}Classification:{RESET} "
        f"{classification}"
    )

    print(
        f"{CYAN}MITRE ATT&CK:{RESET} "
        f"{mitre}"
    )

    print(
        f"\n{CYAN}Evidence — last "
        f"{MAX_LOG_DISPLAY} entries:"
        f"{RESET}"
    )

    for log in logs[-MAX_LOG_DISPLAY:]:
        print(f"  - {log}")

    if len(logs) > MAX_LOG_DISPLAY:
        hidden_count = (
            len(logs) - MAX_LOG_DISPLAY
        )

        print(
            f"{CYAN}... "
            f"({hidden_count} more logs hidden)"
            f"{RESET}"
        )

    print(
        f"{colour}"
        f"{'=' * 60}"
        f"{RESET}\n"
    )

def sanitize_evidence_log(
    log: str,
) -> str:
    """
    Redact sensitive credential material from JSON evidence.
    """

    try:
        event = json.loads(
            log
        )
    except (
        json.JSONDecodeError,
        TypeError,
    ):
        return log

    sensitive_fields = {
        "password",
        "passwd",
        "secret",
        "token",
    }

    for field in sensitive_fields:
        if field in event:
            event[field] = "[REDACTED]"

    message = event.get(
        "message"
    )

    if isinstance(message, str):
        if event.get(
            "eventid"
        ) in {
            "cowrie.login.failed",
            "cowrie.login.success",
        }:
            username = event.get(
                "username",
                "unknown",
            )

            event["message"] = (
                f"login attempt [{username}/[REDACTED]]"
            )

    return json.dumps(
        event,
        sort_keys=True,
    )


def sanitize_evidence_logs(
    logs: list[str],
) -> list[str]:
    """Redact sensitive values from incident evidence."""

    return [
        sanitize_evidence_log(
            log
        )
        for log in logs
    ]

def get_incident_time_range(
    logs: list[str],
) -> tuple[str | None, str | None]:
    """
    Return earliest and latest valid timestamps from
    Ubuntu syslog or Cowrie JSON evidence.
    """

    timestamps: list[datetime.datetime] = []

    for log in logs:
        ubuntu_timestamp = parse_log_timestamp(
            log
        )

        if ubuntu_timestamp is not None:
            timestamps.append(
                ubuntu_timestamp
            )
            continue

        try:
            cowrie_event = json.loads(
                log
            )
        except (
            json.JSONDecodeError,
            TypeError,
        ):
            continue

        timestamp_value = cowrie_event.get(
            "timestamp"
        )

        if not isinstance(
            timestamp_value,
            str,
        ):
            continue

        try:
            cowrie_timestamp = (
                datetime.datetime.fromisoformat(
                    timestamp_value.replace(
                        "Z",
                        "+00:00",
                    )
                )
            )
        except ValueError:
            continue

        if cowrie_timestamp.tzinfo is not None:
            cowrie_timestamp = (
                cowrie_timestamp.astimezone(
                    datetime.timezone.utc
                ).replace(
                    tzinfo=None
                )
            )

        timestamps.append(
            cowrie_timestamp
        )

    if not timestamps:
        return None, None

    timestamps.sort()

    return (
        timestamps[0].isoformat(),
        timestamps[-1].isoformat(),
    )

def calculate_risk_score(
    is_ioc_match: bool,
    failed: int,
    successful: int,
    sources: list[str] | None,
    logs: list[str],
) -> tuple[int, str, list[str]]:
    """Calculate an explainable incident risk score."""

    score = 0
    factors: list[str] = []

    failed_points = min(failed * 10, 30)

    if failed_points > 0:
        score += failed_points
        
        attempt_word = (
            "attempt"
            if failed == 1
            else "attempts"
        )

        factors.append(
            f"{failed} failed authentication "
            f"{attempt_word}: +{failed_points}"
        )

    if failed > 0 and successful > 0:
        score += 30
        factors.append(
            "Successful login after failures: +30"
        )

    if is_ioc_match:
        score += 25
        factors.append(
            "Active IOC match: +25"
        )

    unique_sources = sorted(
        set(sources or [])
    )
    if len(unique_sources) > 1:
        score += 15
        factors.append(
            "Activity observed across "
            f"{len(unique_sources)} sources: +15"
        )

    command_activity = any(
        "cowrie.command.input" in log
        for log in logs
    )

    if command_activity:
        score += 10
        factors.append(
            "Post-authentication command activity: +10"
        )

    score = min(score, 100)

    if score >= 50:
        level = "CRITICAL"
    elif score >= 30:
        level = "HIGH"
    elif score >= 10:
        level = "MEDIUM"
    else:
        level = "LOW"

    return score, level, factors

def generate_actionable_intelligence(
    is_ioc_match: bool,
    failed: int,
    successful: int,
    sources: list[str] | None,
    logs: list[str],
) -> dict:
    """Generate evidence-driven analyst priority and context."""

    unique_sources = sorted(
        set(sources or [])
    )

    cross_source = len(unique_sources) > 1

    success_after_failures = (
        failed > 0
        and successful > 0
    )

    command_activity = any(
        "cowrie.command.input" in log
        for log in logs
    )

    if (
        success_after_failures
        and (
            is_ioc_match
            or cross_source
            or command_activity
        )
    ):
        priority = "IMMEDIATE"

    elif (
        success_after_failures
        or (
            is_ioc_match
            and failed >= 2
        )
        or (
            cross_source
            and failed > 0
        )
    ):
        priority = "HIGH"

    elif (
        failed >= 2
        or is_ioc_match
    ):
        priority = "ROUTINE"

    else:
        priority = "LOW"

    reasons: list[str] = []
    investigation_steps: list[str] = []
    recommended_actions: list[str] = []
    detection_opportunities: list[str] = []

    if failed == 1:
        reasons.append(
            "1 failed authentication attempt "
            "was observed"
        )
    elif failed > 1:
        reasons.append(
            f"{failed} failed authentication "
            "attempts were observed"
        )

    if success_after_failures:
        reasons.append(
            "a successful login followed "
            "earlier authentication failures"
        )

    if is_ioc_match:
        reasons.append(
            "the source matched active "
            "threat intelligence"
        )

    if cross_source:
        reasons.append(
            "activity was confirmed across "
            "multiple telemetry sources"
        )

    if command_activity:
        reasons.append(
            "post-authentication command "
            "activity was observed"
        )

    if failed > 0:
        investigation_steps.append(
            "Review authentication logs for the "
            "source IP and targeted usernames."
        )

    if failed >= 2:
        investigation_steps.append(
            "Check whether the failed attempts "
            "targeted multiple accounts or "
            "occurred repeatedly over time."
        )

        detection_opportunities.append(
            "Create or tune a detection for "
            "repeated SSH authentication failures "
            "from the same source."
        )

    if success_after_failures:
        investigation_steps.append(
            "Validate the successful login and "
            "determine whether the authenticated "
            "account activity was legitimate."
        )

        recommended_actions.append(
            "Review the affected account for "
            "possible credential compromise."
        )

        detection_opportunities.append(
            "Detect successful authentication "
            "following repeated failures within "
            "a short time window."
        )

    if is_ioc_match:
        investigation_steps.append(
            "Search the environment for additional "
            "activity associated with the matched IOC."
        )

        recommended_actions.append(
            "Consider blocking or restricting the "
            "IOC after validating business impact."
        )

        detection_opportunities.append(
            "Hunt for the matched IOC across "
            "available security telemetry."
        )

    if cross_source:
        investigation_steps.append(
            "Compare evidence across all telemetry "
            "sources to confirm the incident scope."
        )

        detection_opportunities.append(
            "Correlate matching source activity "
            "across independent log sources."
        )

    if command_activity:
        investigation_steps.append(
            "Review post-authentication commands "
            "for reconnaissance, persistence, "
            "privilege escalation, or execution."
        )

        recommended_actions.append(
            "Escalate for deeper host investigation "
            "if suspicious command execution is confirmed."
        )

        detection_opportunities.append(
            "Detect suspicious command execution "
            "following successful remote authentication."
        )

    if reasons:
        why_it_matters = (
            "; ".join(reasons) + "."
        )
    else:
        why_it_matters = (
            "Limited suspicious activity "
            "was observed."
        )

    return {
        "priority": priority,
        "why_it_matters": why_it_matters,
        "investigation_steps": investigation_steps,
        "recommended_actions": recommended_actions,
        "detection_opportunities": detection_opportunities,
    }


def extract_incident_context(
    events,
) -> dict:
    """Extract analyst-relevant context from normalized events."""

    usernames = sorted(
        {
            event.username
            for event in events
            if event.username
        }
    )

    source_ports = sorted(
        {
            event.source_port
            for event in events
            if event.source_port is not None
        }
    )

    destination_ports = sorted(
        {
            event.destination_port
            for event in events
            if event.destination_port is not None
        }
    )

    event_types = sorted(
        {
            event.event_type
            for event in events
            if event.event_type
        }
    )

    sources = sorted(
        {
            event.source
            for event in events
            if event.source
        }
    )

    return {
        "usernames": usernames,
        "source_ports": source_ports,
        "destination_ports": destination_ports,
        "event_types": event_types,
        "sources": sources,
    }


def extract_incident_commands(
    events,
) -> list[str]:
    """Extract Cowrie command input from normalized incident events."""

    commands: list[str] = []

    for event in events:
        if event.event_type != "command_executed":
            continue

        try:
            raw_event = json.loads(
                event.raw_log
            )
        except (
            json.JSONDecodeError,
            TypeError,
        ):
            continue

        command = raw_event.get("input")

        if (
            isinstance(command, str)
            and command.strip()
        ):
            commands.append(
                command.strip()
            )

    return commands


def serialize_detected_behavior(
    behavior,
) -> dict:
    """Convert a DetectedBehavior object into incident JSON."""

    attack = None

    if behavior.attack_technique_id:
        attack = {
            "technique_id": (
                behavior.attack_technique_id
            ),
            "mapping_status": (
                behavior.attack_mapping_status
            ),
        }

    return {
        "detection_id": behavior.detection_id,
        "name": behavior.name,
        "behavior": behavior.behavior,
        "confidence": behavior.confidence,
        "evidence": behavior.evidence,
        "attack": attack,
    }

def parse_event_timestamp(
    timestamp: str | None,
) -> datetime.datetime | None:
    """Parse normalized ISO event timestamps."""

    if not timestamp:
        return None

    try:
        parsed = datetime.datetime.fromisoformat(
            timestamp.replace(
                "Z",
                "+00:00",
            )
        )
    except ValueError:
        return None

    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(
            datetime.timezone.utc
        ).replace(
            tzinfo=None
        )

    return parsed


def calculate_failed_activity_span(
    incident_windows,
) -> tuple[int, int, float | None]:
    """
    Return failed-window count, total failures and
    time span covering failed authentication windows.
    """

    failed_windows = []

    total_failed = 0

    for window in incident_windows:
        failed, _ = count_normalized_events(
            window
        )

        if failed <= 0:
            continue

        total_failed += failed

        timestamps = [
            parsed
            for event in window
            if (
                parsed := parse_event_timestamp(
                    event.timestamp
                )
            ) is not None
        ]

        if timestamps:
            failed_windows.append(
                min(timestamps)
            )

    if len(failed_windows) < 2:
        return (
            len(failed_windows),
            total_failed,
            None,
        )

    failed_windows.sort()

    activity_span = (
        failed_windows[-1]
        - failed_windows[0]
    )

    return (
        len(failed_windows),
        total_failed,
        activity_span.total_seconds()
        / 60,
    )

def run_behavior_detections(
    failed: int,
    successful: int,
    usernames: list[str],
    commands: list[str],
    failed_window_count: int,
    source_failed_count: int,
    activity_span_minutes: float | None,
) -> list[dict]:
    """Run the complete behaviour detection catalogue."""

    persistent_failed_count = (
        source_failed_count
        if failed > 0
        else 0
    )

    candidates = [
        detect_repeated_authentication_failures(
            failed
        ),
        detect_success_after_failures(
            failed,
            successful,
        ),
        detect_multi_account_authentication_probing(
            usernames
        ),
        detect_privileged_account_targeting(
            usernames
        ),
        detect_persistent_authentication_probing(
            failed_window_count,
            persistent_failed_count,
            activity_span_minutes,
        ),
        detect_post_authentication_command_execution(
            successful,
            commands,
        ),
        detect_system_reconnaissance(
            commands
        ),
        detect_external_file_download(
            commands
        ),
        detect_privilege_escalation_attempt(
            commands
        ),
        detect_ssh_authorized_key_persistence(
            commands
        ),
    ]

    return [
        serialize_detected_behavior(
            behavior
        )
        for behavior in candidates
        if behavior is not None
    ]

def build_incident_record(
    alert_id: int,
    generated_at: str,
    ip: str,
    is_ioc_match: bool,
    failed: int,
    successful: int,
    severity: str,
    classification: str,
    mitre: str,
    logs: list[str],
    ioc_record: dict | None = None,
    sources: list[str] | None = None,
    incident_context: dict | None = None,
    detected_behaviors: list[dict] | None = None,
) -> dict:
    """Build a structured enriched JSON incident record."""
    start_time, end_time = (
        get_incident_time_range(logs)
    )
    unique_sources = sorted(
        set(sources or [])
    )
    incident_context = incident_context or {
        "usernames": [],
        "source_ports": [],
        "destination_ports": [],
        "event_types": [],
        "sources": unique_sources,
    }

    detected_behaviors = (
        detected_behaviors or []
    )
    risk_score, risk_level, risk_factors = (
        calculate_risk_score(
            is_ioc_match=is_ioc_match,
            failed=failed,
            successful=successful,
            sources=unique_sources,
            logs=logs,
        )
    )
    actionable_intelligence = (
        generate_actionable_intelligence(
            is_ioc_match=is_ioc_match,
            failed=failed,
            successful=successful,
            sources=unique_sources,
            logs=logs,
        )
    ) 
    ioc_context = {
        "matched": is_ioc_match,
        "value": None,
        "type": None,
        "source": None,
        "confidence": None,
        "source_reliability": None,
        "first_seen": None,
        "last_seen": None,
        "expires_at": None,
        "active": False,
        "tags": [],
    }

    if ioc_record:
        ioc_context = {
            "matched": True,
            "value": ioc_record.get(
                "value"
            ),
            "type": ioc_record.get(
                "type"
            ),
            "source": ioc_record.get(
                "source"
            ),
            "confidence": ioc_record.get(
                "confidence"
            ),
            "source_reliability": ioc_record.get(
                "source_reliability"
            ),
            "first_seen": ioc_record.get(
                "first_seen"
            ),
            "last_seen": ioc_record.get(
                "last_seen"
            ),
            "expires_at": ioc_record.get(
                "expires_at"
            ),
            "active": ioc_record.get(
                "active",
                False,
            ),
            "tags": ioc_record.get(
                "tags",
                [],
            ),
        }

    return {
        "incident_id": f"INC-{alert_id:04d}",
        "generated_at": generated_at,
        "source_ip": ip,
        "sources": unique_sources,
        "cross_source": (
            len(unique_sources) > 1
        ),
        "incident_context": incident_context,
        "detected_behaviors": detected_behaviors,
        "risk": {
            "score": risk_score,
            "level": risk_level,
            "factors": risk_factors,
        },
        "actionable_intelligence": (
            actionable_intelligence
        ),
        "ioc": ioc_context,
        "time_window": {
            "start": start_time,
            "end": end_time,
            "window_minutes": (
                CORRELATION_WINDOW_MINUTES
            ),
        },
        "event_counts": {
            "failed_logins": failed,
            "successful_logins": successful,
            "total_events": len(logs),
        },
        "severity": severity,
        "classification": classification,
        "mitre_attack": sorted(
            {
                behavior["attack"]["technique_id"]
                for behavior in detected_behaviors
                if (
                    behavior.get("attack")
                    and behavior["attack"].get(
                        "technique_id"
                    )
                )
            }
        ) if detected_behaviors else [
            technique.strip()
            for technique in mitre.split(",")
            if (
                technique.strip()
                and technique.strip() != "N/A"
            )
        ],
        "evidence": logs,
    }


def write_incident_json(
    incident_file: Path,
    incidents: list[dict],
) -> None:
    """Write structured incident records to JSON."""
    incident_file.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with incident_file.open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            incidents,
            file,
            indent=4,
            ensure_ascii=False,
        )


def create_incident_fingerprint(
    incident: dict,
) -> str:
    """Create a stable fingerprint for an incident."""
    fingerprint_data = {
        "source_ip": incident["source_ip"],
        "classification": incident[
            "classification"
        ],
        "time_window": incident[
            "time_window"
        ],
        "evidence": incident[
            "evidence"
        ],
    }

    encoded_data = json.dumps(
        fingerprint_data,
        sort_keys=True,
        ensure_ascii=False,
    ).encode("utf-8")

    return hashlib.sha256(
        encoded_data
    ).hexdigest()


def load_dedup_state(
    state_file: Path,
) -> dict:
    """Load persistent deduplication state."""
    if not state_file.exists():
        return {}

    try:
        with state_file.open(
            "r",
            encoding="utf-8",
        ) as file:
            state = json.load(file)

        if isinstance(state, dict):
            return state

        return {}

    except (
        json.JSONDecodeError,
        OSError,
    ):
        return {}


def save_dedup_state(
    state_file: Path,
    state: dict,
) -> None:
    """Save persistent deduplication state."""
    state_file.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with state_file.open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            state,
            file,
            indent=4,
            ensure_ascii=False,
        )


def is_duplicate_incident(
    fingerprint: str,
    dedup_state: dict,
    current_time: datetime.datetime,
) -> bool:
    """Return True when an incident is inside the cooldown period."""
    previous = dedup_state.get(
        fingerprint
    )

    if previous is None:
        dedup_state[fingerprint] = {
            "last_seen": (
                current_time.isoformat()
            ),
            "repeat_count": 1,
        }

        return False

    try:
        last_seen = (
            datetime.datetime.fromisoformat(
                previous["last_seen"]
            )
        )

    except (
        KeyError,
        TypeError,
        ValueError,
    ):
        dedup_state[fingerprint] = {
            "last_seen": (
                current_time.isoformat()
            ),
            "repeat_count": 1,
        }

        return False

    previous["repeat_count"] = (
        previous.get(
            "repeat_count",
            1,
        )
        + 1
    )

    time_difference = (
        current_time - last_seen
    )

    if time_difference <= datetime.timedelta(
        minutes=DEDUP_COOLDOWN_MINUTES
    ):
        return True

    previous["last_seen"] = (
        current_time.isoformat()
    )

    return False


def main() -> None:
    
    attack_kb = (
        load_attack_knowledge_base()
    )
    ioc_records = load_iocs(
        IOC_FILE
    )

    log_lines = read_logs(
        LOG_FILE
    )

    ubuntu_events = normalize_ubuntu_auth_logs(
        log_lines
    )

    cowrie_events = normalize_cowrie_logs(
        COWRIE_LOG_FILE
    )

    normalized_events = (
        ubuntu_events
        + cowrie_events
    )

    ip_events = group_events_by_source_ip(
        normalized_events
    )

    print(
        f"{CYAN}========== "
        f"Threat-Informed Detection Engine "
        f"=========={RESET}\n"
    )

    print(
        f"Ubuntu log source: "
        f"{LOG_FILE}"
    )

    print(
        f"Cowrie log source: "
        f"{COWRIE_LOG_FILE}"
    )

    print(
        f"Normalized events: "
        f"{len(normalized_events)}"
    )

    print(
        f"IOC source: "
        f"{IOC_FILE}"
    )

    print(
        f"Observed IPs: "
        f"{len(ip_events)}\n"
    )

    write_csv_header(
        ALERT_FILE
    )

    alert_id = 1
    incident_records: list[dict] = []

    dedup_state = load_dedup_state(
        DEDUP_STATE_FILE
    )

    suppressed_duplicates = 0

    for ip, events in ip_events.items():
        ioc_record = ioc_records.get(
            ip
        )

        is_ioc_match = (
            ioc_record is not None
        )

        incident_windows = (
            create_normalized_event_windows(
                events,
                CORRELATION_WINDOW_MINUTES,
            )
        )

        (
             failed_window_count,
             source_failed_count,
             activity_span_minutes,
         ) = calculate_failed_activity_span(
             incident_windows
         )
        for (
            incident_number,
            incident_logs,
        ) in enumerate(
            incident_windows,
            start=1,
        ):
            failed, successful = (
                count_normalized_events(
                    incident_logs
                )
            )

            raw_logs = sanitize_evidence_logs(
                normalized_events_to_raw_logs(
                    incident_logs
                )
            )
            incident_sources = sorted(
                {
                    event.source
                    for event in incident_logs
                }
            )
            incident_context = extract_incident_context(
                incident_logs
            )

            commands = extract_incident_commands(
                incident_logs
            )

            detected_behaviors = (
                run_behavior_detections(
                    failed=failed,
                    successful=successful,
                    usernames=incident_context[
                        "usernames"
                    ],
                    commands=commands,
                    failed_window_count=(
                        failed_window_count
                    ),
                    source_failed_count=(
                        source_failed_count
                    ),
                    activity_span_minutes=(
                        activity_span_minutes
                    ),
                )
            )

            if attack_kb is not None:
                detected_behaviors = [
                    attack_kb.enrich_behavior(
                        behavior
                    )
                    for behavior in detected_behaviors
                ]

            if not should_alert(
                failed,
                successful,
                is_ioc_match,
                detected_behaviors,
            ):
                continue

            (
                severity,
                classification,
                mitre,
                colour,
            ) = classify_activity(
                failed,
                successful,
                is_ioc_match,
                detected_behaviors,
            )

            current_time = (
                datetime.datetime.now()
            )

            timestamp = (
                current_time.strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
            )

            incident_record = (
                build_incident_record(
                    alert_id,
                    timestamp,
                    ip,
                    is_ioc_match,
                    failed,
                    successful,
                    severity,
                    classification,
                    mitre,
                    raw_logs,
                    ioc_record,
                    incident_sources,
                    incident_context,
                    detected_behaviors,
                )
            )

            fingerprint = (
                create_incident_fingerprint(
                    incident_record
                )
            )

            if is_duplicate_incident(
                fingerprint,
                dedup_state,
                current_time,
            ):
                suppressed_duplicates += 1
                continue

            print(
                f"{CYAN}Incident window: "
                f"{incident_number}/"
                f"{len(incident_windows)}"
                f"{RESET}"
            )

            print_alert(
                alert_id,
                ip,
                is_ioc_match,
                failed,
                successful,
                severity,
                classification,
                mitre,
                colour,
                raw_logs,
                ioc_record,
            )

            append_alert(
                ALERT_FILE,
                alert_id,
                timestamp,
                ip,
                is_ioc_match,
                failed,
                successful,
                severity,
                classification,
                mitre,
                raw_logs,
                ioc_record,
            )

            incident_records.append(
                incident_record
            )

            alert_id += 1

    save_dedup_state(
        DEDUP_STATE_FILE,
        dedup_state,
    )

    write_incident_json(
        INCIDENT_FILE,
        incident_records,
    )

    generated_alerts = (
        alert_id - 1
    )

    print(
        f"{GREEN}"
        f"Detection completed"
        f"{RESET}"
    )

    print(
        f"{GREEN}"
        f"Alerts generated: "
        f"{generated_alerts}"
        f"{RESET}"
    )

    print(
        f"{GREEN}"
        f"CSV output: "
        f"{ALERT_FILE}"
        f"{RESET}"
    )

    print(
        f"{GREEN}"
        f"JSON output: "
        f"{INCIDENT_FILE}"
        f"{RESET}"
    )

    print(
        f"{GREEN}"
        f"Duplicates suppressed: "
        f"{suppressed_duplicates}"
        f"{RESET}"
    )


if __name__ == "__main__":
    main()
