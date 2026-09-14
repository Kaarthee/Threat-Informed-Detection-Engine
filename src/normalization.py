import datetime
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass
class SecurityEvent:
    """Normalized security event shared across log sources."""

    timestamp: str | None
    source_ip: str
    event_type: str
    username: str | None
    source: str
    destination_port: int | None
    protocol: str
    raw_log: str
    source_port: int | None = None

    def to_dict(self) -> dict:
        """Convert the event into a serializable dictionary."""
        return asdict(self)


def parse_ubuntu_timestamp(
    log: str,
) -> str | None:
    """Convert an Ubuntu syslog timestamp into ISO 8601 format."""
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
        parsed_timestamp = datetime.datetime.strptime(
            timestamp_text,
            "%Y %b %d %H:%M:%S",
        )
    except ValueError:
        return None

    return parsed_timestamp.isoformat()


def normalize_ubuntu_auth_log(
    log: str,
) -> SecurityEvent | None:
    """Normalize one Ubuntu SSH authentication log entry."""
    failed_pattern = re.compile(
        r"Failed password for "
        r"(?P<invalid>invalid user )?"
        r"(?P<username>\S+) "
        r"from (?P<source_ip>\d{1,3}(?:\.\d{1,3}){3}) "
        r"port (?P<port>\d+)"
    )

    accepted_pattern = re.compile(
        r"Accepted password for "
        r"(?P<username>\S+) "
        r"from (?P<source_ip>\d{1,3}(?:\.\d{1,3}){3}) "
        r"port (?P<port>\d+)"
    )

    failed_match = failed_pattern.search(log)
    accepted_match = accepted_pattern.search(log)

    if failed_match:
        return SecurityEvent(
            timestamp=parse_ubuntu_timestamp(log),
            source_ip=failed_match.group(
                "source_ip"
            ),
            event_type="authentication_failure",
            username=failed_match.group(
                "username"
            ),
            source="ubuntu_auth",
            destination_port=22,
            protocol="ssh",
            raw_log=log.strip(),
            source_port=int(
                failed_match.group("port")
            ),
        )

    if accepted_match:
        return SecurityEvent(
            timestamp=parse_ubuntu_timestamp(log),
            source_ip=accepted_match.group(
                "source_ip"
            ),
            event_type="authentication_success",
            username=accepted_match.group(
                "username"
            ),
            source="ubuntu_auth",
            destination_port=22,
            protocol="ssh",
            raw_log=log.strip(),
            source_port=int(
                accepted_match.group("port")
            ),
        )

    return None


def normalize_ubuntu_auth_logs(
    logs: list[str],
) -> list[SecurityEvent]:
    """Normalize all supported Ubuntu authentication logs."""
    events: list[SecurityEvent] = []

    for log in logs:
        event = normalize_ubuntu_auth_log(
            log
        )

        if event is not None:
            events.append(event)

    return events


def normalize_cowrie_event(
    event_data: dict,
) -> SecurityEvent | None:
    """Normalize one supported Cowrie JSON event."""
    event_type_map = {
        "cowrie.login.failed": (
            "authentication_failure"
        ),
        "cowrie.login.success": (
            "authentication_success"
        ),
        "cowrie.command.input": (
            "command_executed"
        ),
        "cowrie.session.closed": (
            "session_closed"
        ),
    }

    cowrie_event_id = event_data.get(
        "eventid"
    )

    normalized_event_type = (
        event_type_map.get(
            cowrie_event_id
        )
    )

    if normalized_event_type is None:
        return None

    source_ip = event_data.get(
        "src_ip"
    )

    if not source_ip:
        return None

    timestamp = event_data.get(
        "timestamp"
    )

    if timestamp:
        normalized_timestamp = str(
            timestamp
        ).replace(
            "Z",
            "+00:00",
        )

        try:
            timestamp = (
                datetime.datetime.fromisoformat(
                    normalized_timestamp
                ).isoformat()
            )
        except ValueError:
            timestamp = None

    source_port = event_data.get(
        "src_port"
    )

    try:
        source_port = (
            int(source_port)
            if source_port is not None
            else None
        )
    except (TypeError, ValueError):
        source_port = None

    destination_port = event_data.get(
        "dst_port"
    )

    try:
        destination_port = (
            int(destination_port)
            if destination_port is not None
            else None
        )
    except (TypeError, ValueError):
        destination_port = None

    raw_log = json.dumps(
        event_data,
        sort_keys=True,
        ensure_ascii=False,
    )

    return SecurityEvent(
        timestamp=timestamp,
        source_ip=str(source_ip),
        event_type=normalized_event_type,
        username=event_data.get(
            "username"
        ),
        source="cowrie",
        destination_port=destination_port,
        protocol="ssh",
        raw_log=raw_log,
        source_port=source_port,
    )


def read_cowrie_jsonl(
    log_file: Path,
) -> list[dict]:
    """Read Cowrie JSONL records, skipping malformed lines."""
    events: list[dict] = []

    try:
        with log_file.open(
            "r",
            encoding="utf-8",
            errors="replace",
        ) as file:
            for line in file:
                line = line.strip()

                if not line:
                    continue

                try:
                    event_data = json.loads(
                        line
                    )
                except json.JSONDecodeError:
                    continue

                if isinstance(
                    event_data,
                    dict,
                ):
                    events.append(
                        event_data
                    )

    except FileNotFoundError:
        return []

    return events


def normalize_cowrie_logs(
    log_file: Path,
) -> list[SecurityEvent]:
    """Read and normalize supported Cowrie JSONL events."""
    normalized_events: list[
        SecurityEvent
    ] = []

    for event_data in read_cowrie_jsonl(
        log_file
    ):
        event = normalize_cowrie_event(
            event_data
        )

        if event is not None:
            normalized_events.append(
                event
            )

    return normalized_events


def group_events_by_source_ip(
    events: list[SecurityEvent],
) -> dict[str, list[SecurityEvent]]:
    """Group normalized security events by source IP."""
    grouped_events: dict[
        str,
        list[SecurityEvent],
    ] = {}

    for event in events:
        grouped_events.setdefault(
            event.source_ip,
            [],
        ).append(event)

    return grouped_events


def create_normalized_event_windows(
    events: list[SecurityEvent],
    window_minutes: int = 5,
) -> list[list[SecurityEvent]]:
    """Group normalized events into fixed time windows."""
    parsed_events: list[
        tuple[
            datetime.datetime,
            SecurityEvent,
        ]
    ] = []

    unparsed_events: list[
        SecurityEvent
    ] = []

    for event in events:
        if event.timestamp is None:
            unparsed_events.append(
                event
            )
            continue

        try:
            parsed_timestamp = (
                datetime.datetime.fromisoformat(
                    event.timestamp
                )
            )

            # Cowrie timestamps include timezone data,
            # while Ubuntu syslog timestamps do not.
            # Convert aware values to naive UTC so all
            # timestamps can be sorted and correlated.
            if (
                parsed_timestamp.tzinfo
                is not None
            ):
                parsed_timestamp = (
                    parsed_timestamp.astimezone(
                        datetime.timezone.utc
                    ).replace(
                        tzinfo=None
                    )
                )

        except ValueError:
            unparsed_events.append(
                event
            )
            continue

        parsed_events.append(
            (
                parsed_timestamp,
                event,
            )
        )

    parsed_events.sort(
        key=lambda item: item[0]
    )

    windows: list[
        list[SecurityEvent]
    ] = []

    current_window: list[
        SecurityEvent
    ] = []

    window_start: (
        datetime.datetime | None
    ) = None

    for timestamp, event in parsed_events:
        if window_start is None:
            window_start = timestamp
            current_window = [event]
            continue

        time_difference = (
            timestamp - window_start
        )

        if time_difference <= datetime.timedelta(
            minutes=window_minutes
        ):
            current_window.append(
                event
            )
        else:
            windows.append(
                current_window
            )
            current_window = [event]
            window_start = timestamp

    if current_window:
        windows.append(
            current_window
        )

    for event in unparsed_events:
        windows.append(
            [event]
        )

    return windows


def count_normalized_events(
    events: list[SecurityEvent],
) -> tuple[int, int]:
    """Count normalized authentication failures and successes."""
    failed = sum(
        1
        for event in events
        if event.event_type
        == "authentication_failure"
    )

    successful = sum(
        1
        for event in events
        if event.event_type
        == "authentication_success"
    )

    return failed, successful


def normalized_events_to_raw_logs(
    events: list[SecurityEvent],
) -> list[str]:
    """Return original raw logs for alert evidence."""
    return [
        event.raw_log
        for event in events
    ]
