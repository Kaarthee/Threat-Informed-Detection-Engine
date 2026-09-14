from dataclasses import dataclass, field


@dataclass
class DetectedBehavior:
    detection_id: str
    name: str
    behavior: str
    confidence: str
    evidence: list[str] = field(default_factory=list)
    attack_technique_id: str | None = None
    attack_mapping_status: str = "unmapped"


def detect_repeated_authentication_failures(
    failed_count: int,
    threshold: int = 5,
) -> DetectedBehavior | None:
    """
    D001
    Detect repeated authentication failures.
    """

    if failed_count < threshold:
        return None

    return DetectedBehavior(
        detection_id="D001",
        name="Repeated Authentication Failures",
        behavior="repeated_authentication_failures",
        confidence="high",
        evidence=[
            f"{failed_count} failed authentication attempts observed"
        ],
        attack_technique_id="T1110",
        attack_mapping_status="supported",
    )


def detect_success_after_failures(
    failed_count: int,
    successful_count: int,
) -> DetectedBehavior | None:
    """
    D002
    Detect successful authentication following failures.
    """

    if failed_count <= 0 or successful_count <= 0:
        return None

    return DetectedBehavior(
        detection_id="D002",
        name="Successful Authentication After Failures",
        behavior="successful_authentication_after_failures",
        confidence="medium",
        evidence=[
            f"{failed_count} failed authentication attempts observed",
            f"{successful_count} successful authentication attempts observed",
        ],
        attack_technique_id="T1078",
        attack_mapping_status="contextual",
    )


def detect_multi_account_authentication_probing(
    usernames: list[str],
    threshold: int = 3,
) -> DetectedBehavior | None:
    """
    D003
    Detect one incident targeting multiple distinct accounts.
    """

    unique_usernames = sorted(
        {
            username
            for username in usernames
            if username
        }
    )

    if len(unique_usernames) < threshold:
        return None

    return DetectedBehavior(
        detection_id="D003",
        name="Multi-Account Authentication Probing",
        behavior="multi_account_authentication_probing",
        confidence="medium",
        evidence=[
            (
                f"{len(unique_usernames)} distinct accounts targeted: "
                + ", ".join(unique_usernames)
            )
        ],
        attack_technique_id="T1110.003",
        attack_mapping_status="contextual",
    )


def detect_privileged_account_targeting(
    usernames: list[str],
    privileged_accounts: set[str] | None = None,
) -> DetectedBehavior | None:
    """
    D004
    Detect authentication activity targeting privileged accounts.
    """

    if privileged_accounts is None:
        privileged_accounts = {
            "root",
            "admin",
            "administrator",
        }

    targeted = sorted(
        {
            username.lower()
            for username in usernames
            if username
            and username.lower() in privileged_accounts
        }
    )

    if not targeted:
        return None

    return DetectedBehavior(
        detection_id="D004",
        name="Privileged Account Targeting",
        behavior="privileged_account_targeting",
        confidence="medium",
        evidence=[
            "Privileged accounts targeted: "
            + ", ".join(targeted)
        ],
        attack_technique_id="T1110",
        attack_mapping_status="contextual",
    )


def detect_persistent_authentication_probing(
    incident_window_count: int,
    failed_count: int,
    activity_span_minutes: float | None = None,
    minimum_windows: int = 2,
    maximum_span_minutes: int = 60,
) -> DetectedBehavior | None:
    """
    D005
    Detect repeated authentication probing across multiple
    correlation windows within a meaningful time period.
    """

    if incident_window_count < minimum_windows:
        return None

    if failed_count <= 0:
        return None

    if activity_span_minutes is None:
        return None

    if activity_span_minutes > maximum_span_minutes:
        return None

    return DetectedBehavior(
        detection_id="D005",
        name="Persistent Authentication Probing",
        behavior="persistent_authentication_probing",
        confidence="medium",
        evidence=[
            (
                "Authentication failures observed across "
                f"{incident_window_count} incident windows "
                f"within {activity_span_minutes:.1f} minutes"
            ),
            f"{failed_count} failed authentication attempts observed",
        ],
        attack_technique_id="T1110",
        attack_mapping_status="contextual",
    )

def detect_post_authentication_command_execution(
    successful_count: int,
    commands: list[str],
) -> DetectedBehavior | None:
    """
    D006
    Detect command execution following successful authentication.
    """

    clean_commands = [
        command.strip()
        for command in commands
        if command and command.strip()
    ]

    if successful_count <= 0:
        return None

    if not clean_commands:
        return None

    return DetectedBehavior(
        detection_id="D006",
        name="Post-Authentication Command Execution",
        behavior="post_authentication_command_execution",
        confidence="high",
        evidence=[
            f"{successful_count} successful authentication attempts observed",
            "Commands observed: " + ", ".join(clean_commands),
        ],
        attack_technique_id="T1059",
        attack_mapping_status="contextual",
    )


def detect_system_reconnaissance(
    commands: list[str],
) -> DetectedBehavior | None:
    """
    D007
    Detect common host/system reconnaissance commands.
    """

    reconnaissance_patterns = (
        "uname",
        "hostname",
        "whoami",
        "id",
        "ip addr",
        "ifconfig",
        "cat /etc/os-release",
        "lsb_release",
    )

    matched_commands = []

    for command in commands:
        if not command:
            continue

        normalized = command.strip().lower()

        if any(
            normalized.startswith(pattern)
            for pattern in reconnaissance_patterns
        ):
            matched_commands.append(command.strip())

    if not matched_commands:
        return None

    return DetectedBehavior(
        detection_id="D007",
        name="System Reconnaissance",
        behavior="system_reconnaissance",
        confidence="high",
        evidence=[
            "Reconnaissance commands observed: "
            + ", ".join(matched_commands)
        ],
        attack_technique_id="T1082",
        attack_mapping_status="contextual",
    )


def detect_external_file_download(
    commands: list[str],
) -> DetectedBehavior | None:
    """
    D008
    Detect commands commonly used to retrieve files or tools.
    """

    download_patterns = (
        "wget ",
        "curl ",
        "scp ",
        "ftp ",
        "tftp ",
    )

    matched_commands = []

    for command in commands:
        if not command:
            continue

        normalized = command.strip().lower()

        if any(
            normalized.startswith(pattern)
            for pattern in download_patterns
        ):
            matched_commands.append(command.strip())

    if not matched_commands:
        return None

    return DetectedBehavior(
        detection_id="D008",
        name="External File or Tool Download",
        behavior="external_file_download",
        confidence="medium",
        evidence=[
            "File-transfer commands observed: "
            + ", ".join(matched_commands)
        ],
        attack_technique_id="T1105",
        attack_mapping_status="contextual",
    )


def detect_privilege_escalation_attempt(
    commands: list[str],
) -> DetectedBehavior | None:
    """
    D009
    Detect commands associated with attempts to obtain
    elevated privileges.
    """

    privilege_patterns = (
        "sudo ",
        "sudo -",
        "su ",
        "su -",
        "pkexec ",
    )

    matched_commands = []

    for command in commands:
        if not command:
            continue

        normalized = command.strip().lower()

        if any(
            normalized.startswith(pattern)
            for pattern in privilege_patterns
        ):
            matched_commands.append(command.strip())

    if not matched_commands:
        return None

    return DetectedBehavior(
        detection_id="D009",
        name="Privilege Escalation Attempt",
        behavior="privilege_escalation_attempt",
        confidence="medium",
        evidence=[
            "Privilege-related commands observed: "
            + ", ".join(matched_commands)
        ],
        attack_technique_id="T1548",
        attack_mapping_status="contextual",
    )


def detect_ssh_authorized_key_persistence(
    commands: list[str],
) -> DetectedBehavior | None:
    """
    D010
    Detect attempts to modify SSH authorized_keys,
    potentially establishing persistent SSH access.
    """

    matched_commands = []

    for command in commands:
        if not command:
            continue

        normalized = command.strip().lower()

        if "authorized_keys" in normalized:
            matched_commands.append(command.strip())

    if not matched_commands:
        return None

    return DetectedBehavior(
        detection_id="D010",
        name="SSH Authorized Key Persistence Attempt",
        behavior="ssh_authorized_key_persistence",
        confidence="high",
        evidence=[
            "SSH authorized_keys modification observed: "
            + ", ".join(matched_commands)
        ],
        attack_technique_id="T1098.004",
        attack_mapping_status="supported",
    )
