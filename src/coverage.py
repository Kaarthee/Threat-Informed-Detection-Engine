from dataclasses import dataclass

from src.attack import AttackKnowledgeBase


@dataclass
class DetectionCoverage:
    detection_id: str
    detection_name: str
    technique_id: str
    mapping_status: str
    coverage_status: str
    rationale: str


DETECTION_COVERAGE = [
    DetectionCoverage(
        detection_id="D001",
        detection_name="Repeated Authentication Failures",
        technique_id="T1110",
        mapping_status="supported",
        coverage_status="detected",
        rationale=(
            "Repeated authentication failures provide direct "
            "evidence of brute-force behaviour."
        ),
    ),
    DetectionCoverage(
        detection_id="D002",
        detection_name="Successful Authentication After Failures",
        technique_id="T1078",
        mapping_status="contextual",
        coverage_status="partial",
        rationale=(
            "A successful login after failures may indicate "
            "use of valid credentials, but legitimacy cannot "
            "be determined from authentication telemetry alone."
        ),
    ),
    DetectionCoverage(
        detection_id="D003",
        detection_name="Multi-Account Authentication Probing",
        technique_id="T1110.003",
        mapping_status="contextual",
        coverage_status="partial",
        rationale=(
            "Multiple targeted accounts resemble password "
            "spraying, but password reuse is not directly "
            "observed in the current detection logic."
        ),
    ),
    DetectionCoverage(
        detection_id="D004",
        detection_name="Privileged Account Targeting",
        technique_id="T1110",
        mapping_status="contextual",
        coverage_status="partial",
        rationale=(
            "Privileged account targeting strengthens brute-force "
            "context but is not sufficient alone to prove brute force."
        ),
    ),
    DetectionCoverage(
        detection_id="D005",
        detection_name="Persistent Authentication Probing",
        technique_id="T1110",
        mapping_status="contextual",
        coverage_status="partial",
        rationale=(
            "Repeated authentication activity across bounded "
            "time windows is consistent with brute-force probing."
        ),
    ),
    DetectionCoverage(
        detection_id="D006",
        detection_name="Post-Authentication Command Execution",
        technique_id="T1059",
        mapping_status="contextual",
        coverage_status="partial",
        rationale=(
            "Command execution is observed, but the exact "
            "command interpreter sub-technique is not identified."
        ),
    ),
    DetectionCoverage(
        detection_id="D007",
        detection_name="System Reconnaissance",
        technique_id="T1082",
        mapping_status="contextual",
        coverage_status="partial",
        rationale=(
            "The detector includes system-information commands, "
            "but some commands may map more precisely to other "
            "discovery techniques."
        ),
    ),
    DetectionCoverage(
        detection_id="D008",
        detection_name="External File or Tool Download",
        technique_id="T1105",
        mapping_status="contextual",
        coverage_status="partial",
        rationale=(
            "Observed transfer commands are consistent with "
            "Ingress Tool Transfer, but intent is not guaranteed."
        ),
    ),
    DetectionCoverage(
        detection_id="D009",
        detection_name="Privilege Escalation Attempt",
        technique_id="T1548",
        mapping_status="contextual",
        coverage_status="partial",
        rationale=(
            "Privilege-related commands are observed, but exact "
            "sub-technique attribution varies by command."
        ),
    ),
    DetectionCoverage(
        detection_id="D010",
        detection_name="SSH Authorized Key Persistence Attempt",
        technique_id="T1098.004",
        mapping_status="supported",
        coverage_status="detected",
        rationale=(
            "Modification of SSH authorized_keys directly "
            "supports SSH Authorized Keys persistence detection."
        ),
    ),
]


def build_attack_coverage(
    attack_kb: AttackKnowledgeBase,
) -> list[dict]:
    """Build ATT&CK-enriched detection coverage records."""

    coverage_records = []

    for entry in DETECTION_COVERAGE:
        metadata = attack_kb.get_technique(
            entry.technique_id
        )

        coverage_records.append(
            {
                "detection_id": entry.detection_id,
                "detection_name": entry.detection_name,
                "technique_id": entry.technique_id,
                "technique_name": (
                    metadata["name"]
                    if metadata
                    else None
                ),
                "tactics": (
                    metadata["tactics"]
                    if metadata
                    else []
                ),
                "platforms": (
                    metadata["platforms"]
                    if metadata
                    else []
                ),
                "mapping_status": entry.mapping_status,
                "coverage_status": entry.coverage_status,
                "rationale": entry.rationale,
                "metadata_found": (
                    metadata is not None
                ),
            }
        )

    return coverage_records


def summarize_coverage(
    coverage_records: list[dict],
) -> dict:
    """Return simple coverage counts."""

    total = len(
        coverage_records
    )

    detected = sum(
        1
        for record in coverage_records
        if record["coverage_status"] == "detected"
    )

    partial = sum(
        1
        for record in coverage_records
        if record["coverage_status"] == "partial"
    )

    unsupported = sum(
        1
        for record in coverage_records
        if record["coverage_status"] == "unsupported"
    )

    return {
        "total_detections": total,
        "detected": detected,
        "partial": partial,
        "unsupported": unsupported,
    }
