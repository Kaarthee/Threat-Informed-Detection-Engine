import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(
        0,
        str(PROJECT_ROOT),
    )


from src.attack import AttackKnowledgeBase
from src.coverage import build_attack_coverage


OUTPUT_FILE = Path(
    "docs/attack-coverage.md"
)


def main() -> None:
    attack_kb = AttackKnowledgeBase()

    coverage = build_attack_coverage(
        attack_kb
    )

    lines = [
        "# MITRE ATT&CK Detection Coverage",
        "",
        (
            "This matrix documents the ATT&CK techniques "
            "currently represented by the engine's behavioural "
            "detections."
        ),
        "",
        (
            "Coverage is intentionally conservative. "
            "`Detected` indicates stronger telemetry support, "
            "while `Partial` indicates contextual or incomplete "
            "coverage."
        ),
        "",
        (
            "| Detection | Behaviour | ATT&CK | "
            "Technique | Mapping | Coverage |"
        ),
        "|---|---|---|---|---|---|",
    ]

    for record in coverage:
        lines.append(
            "| "
            f"{record['detection_id']} | "
            f"{record['detection_name']} | "
            f"{record['technique_id']} | "
            f"{record['technique_name']} | "
            f"{record['mapping_status'].title()} | "
            f"{record['coverage_status'].title()} |"
        )

    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            (
                "- **Detected**: telemetry and detection logic "
                "provide comparatively direct support for the "
                "ATT&CK mapping."
            ),
            (
                "- **Partial**: observed behaviour is consistent "
                "with the ATT&CK technique, but available telemetry "
                "does not justify claiming complete coverage."
            ),
            (
                "- **Unsupported**: the engine currently lacks "
                "sufficient telemetry or detection logic."
            ),
            "",
            (
                "ATT&CK enrichment is loaded from the local "
                "MITRE Enterprise ATT&CK STIX dataset."
            ),
        ]
    )

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    OUTPUT_FILE.write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8",
    )

    print(
        f"ATT&CK Markdown coverage written to "
        f"{OUTPUT_FILE}"
    )


if __name__ == "__main__":
    main()
