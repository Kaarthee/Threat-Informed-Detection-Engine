import json
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(
        0,
        str(PROJECT_ROOT),
    )


from src.attack import AttackKnowledgeBase
from src.coverage import (
    build_attack_coverage,
    summarize_coverage,
)


OUTPUT_FILE = Path(
    "alerts/attack-coverage.json"
)


def main() -> None:
    attack_kb = AttackKnowledgeBase()

    coverage = build_attack_coverage(
        attack_kb
    )

    summary = summarize_coverage(
        coverage
    )

    output = {
        "summary": summary,
        "coverage": coverage,
    }

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    OUTPUT_FILE.write_text(
        json.dumps(
            output,
            indent=4,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    print(
        f"ATT&CK coverage written to {OUTPUT_FILE}"
    )

    print(
        f"Total detections: "
        f"{summary['total_detections']}"
    )

    print(
        f"Detected: "
        f"{summary['detected']}"
    )

    print(
        f"Partial: "
        f"{summary['partial']}"
    )

    print(
        f"Unsupported: "
        f"{summary['unsupported']}"
    )


if __name__ == "__main__":
    main()
