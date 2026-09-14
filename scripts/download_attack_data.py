from pathlib import Path
from urllib.request import urlopen


ATTACK_URL = (
    "https://raw.githubusercontent.com/"
    "mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack.json"
)

OUTPUT_FILE = Path(
    "data/attack/enterprise-attack.json"
)


def main() -> None:
    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    print(
        "Downloading MITRE ATT&CK Enterprise data..."
    )

    with urlopen(
        ATTACK_URL,
        timeout=60,
    ) as response:
        data = response.read()

    OUTPUT_FILE.write_bytes(
        data
    )

    size_mb = (
        OUTPUT_FILE.stat().st_size
        / 1024
        / 1024
    )

    print(
        f"Saved: {OUTPUT_FILE}"
    )

    print(
        f"Size: {size_mb:.2f} MB"
    )


if __name__ == "__main__":
    main()
