import json
from pathlib import Path


DEFAULT_ATTACK_FILE = Path(
    "data/attack/enterprise-attack.json"
)


class AttackDataError(Exception):
    """Raised when ATT&CK data cannot be loaded correctly."""


def load_attack_bundle(
    attack_file: Path = DEFAULT_ATTACK_FILE,
) -> dict:
    """Load the local MITRE ATT&CK STIX bundle."""

    try:
        with attack_file.open(
            "r",
            encoding="utf-8",
        ) as file:
            data = json.load(file)

    except FileNotFoundError as error:
        raise AttackDataError(
            f"ATT&CK data file not found: {attack_file}"
        ) from error

    except json.JSONDecodeError as error:
        raise AttackDataError(
            f"Invalid ATT&CK JSON: {attack_file}"
        ) from error

    if not isinstance(data, dict):
        raise AttackDataError(
            "ATT&CK bundle must be a JSON object"
        )

    objects = data.get(
        "objects"
    )

    if not isinstance(objects, list):
        raise AttackDataError(
            "ATT&CK bundle missing 'objects' list"
        )

    return data


def get_external_attack_id(
    attack_object: dict,
) -> str | None:
    """Extract the MITRE ATT&CK technique ID."""

    references = attack_object.get(
        "external_references",
        [],
    )

    for reference in references:
        if not isinstance(
            reference,
            dict,
        ):
            continue

        if reference.get(
            "source_name"
        ) != "mitre-attack":
            continue

        external_id = reference.get(
            "external_id"
        )

        if isinstance(
            external_id,
            str,
        ):
            return external_id

    return None


def build_technique_index(
    attack_bundle: dict,
) -> dict[str, dict]:
    """
    Build a technique index keyed by ATT&CK ID.

    Example:
        T1110 -> attack-pattern object
        T1110.003 -> attack-pattern object
    """

    index: dict[str, dict] = {}

    for attack_object in attack_bundle.get(
        "objects",
        [],
    ):
        if not isinstance(
            attack_object,
            dict,
        ):
            continue

        if attack_object.get(
            "type"
        ) != "attack-pattern":
            continue

        attack_id = get_external_attack_id(
            attack_object
        )

        if not attack_id:
            continue

        index[attack_id] = (
            attack_object
        )

    return index


def extract_tactics(
    attack_object: dict,
) -> list[str]:
    """Return ATT&CK tactic names from kill-chain phases."""

    tactics = {
        phase.get(
            "phase_name"
        )
        for phase in attack_object.get(
            "kill_chain_phases",
            [],
        )
        if (
            isinstance(
                phase,
                dict,
            )
            and phase.get(
                "kill_chain_name"
            ) == "mitre-attack"
            and phase.get(
                "phase_name"
            )
        )
    }

    return sorted(
        tactics
    )


def extract_platforms(
    attack_object: dict,
) -> list[str]:
    """Return supported ATT&CK platforms."""

    platforms = attack_object.get(
        "x_mitre_platforms",
        [],
    )

    if not isinstance(
        platforms,
        list,
    ):
        return []

    return sorted(
        {
            platform
            for platform in platforms
            if isinstance(
                platform,
                str,
            )
        }
    )


def technique_to_metadata(
    attack_object: dict,
) -> dict:
    """Convert a STIX attack-pattern into compact metadata."""

    attack_id = get_external_attack_id(
        attack_object
    )

    return {
        "technique_id": attack_id,
        "name": attack_object.get(
            "name"
        ),
        "description": attack_object.get(
            "description"
        ),
        "tactics": extract_tactics(
            attack_object
        ),
        "platforms": extract_platforms(
            attack_object
        ),
        "is_subtechnique": bool(
            attack_object.get(
                "x_mitre_is_subtechnique",
                False,
            )
        ),
        "deprecated": bool(
            attack_object.get(
                "x_mitre_deprecated",
                False,
            )
        ),
        "revoked": bool(
            attack_object.get(
                "revoked",
                False,
            )
        ),
        "created": attack_object.get(
            "created"
        ),
        "modified": attack_object.get(
            "modified"
        ),
        "stix_id": attack_object.get(
            "id"
        ),
        "source": "MITRE ATT&CK",
    }


class AttackKnowledgeBase:
    """Local MITRE ATT&CK technique lookup service."""

    def __init__(
        self,
        attack_file: Path = DEFAULT_ATTACK_FILE,
    ):
        self.attack_file = (
            attack_file
        )

        self.bundle = load_attack_bundle(
            attack_file
        )

        self.techniques = (
            build_technique_index(
                self.bundle
            )
        )

    def get_technique(
        self,
        technique_id: str,
    ) -> dict | None:
        """Return metadata for one ATT&CK technique."""

        attack_object = (
            self.techniques.get(
                technique_id
            )
        )

        if attack_object is None:
            return None

        return technique_to_metadata(
            attack_object
        )

    def has_technique(
        self,
        technique_id: str,
    ) -> bool:
        """Return True if the technique exists."""

        return (
            technique_id
            in self.techniques
        )

    def get_active_techniques(
        self,
    ) -> dict[str, dict]:
        """Return all non-revoked, non-deprecated techniques."""

        active: dict[str, dict] = {}

        for (
            technique_id,
            attack_object,
        ) in self.techniques.items():
            metadata = (
                technique_to_metadata(
                    attack_object
                )
            )

            if (
                metadata["deprecated"]
                or metadata["revoked"]
            ):
                continue

            active[
                technique_id
            ] = metadata

        return active

    def enrich_behavior(
        self,
        behavior: dict,
    ) -> dict:
        """
        Enrich one detected behavior with official
        ATT&CK metadata.
        """

        enriched = dict(
            behavior
        )

        attack = behavior.get(
            "attack"
        )

        if not isinstance(
            attack,
            dict,
        ):
            return enriched

        technique_id = attack.get(
            "technique_id"
        )

        if not technique_id:
            return enriched

        metadata = self.get_technique(
            technique_id
        )

        if metadata is None:
            enriched_attack = dict(
                attack
            )

            enriched_attack[
                "metadata_found"
            ] = False

            enriched[
                "attack"
            ] = enriched_attack

            return enriched

        enriched_attack = dict(
            attack
        )

        enriched_attack.update(
            {
                "metadata_found": True,
                "name": metadata[
                    "name"
                ],
                "tactics": metadata[
                    "tactics"
                ],
                "platforms": metadata[
                    "platforms"
                ],
                "is_subtechnique": metadata[
                    "is_subtechnique"
                ],
                "deprecated": metadata[
                    "deprecated"
                ],
                "revoked": metadata[
                    "revoked"
                ],
                "modified": metadata[
                    "modified"
                ],
                "source": metadata[
                    "source"
                ],
            }
        )

        enriched[
            "attack"
        ] = enriched_attack

        return enriched


def load_attack_knowledge_base(
    attack_file: Path = DEFAULT_ATTACK_FILE,
) -> AttackKnowledgeBase | None:
    """
    Load ATT&CK metadata safely.

    Returns None if the local cache is unavailable or invalid.
    """

    try:
        return AttackKnowledgeBase(
            attack_file
        )

    except AttackDataError:
        return None
