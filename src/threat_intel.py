import datetime
import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path


class ThreatIntelError(Exception):
    """Raised when threat-intelligence data cannot be processed."""


@dataclass
class ThreatIntelIndicator:
    """Provider-independent threat-intelligence indicator."""

    value: str
    type: str
    source: str
    confidence: int | None = None
    source_reliability: str | None = None
    first_seen: str | None = None
    last_seen: str | None = None
    expires_at: str | None = None
    active: bool = True
    tags: list[str] = field(default_factory=list)
    external_id: str | None = None
    stix_id: str | None = None
    provenance: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Convert the indicator to a serializable dictionary."""
        return asdict(self)

    def is_current(
        self,
        reference_time: datetime.datetime | None = None,
    ) -> bool:
        """
        Return True when the indicator was valid at the reference time.

        Validation considers:
        - active/revoked state
        - first_seen / STIX valid_from
        - expires_at / STIX valid_until
        """

        if not self.active:
            return False

        current = (
            reference_time
            or datetime.datetime.now(
                datetime.timezone.utc
            )
        )

        if current.tzinfo is None:
            current = current.replace(
                tzinfo=datetime.timezone.utc
            )

        first_seen = parse_timestamp(
            self.first_seen
        )

        if (
            first_seen is not None
            and current < first_seen
        ):
            return False

        expiry = parse_timestamp(
            self.expires_at
        )

        if (
            expiry is not None
            and current > expiry
        ):
            return False

        if (
            self.expires_at
            and expiry is None
        ):
            return False

        return True


def parse_timestamp(
    timestamp: str | None,
) -> datetime.datetime | None:
    """Parse ISO timestamps including STIX timestamps ending in Z."""

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

    if parsed.tzinfo is None:
        parsed = parsed.replace(
            tzinfo=datetime.timezone.utc
        )

    return parsed


def normalize_indicator_type(
    indicator_type: str,
) -> str:
    """Normalize provider-specific indicator type names."""

    mapping = {
        "ipv4": "ipv4",
        "ipv4-addr": "ipv4",
        "ipv6": "ipv6",
        "ipv6-addr": "ipv6",
        "domain": "domain",
        "domain-name": "domain",
        "url": "url",
        "sha256": "sha256",
        "sha-256": "sha256",
    }

    normalized = indicator_type.strip().lower()

    return mapping.get(
        normalized,
        normalized,
    )


class LocalJSONIntelProvider:
    """Load indicators from the project's local IOC JSON file."""

    def __init__(
        self,
        indicator_file: Path,
    ):
        self.indicator_file = indicator_file

    def load(self) -> list[ThreatIntelIndicator]:
        """Load local JSON indicators."""

        try:
            with self.indicator_file.open(
                "r",
                encoding="utf-8",
            ) as file:
                data = json.load(file)

        except FileNotFoundError as error:
            raise ThreatIntelError(
                f"Threat intelligence file not found: "
                f"{self.indicator_file}"
            ) from error

        except json.JSONDecodeError as error:
            raise ThreatIntelError(
                f"Invalid threat intelligence JSON: "
                f"{self.indicator_file}"
            ) from error

        indicators = data.get("indicators")

        if not isinstance(
            indicators,
            list,
        ):
            raise ThreatIntelError(
                "'indicators' must be a list"
            )

        results: list[
            ThreatIntelIndicator
        ] = []

        for record in indicators:
            if not isinstance(
                record,
                dict,
            ):
                continue

            value = record.get("value")
            indicator_type = record.get(
                "type"
            )

            if (
                not isinstance(
                    value,
                    str,
                )
                or not isinstance(
                    indicator_type,
                    str,
                )
            ):
                continue

            tags = record.get(
                "tags",
                [],
            )

            if not isinstance(
                tags,
                list,
            ):
                tags = []

            results.append(
                ThreatIntelIndicator(
                    value=value,
                    type=normalize_indicator_type(
                        indicator_type
                    ),
                    source=record.get(
                        "source",
                        "Local JSON",
                    ),
                    confidence=record.get(
                        "confidence"
                    ),
                    source_reliability=record.get(
                        "source_reliability"
                    ),
                    first_seen=record.get(
                        "first_seen"
                    ),
                    last_seen=record.get(
                        "last_seen"
                    ),
                    expires_at=record.get(
                        "expires_at"
                    ),
                    active=bool(
                        record.get(
                            "active",
                            True,
                        )
                    ),
                    tags=[
                        str(tag)
                        for tag in tags
                    ],
                    external_id=record.get(
                        "external_id"
                    ),
                    stix_id=record.get(
                        "stix_id"
                    ),
                    provenance={
                        "provider": "local_json",
                        "file": str(
                            self.indicator_file
                        ),
                    },
                )
            )

        return results


STIX_SIMPLE_PATTERN = re.compile(
    r"^\[\s*"
    r"(?P<object_type>"
    r"ipv4-addr|ipv6-addr|domain-name|url"
    r")"
    r":value\s*=\s*"
    r"'(?P<value>[^']+)'"
    r"\s*\]$",
    re.IGNORECASE,
)

STIX_SHA256_PATTERN = re.compile(
    r"^\[\s*file:hashes\."
    r"(?:'SHA-256'|\"SHA-256\"|SHA-256)"
    r"\s*=\s*"
    r"'(?P<value>[A-Fa-f0-9]{64})'"
    r"\s*\]$",
    re.IGNORECASE,
)


def parse_stix_indicator_pattern(
    pattern: str,
) -> tuple[str, str] | None:
    """
    Parse simple STIX indicator patterns supported by the engine.

    Supported examples:
        [ipv4-addr:value = '1.2.3.4']
        [domain-name:value = 'example.com']
        [url:value = 'https://example.com']
        [file:hashes.'SHA-256' = '<hash>']
    """

    simple_match = (
        STIX_SIMPLE_PATTERN.match(
            pattern
        )
    )

    if simple_match:
        return (
            normalize_indicator_type(
                simple_match.group(
                    "object_type"
                )
            ),
            simple_match.group(
                "value"
            ),
        )

    hash_match = (
        STIX_SHA256_PATTERN.match(
            pattern
        )
    )

    if hash_match:
        return (
            "sha256",
            hash_match.group(
                "value"
            ).lower(),
        )

    return None


class STIXIntelProvider:
    """Load supported indicators from a STIX 2.x bundle."""

    def __init__(
        self,
        stix_file: Path,
        source_name: str = "STIX Bundle",
    ):
        self.stix_file = stix_file
        self.source_name = source_name

    def load(self) -> list[ThreatIntelIndicator]:
        """Load supported STIX Indicator objects."""

        try:
            with self.stix_file.open(
                "r",
                encoding="utf-8",
            ) as file:
                bundle = json.load(file)

        except FileNotFoundError as error:
            raise ThreatIntelError(
                f"STIX file not found: "
                f"{self.stix_file}"
            ) from error

        except json.JSONDecodeError as error:
            raise ThreatIntelError(
                f"Invalid STIX JSON: "
                f"{self.stix_file}"
            ) from error

        objects = bundle.get("objects")

        if not isinstance(
            objects,
            list,
        ):
            raise ThreatIntelError(
                "STIX bundle missing 'objects' list"
            )

        indicators: list[
            ThreatIntelIndicator
        ] = []

        for stix_object in objects:
            if not isinstance(
                stix_object,
                dict,
            ):
                continue

            if stix_object.get(
                "type"
            ) != "indicator":
                continue

            pattern = stix_object.get(
                "pattern"
            )

            if not isinstance(
                pattern,
                str,
            ):
                continue

            parsed = (
                parse_stix_indicator_pattern(
                    pattern
                )
            )

            if parsed is None:
                continue

            (
                indicator_type,
                value,
            ) = parsed

            labels = stix_object.get(
                "labels",
                [],
            )

            if not isinstance(
                labels,
                list,
            ):
                labels = []

            confidence = stix_object.get(
                "confidence"
            )

            if not isinstance(
                confidence,
                int,
            ):
                confidence = None

            revoked = bool(
                stix_object.get(
                    "revoked",
                    False,
                )
            )

            valid_from = stix_object.get(
                "valid_from"
            )

            valid_until = stix_object.get(
                "valid_until"
            )

            indicators.append(
                ThreatIntelIndicator(
                    value=value,
                    type=indicator_type,
                    source=self.source_name,
                    confidence=confidence,
                    source_reliability=None,
                    first_seen=valid_from,
                    last_seen=stix_object.get(
                        "modified"
                    ),
                    expires_at=valid_until,
                    active=not revoked,
                    tags=[
                        str(label)
                        for label in labels
                    ],
                    external_id=None,
                    stix_id=stix_object.get(
                        "id"
                    ),
                    provenance={
                        "provider": "stix",
                        "file": str(
                            self.stix_file
                        ),
                        "created_by_ref": (
                            stix_object.get(
                                "created_by_ref"
                            )
                        ),
                        "pattern": pattern,
                        "pattern_type": (
                            stix_object.get(
                                "pattern_type"
                            )
                        ),
                    },
                )
            )

        return indicators


def reliability_rank(
    reliability: str | None,
) -> int:
    """Return a sortable reliability score."""

    ranks = {
        "A": 5,
        "B": 4,
        "C": 3,
        "D": 2,
        "E": 1,
        "F": 0,
    }

    if not reliability:
        return -1

    return ranks.get(
        reliability.upper(),
        -1,
    )


def indicator_sort_key(
    indicator: ThreatIntelIndicator,
) -> tuple:
    """Rank indicators when multiple sources contain the same value."""

    confidence = (
        indicator.confidence
        if indicator.confidence
        is not None
        else -1
    )

    last_seen = (
        parse_timestamp(
            indicator.last_seen
        )
        or datetime.datetime.min.replace(
            tzinfo=datetime.timezone.utc
        )
    )

    return (
        confidence,
        reliability_rank(
            indicator.source_reliability
        ),
        last_seen,
    )


class ThreatIntelStore:
    """Aggregate indicators from multiple intelligence providers."""

    def __init__(
        self,
        providers: list | None = None,
    ):
        self.providers = providers or []

        self.indicators: list[
            ThreatIntelIndicator
        ] = []

        self.index: dict[
            tuple[str, str],
            list[ThreatIntelIndicator],
        ] = {}

    def load(self) -> None:
        """Load and index indicators from all configured providers."""

        self.indicators = []
        self.index = {}

        for provider in self.providers:
            provider_indicators = (
                provider.load()
            )

            for indicator in provider_indicators:
                self.indicators.append(
                    indicator
                )

                key = (
                    indicator.type,
                    indicator.value,
                )

                self.index.setdefault(
                    key,
                    [],
                ).append(
                    indicator
                )

    def lookup(
        self,
        value: str,
        indicator_type: str,
        active_only: bool = True,
        reference_time: datetime.datetime | None = None,
    ) -> list[ThreatIntelIndicator]:
        """
        Return matching indicators ranked by confidence.

        When reference_time is supplied, lifecycle validation is
        evaluated against the incident time instead of current time.
        """

        normalized_type = (
            normalize_indicator_type(
                indicator_type
            )
        )

        matches = list(
            self.index.get(
                (
                    normalized_type,
                    value,
                ),
                [],
            )
        )

        if active_only:
            matches = [
                indicator
                for indicator in matches
                if indicator.is_current(
                    reference_time=reference_time
                )
            ]

        return sorted(
            matches,
            key=indicator_sort_key,
            reverse=True,
        )

    def lookup_ip(
        self,
        ip: str,
        active_only: bool = True,
        reference_time: datetime.datetime | None = None,
    ) -> list[ThreatIntelIndicator]:
        """Lookup an IPv4 indicator."""

        return self.lookup(
            value=ip,
            indicator_type="ipv4",
            active_only=active_only,
            reference_time=reference_time,
        )

    def best_ip_match(
        self,
        ip: str,
        reference_time: datetime.datetime | None = None,
    ) -> ThreatIntelIndicator | None:
        """Return the highest-ranked active IPv4 match."""

        matches = self.lookup_ip(
            ip,
            reference_time=reference_time,
        )

        if not matches:
            return None

        return matches[0]

    def get_source_matches(
        self,
        value: str,
        indicator_type: str,
        reference_time: datetime.datetime | None = None,
    ) -> list[dict]:
        """Return all matching source records as dictionaries."""

        return [
            indicator.to_dict()
            for indicator in self.lookup(
                value,
                indicator_type,
                reference_time=reference_time,
            )
        ]
