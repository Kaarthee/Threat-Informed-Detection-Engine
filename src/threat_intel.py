import datetime
import ipaddress
import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
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



def stix_object_to_indicator(
    stix_object: dict,
    source_name: str,
    provenance: dict,
) -> ThreatIntelIndicator | None:
    """Convert one supported STIX Indicator object."""

    if not isinstance(
        stix_object,
        dict,
    ):
        return None

    if stix_object.get(
        "type"
    ) != "indicator":
        return None

    pattern = stix_object.get(
        "pattern"
    )

    if not isinstance(
        pattern,
        str,
    ):
        return None

    parsed = (
        parse_stix_indicator_pattern(
            pattern
        )
    )

    if parsed is None:
        return None

    indicator_type, value = parsed

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

    return ThreatIntelIndicator(
        value=value,
        type=indicator_type,
        source=source_name,
        confidence=confidence,
        source_reliability=None,
        first_seen=stix_object.get(
            "valid_from"
        ),
        last_seen=stix_object.get(
            "modified"
        ),
        expires_at=stix_object.get(
            "valid_until"
        ),
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
            **provenance,
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
            indicator = stix_object_to_indicator(
                stix_object=stix_object,
                source_name=self.source_name,
                provenance={
                    "provider": "stix",
                    "file": str(
                        self.stix_file
                    ),
                },
            )

            if indicator is not None:
                indicators.append(
                    indicator
                )

        return indicators



class TAXIIIntelProvider:
    """
    Retrieve STIX objects from a TAXII 2.x collection endpoint.

    The provider expects a URL that returns a TAXII envelope
    containing an "objects" list of STIX objects.
    """

    def __init__(
        self,
        collection_objects_url: str,
        source_name: str = "TAXII Feed",
        username: str | None = None,
        password: str | None = None,
        timeout_seconds: int = 10,
    ):
        self.collection_objects_url = (
            collection_objects_url
        )
        self.source_name = source_name
        self.username = username
        self.password = password
        self.timeout_seconds = timeout_seconds

    def _build_request(
        self,
        url: str,
    ) -> urllib.request.Request:
        """Build a TAXII request with STIX/TAXII media types."""

        headers = {
            "Accept": (
                "application/taxii+json;version=2.1"
            ),
        }

        request = urllib.request.Request(
            url=url,
            headers=headers,
            method="GET",
        )

        if (
            self.username is not None
            and self.password is not None
        ):
            credentials = (
                f"{self.username}:{self.password}"
            ).encode(
                "utf-8"
            )

            import base64

            encoded_credentials = (
                base64.b64encode(
                    credentials
                ).decode(
                    "ascii"
                )
            )

            request.add_header(
                "Authorization",
                f"Basic {encoded_credentials}",
            )

        return request

    def _fetch_json(
        self,
        url: str,
    ) -> dict:
        """Fetch and decode a TAXII JSON response."""

        request = self._build_request(
            url
        )

        try:
            with urllib.request.urlopen(
                request,
                timeout=self.timeout_seconds,
            ) as response:
                payload = response.read()

        except (
            urllib.error.HTTPError,
            urllib.error.URLError,
            TimeoutError,
        ) as error:
            raise ThreatIntelError(
                "TAXII request failed for "
                f"{url}: {error}"
            ) from error

        try:
            data = json.loads(
                payload.decode(
                    "utf-8"
                )
            )

        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
        ) as error:
            raise ThreatIntelError(
                "Invalid TAXII JSON response "
                f"from {url}"
            ) from error

        if not isinstance(
            data,
            dict,
        ):
            raise ThreatIntelError(
                "TAXII response must be a JSON object"
            )

        return data

    def load(self) -> list[ThreatIntelIndicator]:
        """
        Fetch supported STIX Indicator objects.

        TAXII pagination is followed when a response includes
        more=true and a next token.
        """

        indicators: list[
            ThreatIntelIndicator
        ] = []

        next_url = (
            self.collection_objects_url
        )

        while next_url:
            envelope = self._fetch_json(
                next_url
            )

            objects = envelope.get(
                "objects",
                [],
            )

            if not isinstance(
                objects,
                list,
            ):
                raise ThreatIntelError(
                    "TAXII response 'objects' must be a list"
                )

            for stix_object in objects:
                indicator = (
                    stix_object_to_indicator(
                        stix_object=stix_object,
                        source_name=self.source_name,
                        provenance={
                            "provider": "taxii",
                            "url": next_url,
                        },
                    )
                )

                if indicator is not None:
                    indicators.append(
                        indicator
                    )

            more = bool(
                envelope.get(
                    "more",
                    False,
                )
            )

            next_token = envelope.get(
                "next"
            )

            if (
                more
                and isinstance(
                    next_token,
                    str,
                )
                and next_token
            ):
                parsed_url = (
                    urllib.parse.urlsplit(
                        self.collection_objects_url
                    )
                )

                query = dict(
                    urllib.parse.parse_qsl(
                        parsed_url.query,
                        keep_blank_values=True,
                    )
                )

                query["next"] = (
                    next_token
                )

                next_url = (
                    urllib.parse.urlunsplit(
                        (
                            parsed_url.scheme,
                            parsed_url.netloc,
                            parsed_url.path,
                            urllib.parse.urlencode(
                                query
                            ),
                            parsed_url.fragment,
                        )
                    )
                )

            else:
                next_url = None

        return indicators




def unix_timestamp_to_iso(
    value,
) -> str | None:
    """Convert a Unix timestamp to an ISO-8601 UTC timestamp."""

    if value in (
        None,
        "",
    ):
        return None

    try:
        timestamp = int(
            value
        )
    except (
        TypeError,
        ValueError,
    ):
        return None

    try:
        parsed = datetime.datetime.fromtimestamp(
            timestamp,
            tz=datetime.timezone.utc,
        )
    except (
        OverflowError,
        OSError,
        ValueError,
    ):
        return None

    return parsed.isoformat().replace(
        "+00:00",
        "Z",
    )


def normalize_misp_attribute_type(
    attribute_type: str,
    value: str,
) -> str | None:
    """Map supported MISP attribute types to the common indicator model."""

    normalized = attribute_type.strip().lower()

    if normalized in {
        "ip-src",
        "ip-dst",
        "ip-src|port",
        "ip-dst|port",
    }:
        ip_value = value.split(
            "|",
            1,
        )[0].strip()

        try:
            parsed_ip = ipaddress.ip_address(
                ip_value
            )
        except ValueError:
            return None

        if parsed_ip.version == 4:
            return "ipv4"

        return "ipv6"

    mapping = {
        "domain": "domain",
        "hostname": "domain",
        "url": "url",
        "sha256": "sha256",
    }

    return mapping.get(
        normalized
    )


def normalize_misp_attribute_value(
    attribute_type: str,
    value: str,
) -> str:
    """Normalize the value portion of supported MISP attributes."""

    normalized = attribute_type.strip().lower()

    if normalized in {
        "ip-src|port",
        "ip-dst|port",
    }:
        return value.split(
            "|",
            1,
        )[0].strip()

    if normalized == "sha256":
        return value.lower()

    return value.strip()


def extract_misp_tags(
    attribute: dict,
) -> list[str]:
    """Extract tag names attached to a MISP attribute."""

    raw_tags = attribute.get(
        "Tag",
        [],
    )

    if not isinstance(
        raw_tags,
        list,
    ):
        return []

    tags: list[str] = []

    for tag in raw_tags:
        if isinstance(
            tag,
            dict,
        ):
            name = tag.get(
                "name"
            )

            if isinstance(
                name,
                str,
            ):
                tags.append(
                    name
                )

        elif isinstance(
            tag,
            str,
        ):
            tags.append(
                tag
            )

    return tags


def misp_attribute_to_indicator(
    attribute: dict,
    source_name: str,
    provenance: dict,
) -> ThreatIntelIndicator | None:
    """Convert one supported MISP attribute into the common model."""

    if not isinstance(
        attribute,
        dict,
    ):
        return None

    attribute_type = attribute.get(
        "type"
    )
    value = attribute.get(
        "value"
    )

    if (
        not isinstance(
            attribute_type,
            str,
        )
        or not isinstance(
            value,
            str,
        )
    ):
        return None

    indicator_type = (
        normalize_misp_attribute_type(
            attribute_type,
            value,
        )
    )

    if indicator_type is None:
        return None

    normalized_value = (
        normalize_misp_attribute_value(
            attribute_type,
            value,
        )
    )

    if not normalized_value:
        return None

    deleted = bool(
        attribute.get(
            "deleted",
            False,
        )
    )

    first_seen = attribute.get(
        "first_seen"
    )
    last_seen = attribute.get(
        "last_seen"
    )

    if not isinstance(
        first_seen,
        str,
    ):
        first_seen = None

    if not isinstance(
        last_seen,
        str,
    ):
        last_seen = None

    timestamp = unix_timestamp_to_iso(
        attribute.get(
            "timestamp"
        )
    )

    if first_seen is None:
        first_seen = timestamp

    if last_seen is None:
        last_seen = timestamp

    event_id = attribute.get(
        "event_id"
    )

    attribute_id = attribute.get(
        "id"
    )

    attribute_uuid = attribute.get(
        "uuid"
    )

    return ThreatIntelIndicator(
        value=normalized_value,
        type=indicator_type,
        source=source_name,
        confidence=None,
        source_reliability=None,
        first_seen=first_seen,
        last_seen=last_seen,
        expires_at=None,
        active=not deleted,
        tags=extract_misp_tags(
            attribute
        ),
        external_id=(
            str(attribute_id)
            if attribute_id is not None
            else None
        ),
        stix_id=None,
        provenance={
            **provenance,
            "event_id": (
                str(event_id)
                if event_id is not None
                else None
            ),
            "attribute_id": (
                str(attribute_id)
                if attribute_id is not None
                else None
            ),
            "attribute_uuid": (
                str(attribute_uuid)
                if attribute_uuid is not None
                else None
            ),
            "attribute_type": attribute_type,
            "category": attribute.get(
                "category"
            ),
            "comment": attribute.get(
                "comment"
            ),
            "to_ids": attribute.get(
                "to_ids"
            ),
        },
    )


class MISPIntelProvider:
    """
    Retrieve supported indicators from the MISP REST API.

    The provider uses the attributes/restSearch endpoint and converts
    supported MISP attributes into ThreatIntelIndicator objects.
    """

    def __init__(
        self,
        base_url: str,
        api_key: str,
        source_name: str = "MISP",
        timeout_seconds: int = 10,
        verify_ssl: bool = True,
        search_payload: dict | None = None,
    ):
        self.base_url = base_url.rstrip(
            "/"
        )
        self.api_key = api_key
        self.source_name = source_name
        self.timeout_seconds = timeout_seconds
        self.verify_ssl = verify_ssl
        self.search_payload = (
            search_payload
            if search_payload is not None
            else {
                "returnFormat": "json",
                "published": True,
            }
        )

    @property
    def rest_search_url(
        self,
    ) -> str:
        """Return the MISP attribute search endpoint."""

        return (
            f"{self.base_url}/attributes/restSearch"
        )

    def _build_request(
        self,
    ) -> urllib.request.Request:
        """Build an authenticated MISP REST request."""

        body = json.dumps(
            self.search_payload
        ).encode(
            "utf-8"
        )

        return urllib.request.Request(
            url=self.rest_search_url,
            data=body,
            headers={
                "Authorization": self.api_key,
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            method="POST",
        )

    def _fetch_json(
        self,
    ) -> dict | list:
        """Fetch and decode a MISP JSON response."""

        request = self._build_request()

        ssl_context = None

        if not self.verify_ssl:
            ssl_context = (
                ssl._create_unverified_context()
            )

        try:
            with urllib.request.urlopen(
                request,
                timeout=self.timeout_seconds,
                context=ssl_context,
            ) as response:
                payload = response.read()

        except (
            urllib.error.HTTPError,
            urllib.error.URLError,
            TimeoutError,
        ) as error:
            raise ThreatIntelError(
                "MISP request failed for "
                f"{self.rest_search_url}: {error}"
            ) from error

        try:
            data = json.loads(
                payload.decode(
                    "utf-8"
                )
            )

        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
        ) as error:
            raise ThreatIntelError(
                "Invalid MISP JSON response from "
                f"{self.rest_search_url}"
            ) from error

        if not isinstance(
            data,
            (
                dict,
                list,
            ),
        ):
            raise ThreatIntelError(
                "MISP response must be a JSON object or list"
            )

        return data

    def _extract_attributes(
        self,
        payload: dict | list,
    ) -> list[dict]:
        """Extract attribute dictionaries from common MISP response shapes."""

        if isinstance(
            payload,
            list,
        ):
            return [
                item
                for item in payload
                if isinstance(
                    item,
                    dict,
                )
            ]

        response = payload.get(
            "response"
        )

        if isinstance(
            response,
            dict,
        ):
            attributes = response.get(
                "Attribute"
            )

            if isinstance(
                attributes,
                list,
            ):
                return [
                    item
                    for item in attributes
                    if isinstance(
                        item,
                        dict,
                    )
                ]

        if isinstance(
            response,
            list,
        ):
            return [
                item
                for item in response
                if isinstance(
                    item,
                    dict,
                )
            ]

        attributes = payload.get(
            "Attribute"
        )

        if isinstance(
            attributes,
            list,
        ):
            return [
                item
                for item in attributes
                if isinstance(
                    item,
                    dict,
                )
            ]

        raise ThreatIntelError(
            "MISP response did not contain an attribute list"
        )

    def load(
        self,
    ) -> list[ThreatIntelIndicator]:
        """Fetch and normalize supported MISP attributes."""

        payload = self._fetch_json()

        attributes = self._extract_attributes(
            payload
        )

        indicators: list[
            ThreatIntelIndicator
        ] = []

        for attribute in attributes:
            indicator = (
                misp_attribute_to_indicator(
                    attribute=attribute,
                    source_name=self.source_name,
                    provenance={
                        "provider": "misp",
                        "url": self.rest_search_url,
                    },
                )
            )

            if indicator is not None:
                indicators.append(
                    indicator
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
