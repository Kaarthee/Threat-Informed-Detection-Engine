import datetime
import json
import tempfile
import unittest
from unittest import mock
from pathlib import Path

from src.threat_intel import (
    LocalJSONIntelProvider,
    STIXIntelProvider,
    TAXIIIntelProvider,
    ThreatIntelError,
    ThreatIntelIndicator,
    ThreatIntelStore,
    normalize_indicator_type,
    parse_stix_indicator_pattern,
)


class TestThreatIntelIndicator(unittest.TestCase):

    def test_active_indicator_is_current(self):
        indicator = ThreatIntelIndicator(
            value="1.2.3.4",
            type="ipv4",
            source="Test",
            active=True,
            expires_at="2099-01-01T00:00:00Z",
        )

        self.assertTrue(
            indicator.is_current()
        )

    def test_inactive_indicator_is_not_current(self):
        indicator = ThreatIntelIndicator(
            value="1.2.3.4",
            type="ipv4",
            source="Test",
            active=False,
        )

        self.assertFalse(
            indicator.is_current()
        )

    def test_expired_indicator_is_not_current(self):
        indicator = ThreatIntelIndicator(
            value="1.2.3.4",
            type="ipv4",
            source="Test",
            active=True,
            expires_at="2020-01-01T00:00:00Z",
        )

        self.assertFalse(
            indicator.is_current(
                datetime.datetime(
                    2026,
                    1,
                    1,
                    tzinfo=datetime.timezone.utc,
                )
            )
        )


    def test_indicator_is_not_current_before_first_seen(self):
        indicator = ThreatIntelIndicator(
            value="1.2.3.4",
            type="ipv4",
            source="Test",
            active=True,
            first_seen="2026-09-14T00:00:00Z",
            expires_at="2027-09-14T00:00:00Z",
        )

        self.assertFalse(
            indicator.is_current(
                datetime.datetime(
                    2026,
                    7,
                    17,
                    tzinfo=datetime.timezone.utc,
                )
            )
        )

    def test_indicator_is_current_inside_validity_window(self):
        indicator = ThreatIntelIndicator(
            value="1.2.3.4",
            type="ipv4",
            source="Test",
            active=True,
            first_seen="2026-09-14T00:00:00Z",
            expires_at="2027-09-14T00:00:00Z",
        )

        self.assertTrue(
            indicator.is_current(
                datetime.datetime(
                    2026,
                    10,
                    3,
                    tzinfo=datetime.timezone.utc,
                )
            )
        )


class TestIndicatorTypeNormalization(unittest.TestCase):

    def test_ipv4_stix_type(self):
        self.assertEqual(
            normalize_indicator_type(
                "ipv4-addr"
            ),
            "ipv4",
        )

    def test_domain_stix_type(self):
        self.assertEqual(
            normalize_indicator_type(
                "domain-name"
            ),
            "domain",
        )

    def test_sha256_type(self):
        self.assertEqual(
            normalize_indicator_type(
                "SHA-256"
            ),
            "sha256",
        )


class TestSTIXPatternParsing(unittest.TestCase):

    def test_ipv4_pattern(self):
        result = parse_stix_indicator_pattern(
            "[ipv4-addr:value = '45.141.215.90']"
        )

        self.assertEqual(
            result,
            (
                "ipv4",
                "45.141.215.90",
            ),
        )

    def test_domain_pattern(self):
        result = parse_stix_indicator_pattern(
            "[domain-name:value = 'example.com']"
        )

        self.assertEqual(
            result,
            (
                "domain",
                "example.com",
            ),
        )

    def test_sha256_pattern(self):
        hash_value = (
            "a" * 64
        )

        result = parse_stix_indicator_pattern(
            "[file:hashes.'SHA-256' = "
            f"'{hash_value}']"
        )

        self.assertEqual(
            result,
            (
                "sha256",
                hash_value,
            ),
        )

    def test_unsupported_pattern_returns_none(self):
        result = parse_stix_indicator_pattern(
            "[process:name = 'evil.exe']"
        )

        self.assertIsNone(
            result
        )


class TestLocalJSONProvider(unittest.TestCase):

    def test_loads_valid_indicator(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(
                temp_dir
            ) / "iocs.json"

            path.write_text(
                json.dumps(
                    {
                        "indicators": [
                            {
                                "value": "1.2.3.4",
                                "type": "ipv4",
                                "source": "Test Feed",
                                "confidence": 90,
                                "active": True,
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            provider = LocalJSONIntelProvider(
                path
            )

            indicators = provider.load()

            self.assertEqual(
                len(indicators),
                1,
            )

            self.assertEqual(
                indicators[0].value,
                "1.2.3.4",
            )

            self.assertEqual(
                indicators[0].source,
                "Test Feed",
            )

    def test_missing_file_raises_error(self):
        provider = LocalJSONIntelProvider(
            Path(
                "missing-iocs.json"
            )
        )

        with self.assertRaises(
            ThreatIntelError
        ):
            provider.load()


class TestSTIXProvider(unittest.TestCase):

    def test_loads_supported_indicator(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(
                temp_dir
            ) / "bundle.json"

            path.write_text(
                json.dumps(
                    {
                        "type": "bundle",
                        "objects": [
                            {
                                "type": "indicator",
                                "id": "indicator--test",
                                "pattern_type": "stix",
                                "pattern": (
                                    "[ipv4-addr:value = "
                                    "'8.8.8.8']"
                                ),
                                "confidence": 80,
                                "valid_from": (
                                    "2026-01-01T00:00:00Z"
                                ),
                                "valid_until": (
                                    "2099-01-01T00:00:00Z"
                                ),
                                "labels": [
                                    "scanner"
                                ],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            provider = STIXIntelProvider(
                path,
                source_name="Test STIX",
            )

            indicators = provider.load()

            self.assertEqual(
                len(indicators),
                1,
            )

            self.assertEqual(
                indicators[0].value,
                "8.8.8.8",
            )

            self.assertEqual(
                indicators[0].source,
                "Test STIX",
            )

            self.assertEqual(
                indicators[0].stix_id,
                "indicator--test",
            )

    def test_unsupported_pattern_is_skipped(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(
                temp_dir
            ) / "bundle.json"

            path.write_text(
                json.dumps(
                    {
                        "type": "bundle",
                        "objects": [
                            {
                                "type": "indicator",
                                "id": "indicator--test",
                                "pattern": (
                                    "[process:name = "
                                    "'evil.exe']"
                                ),
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            provider = STIXIntelProvider(
                path
            )

            self.assertEqual(
                provider.load(),
                [],
            )



class TestTAXIIProvider(unittest.TestCase):

    def setUp(self):
        self.provider = TAXIIIntelProvider(
            "https://example.test/taxii2/"
            "collections/test/objects/",
            source_name="Test TAXII Feed",
        )

    def test_loads_supported_indicator(self):
        envelope = {
            "objects": [
                {
                    "type": "indicator",
                    "id": "indicator--taxii-test",
                    "pattern_type": "stix",
                    "pattern": (
                        "[ipv4-addr:value = "
                        "'9.9.9.9']"
                    ),
                    "confidence": 85,
                    "valid_from": (
                        "2026-01-01T00:00:00Z"
                    ),
                    "valid_until": (
                        "2099-01-01T00:00:00Z"
                    ),
                    "labels": [
                        "scanner"
                    ],
                }
            ],
            "more": False,
        }

        with mock.patch.object(
            self.provider,
            "_fetch_json",
            return_value=envelope,
        ):
            indicators = self.provider.load()

        self.assertEqual(
            len(indicators),
            1,
        )

        self.assertEqual(
            indicators[0].value,
            "9.9.9.9",
        )

        self.assertEqual(
            indicators[0].source,
            "Test TAXII Feed",
        )

        self.assertEqual(
            indicators[0].stix_id,
            "indicator--taxii-test",
        )

        self.assertEqual(
            indicators[0].provenance[
                "provider"
            ],
            "taxii",
        )

    def test_unsupported_stix_object_is_skipped(self):
        envelope = {
            "objects": [
                {
                    "type": "indicator",
                    "id": "indicator--unsupported",
                    "pattern": (
                        "[process:name = "
                        "'evil.exe']"
                    ),
                }
            ],
            "more": False,
        }

        with mock.patch.object(
            self.provider,
            "_fetch_json",
            return_value=envelope,
        ):
            indicators = self.provider.load()

        self.assertEqual(
            indicators,
            [],
        )

    def test_invalid_taxii_json_raises_error(self):
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.read.return_value = (
            b"{invalid-json"
        )

        with mock.patch(
            "src.threat_intel."
            "urllib.request.urlopen",
            return_value=response,
        ):
            with self.assertRaises(
                ThreatIntelError
            ):
                self.provider._fetch_json(
                    self.provider.collection_objects_url
                )

    def test_malformed_objects_value_raises_error(self):
        with mock.patch.object(
            self.provider,
            "_fetch_json",
            return_value={
                "objects": "not-a-list",
                "more": False,
            },
        ):
            with self.assertRaises(
                ThreatIntelError
            ):
                self.provider.load()

    def test_pagination_follows_next_token(self):
        first_page = {
            "objects": [],
            "more": True,
            "next": "token-2",
        }

        second_page = {
            "objects": [],
            "more": False,
        }

        with mock.patch.object(
            self.provider,
            "_fetch_json",
            side_effect=[
                first_page,
                second_page,
            ],
        ) as fetch_json:
            indicators = self.provider.load()

        self.assertEqual(
            indicators,
            [],
        )

        self.assertEqual(
            fetch_json.call_count,
            2,
        )

        second_url = (
            fetch_json.call_args_list[
                1
            ].args[0]
        )

        self.assertIn(
            "next=token-2",
            second_url,
        )

    def test_basic_auth_header_is_added(self):
        provider = TAXIIIntelProvider(
            "https://example.test/taxii2/"
            "collections/test/objects/",
            username="user",
            password="pass",
        )

        request = provider._build_request(
            provider.collection_objects_url
        )

        self.assertEqual(
            request.get_header(
                "Authorization"
            ),
            "Basic dXNlcjpwYXNz",
        )

        self.assertEqual(
            request.get_header(
                "Accept"
            ),
            "application/taxii+json;version=2.1",
        )


class TestThreatIntelStore(unittest.TestCase):

    def setUp(self):
        self.local_provider = LocalJSONIntelProvider(
            Path(
                "data/iocs.json"
            )
        )

        self.stix_provider = STIXIntelProvider(
            Path(
                "data/stix/"
                "sample-indicators.json"
            ),
            source_name="Sample STIX Feed",
        )

        self.store = ThreatIntelStore(
            providers=[
                self.local_provider,
                self.stix_provider,
            ]
        )

        self.store.load()

    def test_all_sources_are_loaded(self):
        self.assertEqual(
            len(self.store.indicators),
            6,
        )

    def test_multi_source_ip_returns_two_matches(self):
        matches = self.store.lookup_ip(
            "45.141.215.90"
        )

        self.assertEqual(
            len(matches),
            2,
        )

        sources = {
            match.source
            for match in matches
        }

        self.assertEqual(
            sources,
            {
                "External Threat Feed",
                "Sample STIX Feed",
            },
        )


    def test_historical_lookup_excludes_future_stix_indicator(self):
        matches = self.store.lookup_ip(
            "45.141.215.90",
            reference_time=datetime.datetime(
                2026,
                7,
                17,
                10,
                5,
                tzinfo=datetime.timezone.utc,
            ),
        )

        self.assertEqual(
            len(matches),
            1,
        )

        self.assertEqual(
            matches[0].source,
            "External Threat Feed",
        )

    def test_highest_confidence_match_is_first(self):
        matches = self.store.lookup_ip(
            "45.141.215.90"
        )

        self.assertEqual(
            matches[0].confidence,
            90,
        )

        self.assertEqual(
            matches[1].confidence,
            80,
        )

    def test_best_match_returns_highest_ranked_indicator(self):
        match = self.store.best_ip_match(
            "45.141.215.90"
        )

        self.assertIsNotNone(
            match
        )

        self.assertEqual(
            match.source,
            "External Threat Feed",
        )

    def test_stix_only_indicator_is_found(self):
        matches = self.store.lookup_ip(
            "203.0.113.50"
        )

        self.assertEqual(
            len(matches),
            1,
        )

        self.assertEqual(
            matches[0].source,
            "Sample STIX Feed",
        )

    def test_unknown_ip_returns_empty_list(self):
        self.assertEqual(
            self.store.lookup_ip(
                "198.51.100.200"
            ),
            [],
        )

    def test_inactive_local_indicator_is_filtered(self):
        matches = self.store.lookup_ip(
            "192.168.20.18"
        )

        self.assertEqual(
            matches,
            [],
        )


if __name__ == "__main__":
    unittest.main()
