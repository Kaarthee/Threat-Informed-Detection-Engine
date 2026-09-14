import json
import tempfile
import unittest
from pathlib import Path

from src.attack import (
    AttackDataError,
    AttackKnowledgeBase,
    build_technique_index,
    extract_platforms,
    extract_tactics,
    get_external_attack_id,
    load_attack_bundle,
    load_attack_knowledge_base,
    technique_to_metadata,
)


class TestAttackBundleLoading(unittest.TestCase):

    def test_missing_file_raises_error(self):
        missing_file = Path(
            "data/attack/does-not-exist.json"
        )

        with self.assertRaises(
            AttackDataError
        ):
            load_attack_bundle(
                missing_file
            )

    def test_invalid_json_raises_error(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(
                temp_dir
            ) / "invalid.json"

            path.write_text(
                "{not-valid-json",
                encoding="utf-8",
            )

            with self.assertRaises(
                AttackDataError
            ):
                load_attack_bundle(
                    path
                )

    def test_missing_objects_list_raises_error(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(
                temp_dir
            ) / "invalid-bundle.json"

            path.write_text(
                json.dumps(
                    {
                        "type": "bundle",
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaises(
                AttackDataError
            ):
                load_attack_bundle(
                    path
                )


class TestAttackObjectParsing(unittest.TestCase):

    def setUp(self):
        self.object = {
            "type": "attack-pattern",
            "id": "attack-pattern--example",
            "name": "Example Technique",
            "created": "2026-01-01T00:00:00Z",
            "modified": "2026-02-01T00:00:00Z",
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "external_id": "T9999",
                }
            ],
            "kill_chain_phases": [
                {
                    "kill_chain_name": "mitre-attack",
                    "phase_name": "discovery",
                },
                {
                    "kill_chain_name": "mitre-attack",
                    "phase_name": "execution",
                },
            ],
            "x_mitre_platforms": [
                "Linux",
                "Windows",
            ],
            "x_mitre_is_subtechnique": False,
            "x_mitre_deprecated": False,
            "revoked": False,
        }

    def test_external_attack_id(self):
        self.assertEqual(
            get_external_attack_id(
                self.object
            ),
            "T9999",
        )

    def test_tactics_are_extracted(self):
        self.assertEqual(
            extract_tactics(
                self.object
            ),
            [
                "discovery",
                "execution",
            ],
        )

    def test_platforms_are_extracted(self):
        self.assertEqual(
            extract_platforms(
                self.object
            ),
            [
                "Linux",
                "Windows",
            ],
        )

    def test_metadata_conversion(self):
        metadata = technique_to_metadata(
            self.object
        )

        self.assertEqual(
            metadata["technique_id"],
            "T9999",
        )

        self.assertEqual(
            metadata["name"],
            "Example Technique",
        )

        self.assertFalse(
            metadata["deprecated"]
        )

        self.assertFalse(
            metadata["revoked"]
        )


class TestTechniqueIndex(unittest.TestCase):

    def test_only_attack_patterns_are_indexed(self):
        bundle = {
            "objects": [
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--one",
                    "external_references": [
                        {
                            "source_name": "mitre-attack",
                            "external_id": "T1234",
                        }
                    ],
                },
                {
                    "type": "malware",
                    "id": "malware--one",
                    "external_references": [
                        {
                            "source_name": "mitre-attack",
                            "external_id": "S9999",
                        }
                    ],
                },
            ]
        }

        index = build_technique_index(
            bundle
        )

        self.assertIn(
            "T1234",
            index,
        )

        self.assertNotIn(
            "S9999",
            index,
        )


class TestRealAttackKnowledgeBase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.attack = (
            AttackKnowledgeBase()
        )

    def test_t1110_exists(self):
        technique = (
            self.attack.get_technique(
                "T1110"
            )
        )

        self.assertIsNotNone(
            technique
        )

        self.assertEqual(
            technique["name"],
            "Brute Force",
        )

    def test_t1110_003_exists(self):
        technique = (
            self.attack.get_technique(
                "T1110.003"
            )
        )

        self.assertIsNotNone(
            technique
        )

        self.assertEqual(
            technique["name"],
            "Password Spraying",
        )

        self.assertTrue(
            technique[
                "is_subtechnique"
            ]
        )

    def test_unknown_technique_returns_none(self):
        self.assertIsNone(
            self.attack.get_technique(
                "T0000"
            )
        )

    def test_has_technique(self):
        self.assertTrue(
            self.attack.has_technique(
                "T1078"
            )
        )

        self.assertFalse(
            self.attack.has_technique(
                "T0000"
            )
        )

    def test_active_techniques_exclude_retired_content(self):
        active = (
            self.attack.get_active_techniques()
        )

        for metadata in active.values():
            self.assertFalse(
                metadata["deprecated"]
            )

            self.assertFalse(
                metadata["revoked"]
            )


class TestBehaviorEnrichment(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.attack = (
            AttackKnowledgeBase()
        )

    def test_behavior_is_enriched(self):
        behavior = {
            "detection_id": "D001",
            "attack": {
                "technique_id": "T1110",
                "mapping_status": "supported",
            },
        }

        enriched = (
            self.attack.enrich_behavior(
                behavior
            )
        )

        attack = enriched[
            "attack"
        ]

        self.assertTrue(
            attack[
                "metadata_found"
            ]
        )

        self.assertEqual(
            attack["name"],
            "Brute Force",
        )

        self.assertEqual(
            attack["source"],
            "MITRE ATT&CK",
        )

        self.assertIn(
            "credential-access",
            attack["tactics"],
        )

    def test_unknown_attack_id_is_preserved(self):
        behavior = {
            "detection_id": "TEST",
            "attack": {
                "technique_id": "T0000",
                "mapping_status": "contextual",
            },
        }

        enriched = (
            self.attack.enrich_behavior(
                behavior
            )
        )

        self.assertFalse(
            enriched["attack"][
                "metadata_found"
            ]
        )

        self.assertEqual(
            enriched["attack"][
                "technique_id"
            ],
            "T0000",
        )

    def test_behavior_without_attack_is_unchanged(self):
        behavior = {
            "detection_id": "TEST",
            "attack": None,
        }

        enriched = (
            self.attack.enrich_behavior(
                behavior
            )
        )

        self.assertEqual(
            enriched,
            behavior,
        )


class TestSafeAttackLoading(unittest.TestCase):

    def test_missing_cache_returns_none(self):
        result = (
            load_attack_knowledge_base(
                Path(
                    "data/attack/"
                    "missing-cache.json"
                )
            )
        )

        self.assertIsNone(
            result
        )


if __name__ == "__main__":
    unittest.main()
