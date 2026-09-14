import unittest

from src.attack import AttackKnowledgeBase
from src.coverage import (
    DETECTION_COVERAGE,
    build_attack_coverage,
    summarize_coverage,
)


class TestCoverageCatalogue(unittest.TestCase):

    def test_catalogue_contains_ten_detections(self):
        self.assertEqual(
            len(DETECTION_COVERAGE),
            10,
        )

    def test_detection_ids_are_unique(self):
        detection_ids = [
            entry.detection_id
            for entry in DETECTION_COVERAGE
        ]

        self.assertEqual(
            len(detection_ids),
            len(set(detection_ids)),
        )


class TestCoverageGeneration(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.attack = AttackKnowledgeBase()

        cls.coverage = build_attack_coverage(
            cls.attack
        )

    def test_all_records_have_attack_metadata(self):
        for record in self.coverage:
            self.assertTrue(
                record["metadata_found"]
            )

            self.assertIsNotNone(
                record["technique_name"]
            )

    def test_d001_maps_to_brute_force(self):
        record = next(
            item
            for item in self.coverage
            if item["detection_id"] == "D001"
        )

        self.assertEqual(
            record["technique_id"],
            "T1110",
        )

        self.assertEqual(
            record["technique_name"],
            "Brute Force",
        )

        self.assertEqual(
            record["coverage_status"],
            "detected",
        )

    def test_d003_maps_to_password_spraying(self):
        record = next(
            item
            for item in self.coverage
            if item["detection_id"] == "D003"
        )

        self.assertEqual(
            record["technique_id"],
            "T1110.003",
        )

        self.assertEqual(
            record["technique_name"],
            "Password Spraying",
        )

        self.assertEqual(
            record["coverage_status"],
            "partial",
        )

    def test_d010_maps_to_ssh_authorized_keys(self):
        record = next(
            item
            for item in self.coverage
            if item["detection_id"] == "D010"
        )

        self.assertEqual(
            record["technique_id"],
            "T1098.004",
        )

        self.assertEqual(
            record["technique_name"],
            "SSH Authorized Keys",
        )

        self.assertEqual(
            record["coverage_status"],
            "detected",
        )


class TestCoverageSummary(unittest.TestCase):

    def test_summary_counts(self):
        attack = AttackKnowledgeBase()

        coverage = build_attack_coverage(
            attack
        )

        summary = summarize_coverage(
            coverage
        )

        self.assertEqual(
            summary["total_detections"],
            10,
        )

        self.assertEqual(
            summary["detected"],
            2,
        )

        self.assertEqual(
            summary["partial"],
            8,
        )

        self.assertEqual(
            summary["unsupported"],
            0,
        )


if __name__ == "__main__":
    unittest.main()

