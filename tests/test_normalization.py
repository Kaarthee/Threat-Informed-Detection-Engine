import datetime
import unittest

from src.normalization import (
    count_normalized_events,
    create_normalized_event_windows,
    group_events_by_source_ip,
    normalized_events_to_raw_logs,
    SecurityEvent,
    normalize_ubuntu_auth_log,
    normalize_ubuntu_auth_logs,
    parse_ubuntu_timestamp,
    normalize_cowrie_event,
    normalize_cowrie_logs,
    read_cowrie_jsonl,
)


class TestUbuntuTimestampNormalization(unittest.TestCase):
    def test_valid_timestamp_becomes_iso_format(self):
        log = (
            "Apr 28 10:35:11 ubuntu sshd[1234]: "
            "Failed password for root from "
            "192.168.56.101 port 44322 ssh2"
        )

        result = parse_ubuntu_timestamp(log)
        current_year = datetime.datetime.now().year

        self.assertEqual(
            result,
            f"{current_year}-04-28T10:35:11",
        )

    def test_invalid_timestamp_returns_none(self):
        log = (
            "INVALID-TIME ubuntu sshd[1234]: "
            "Failed password for root from "
            "192.168.56.101 port 44322 ssh2"
        )

        result = parse_ubuntu_timestamp(log)

        self.assertIsNone(result)


class TestUbuntuAuthNormalization(unittest.TestCase):
    def test_failed_login_is_normalized(self):
        log = (
            "Apr 28 10:35:11 ubuntu sshd[1234]: "
            "Failed password for root from "
            "192.168.56.101 port 44322 ssh2"
        )

        event = normalize_ubuntu_auth_log(log)

        self.assertIsInstance(
            event,
            SecurityEvent,
        )
        self.assertEqual(
            event.source_ip,
            "192.168.56.101",
        )
        self.assertEqual(
            event.event_type,
            "authentication_failure",
        )
        self.assertEqual(
            event.username,
            "root",
        )
        self.assertEqual(
            event.source_port,
            44322,
        )
        self.assertEqual(
            event.destination_port,
            22,
        )
        self.assertEqual(
            event.source,
            "ubuntu_auth",
        )
        self.assertEqual(
            event.protocol,
            "ssh",
        )

    def test_successful_login_is_normalized(self):
        log = (
            "Apr 28 10:36:45 ubuntu sshd[1237]: "
            "Accepted password for user from "
            "192.168.56.101 port 53421 ssh2"
        )

        event = normalize_ubuntu_auth_log(log)

        self.assertIsNotNone(event)
        self.assertEqual(
            event.event_type,
            "authentication_success",
        )
        self.assertEqual(
            event.username,
            "user",
        )
        self.assertEqual(
            event.source_port,
            53421,
        )
        self.assertEqual(
            event.destination_port,
            22,
        )

    def test_invalid_user_login_is_normalized(self):
        log = (
            "Apr 28 10:40:00 ubuntu sshd[2000]: "
            "Failed password for invalid user admin from "
            "203.0.113.50 port 60000 ssh2"
        )

        event = normalize_ubuntu_auth_log(log)

        self.assertIsNotNone(event)
        self.assertEqual(
            event.username,
            "admin",
        )
        self.assertEqual(
            event.event_type,
            "authentication_failure",
        )

    def test_unrelated_log_returns_none(self):
        log = (
            "Apr 28 10:45:00 ubuntu systemd[1]: "
            "Started Daily Cleanup."
        )

        event = normalize_ubuntu_auth_log(log)

        self.assertIsNone(event)

    def test_malformed_timestamp_preserves_event(self):
        log = (
            "INVALID-TIME ubuntu sshd[3000]: "
            "Failed password for root from "
            "198.51.100.10 port 50000 ssh2"
        )

        event = normalize_ubuntu_auth_log(log)

        self.assertIsNotNone(event)
        self.assertIsNone(
            event.timestamp
        )
        self.assertEqual(
            event.source_ip,
            "198.51.100.10",
        )

    def test_multiple_logs_only_return_supported_events(self):
        logs = [
            (
                "Apr 28 10:35:11 ubuntu sshd[1234]: "
                "Failed password for root from "
                "192.168.56.101 port 44322 ssh2"
            ),
            (
                "Apr 28 10:36:45 ubuntu sshd[1237]: "
                "Accepted password for user from "
                "192.168.56.101 port 53421 ssh2"
            ),
            (
                "Apr 28 10:45:00 ubuntu systemd[1]: "
                "Started Daily Cleanup."
            ),
        ]

        events = normalize_ubuntu_auth_logs(
            logs
        )

        self.assertEqual(
            len(events),
            2,
        )
        self.assertEqual(
            events[0].event_type,
            "authentication_failure",
        )
        self.assertEqual(
            events[1].event_type,
            "authentication_success",
        )

    def test_event_converts_to_dictionary(self):
        log = (
            "Apr 28 10:35:11 ubuntu sshd[1234]: "
            "Failed password for root from "
            "192.168.56.101 port 44322 ssh2"
        )

        event = normalize_ubuntu_auth_log(log)
        event_dict = event.to_dict()

        self.assertEqual(
            event_dict["source_ip"],
            "192.168.56.101",
        )
        self.assertEqual(
            event_dict["event_type"],
            "authentication_failure",
        )
        self.assertIn(
            "raw_log",
            event_dict,
        )
        self.assertEqual(
            event_dict["source_port"],
            44322,
        )
        self.assertEqual(
            event_dict["destination_port"],
            22,
        )

class TestNormalizedEventProcessing(unittest.TestCase):
    def create_event(
        self,
        timestamp,
        source_ip,
        event_type,
        raw_log,
    ):
        return SecurityEvent(
            timestamp=timestamp,
            source_ip=source_ip,
            event_type=event_type,
            username="test",
            source="ubuntu_auth",
            destination_port=22,
            protocol="ssh",
            raw_log=raw_log,
        )

    def test_events_group_by_source_ip(self):
        events = [
            self.create_event(
                "2026-04-28T10:00:00",
                "192.168.1.10",
                "authentication_failure",
                "failure-one",
            ),
            self.create_event(
                "2026-04-28T10:01:00",
                "192.168.1.10",
                "authentication_failure",
                "failure-two",
            ),
            self.create_event(
                "2026-04-28T10:02:00",
                "192.168.1.20",
                "authentication_success",
                "success-one",
            ),
        ]

        grouped = group_events_by_source_ip(events)

        self.assertEqual(len(grouped), 2)
        self.assertEqual(
            len(grouped["192.168.1.10"]),
            2,
        )
        self.assertEqual(
            len(grouped["192.168.1.20"]),
            1,
        )

    def test_events_inside_window_are_grouped(self):
        events = [
            self.create_event(
                "2026-04-28T12:00:00",
                "192.168.1.10",
                "authentication_failure",
                "failure-one",
            ),
            self.create_event(
                "2026-04-28T12:05:00",
                "192.168.1.10",
                "authentication_failure",
                "failure-two",
            ),
        ]

        windows = create_normalized_event_windows(events)

        self.assertEqual(len(windows), 1)
        self.assertEqual(len(windows[0]), 2)

    def test_event_after_window_starts_new_incident(self):
        events = [
            self.create_event(
                "2026-04-28T12:00:00",
                "192.168.1.10",
                "authentication_failure",
                "failure-one",
            ),
            self.create_event(
                "2026-04-28T12:05:01",
                "192.168.1.10",
                "authentication_failure",
                "failure-two",
            ),
        ]

        windows = create_normalized_event_windows(events)

        self.assertEqual(len(windows), 2)

    def test_events_are_sorted_before_correlation(self):
        events = [
            self.create_event(
                "2026-04-28T13:04:00",
                "192.168.1.10",
                "authentication_failure",
                "later-event",
            ),
            self.create_event(
                "2026-04-28T13:00:00",
                "192.168.1.10",
                "authentication_failure",
                "earlier-event",
            ),
        ]

        windows = create_normalized_event_windows(events)

        self.assertEqual(
            windows[0][0].raw_log,
            "earlier-event",
        )
        self.assertEqual(
            windows[0][1].raw_log,
            "later-event",
        )

    def test_event_without_timestamp_is_isolated(self):
        events = [
            self.create_event(
                "2026-04-28T14:00:00",
                "192.168.1.10",
                "authentication_failure",
                "valid-event",
            ),
            self.create_event(
                None,
                "192.168.1.10",
                "authentication_failure",
                "invalid-time-event",
            ),
        ]

        windows = create_normalized_event_windows(events)

        self.assertEqual(len(windows), 2)
        self.assertEqual(
            windows[1][0].raw_log,
            "invalid-time-event",
        )

    def test_normalized_event_counts(self):
        events = [
            self.create_event(
                "2026-04-28T15:00:00",
                "192.168.1.10",
                "authentication_failure",
                "failure-one",
            ),
            self.create_event(
                "2026-04-28T15:01:00",
                "192.168.1.10",
                "authentication_failure",
                "failure-two",
            ),
            self.create_event(
                "2026-04-28T15:02:00",
                "192.168.1.10",
                "authentication_success",
                "success-one",
            ),
        ]

        failed, successful = count_normalized_events(events)

        self.assertEqual(failed, 2)
        self.assertEqual(successful, 1)

    def test_raw_logs_are_preserved_as_evidence(self):
        events = [
            self.create_event(
                "2026-04-28T16:00:00",
                "192.168.1.10",
                "authentication_failure",
                "original-log-one",
            ),
            self.create_event(
                "2026-04-28T16:01:00",
                "192.168.1.10",
                "authentication_success",
                "original-log-two",
            ),
        ]

        raw_logs = normalized_events_to_raw_logs(events)

        self.assertEqual(
            raw_logs,
            [
                "original-log-one",
                "original-log-two",
            ],
        )

    def test_cross_source_events_share_window(self):
        events = [
            SecurityEvent(
                timestamp="2026-07-17T10:00:00",
                source_ip="45.141.215.90",
                event_type="authentication_failure",
                username="root",
                source="ubuntu_auth",
                destination_port=22,
                protocol="ssh",
                raw_log="ubuntu failure",
            ),
            SecurityEvent(
                timestamp="2026-07-17T10:01:00+00:00",
                source_ip="45.141.215.90",
                event_type="authentication_failure",
                username="admin",
                source="cowrie",
                destination_port=22,
                protocol="ssh",
                raw_log="cowrie failure",
            ),
        ]

        windows = create_normalized_event_windows(
            events
        )

        self.assertEqual(
            len(windows),
            1,
        )

        sources = {
            event.source
            for event in windows[0]
        }

        self.assertEqual(
            sources,
            {
                "ubuntu_auth",
                "cowrie",
            },
        )

class TestCowrieNormalization(unittest.TestCase):
    def test_failed_login_is_normalized(self):
        event_data = {
            "eventid": "cowrie.login.failed",
            "timestamp": "2026-07-17T10:00:00.000000Z",
            "src_ip": "45.141.215.90",
            "src_port": 50100,
            "dst_port": 22,
            "username": "root",
        }

        event = normalize_cowrie_event(event_data)

        self.assertIsNotNone(event)
        self.assertEqual(
            event.event_type,
            "authentication_failure",
        )
        self.assertEqual(
            event.source_ip,
            "45.141.215.90",
        )
        self.assertEqual(
            event.username,
            "root",
        )
        self.assertEqual(
            event.source,
            "cowrie",
        )
        self.assertEqual(
            event.source_port,
            50100,
        )
        self.assertEqual(
            event.destination_port,
            22,
        )

    def test_successful_login_is_normalized(self):
        event_data = {
            "eventid": "cowrie.login.success",
            "timestamp": "2026-07-17T10:02:00.000000Z",
            "src_ip": "45.141.215.90",
            "dst_port": 22,
            "username": "root",
        }

        event = normalize_cowrie_event(event_data)

        self.assertIsNotNone(event)
        self.assertEqual(
            event.event_type,
            "authentication_success",
        )

    def test_command_event_is_normalized(self):
        event_data = {
            "eventid": "cowrie.command.input",
            "timestamp": "2026-07-17T10:03:00.000000Z",
            "src_ip": "45.141.215.90",
            "dst_port": 22,
            "input": "uname -a",
        }

        event = normalize_cowrie_event(event_data)

        self.assertIsNotNone(event)
        self.assertEqual(
            event.event_type,
            "command_executed",
        )
        self.assertIsNone(
            event.username
        )

    def test_session_closed_is_normalized(self):
        event_data = {
            "eventid": "cowrie.session.closed",
            "timestamp": "2026-07-17T10:05:00.000000Z",
            "src_ip": "45.141.215.90",
            "dst_port": 22,
        }

        event = normalize_cowrie_event(event_data)

        self.assertIsNotNone(event)
        self.assertEqual(
            event.event_type,
            "session_closed",
        )

    def test_unsupported_event_returns_none(self):
        event_data = {
            "eventid": "cowrie.client.version",
            "timestamp": "2026-07-17T10:06:00.000000Z",
            "src_ip": "45.141.215.90",
        }

        event = normalize_cowrie_event(event_data)

        self.assertIsNone(event)

    def test_missing_source_ip_returns_none(self):
        event_data = {
            "eventid": "cowrie.login.failed",
            "timestamp": "2026-07-17T10:00:00.000000Z",
            "username": "root",
        }

        event = normalize_cowrie_event(event_data)

        self.assertIsNone(event)

    def test_invalid_timestamp_preserves_event(self):
        event_data = {
            "eventid": "cowrie.login.failed",
            "timestamp": "not-a-valid-time",
            "src_ip": "45.141.215.90",
            "dst_port": 22,
            "username": "root",
        }

        event = normalize_cowrie_event(event_data)

        self.assertIsNotNone(event)
        self.assertIsNone(
            event.timestamp
        )

    def test_jsonl_reader_skips_malformed_lines(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as directory:
            log_file = Path(directory) / "cowrie.jsonl"

            log_file.write_text(
                "\n".join(
                    [
                        (
                            '{"eventid":"cowrie.login.failed",'
                            '"src_ip":"45.141.215.90"}'
                        ),
                        "not-valid-json",
                        "",
                    ]
                ),
                encoding="utf-8",
            )

            events = read_cowrie_jsonl(
                log_file
            )

        self.assertEqual(
            len(events),
            1,
        )

    def test_sample_file_normalizes_all_events(self):
        from pathlib import Path

        events = normalize_cowrie_logs(
            Path("logs/sample-cowrie.jsonl")
        )

        self.assertEqual(
            len(events),
            15,
        )
        self.assertEqual(
            events[0].event_type,
            "authentication_failure",
        )
        self.assertEqual(
            events[2].event_type,
            "authentication_success",
        )
        self.assertEqual(
            events[3].event_type,
            "command_executed",
        )

if __name__ == "__main__":
    unittest.main()
