#!/usr/bin/env python3
"""Regression tests for the independent QUIC v3 oracle and checked-in fixture."""

from __future__ import annotations

import json
import struct
import unittest

import quic_v3_oracle as oracle


class QuicV3OracleTest(unittest.TestCase):
    def test_checked_in_fixture_is_exact(self) -> None:
        generated = oracle.build_fixture()
        checked_in = json.loads(oracle.FIXTURE.read_text(encoding="utf-8"))
        self.assertEqual(checked_in, generated)

    def test_envelope_layout_is_exactly_44_bytes(self) -> None:
        session = bytes(range(16))
        payload = bytes.fromhex(
            oracle.build_fixture()["artifacts"]["route_input_state"]["hex"]
        )[44:]
        record = oracle.envelope(session, 1, 1, 0, 2, 3, payload)
        self.assertEqual(record[:4], b"ULM3")
        self.assertEqual(record[4], 3)
        self.assertEqual(record[8:10], b"\x00\x2c")
        self.assertEqual(int.from_bytes(record[10:12], "big"), len(payload))
        self.assertEqual(record[12:28], session)
        self.assertEqual(len(record) - len(payload), 44)
        self.assertEqual(
            oracle.validate_envelope(record, "c2h", session, 1152),
            ("input-state", 2, 3, payload),
        )

    def test_every_registered_route_has_only_one_meaning(self) -> None:
        self.assertEqual(len(oracle.ROUTES), len(set(oracle.ROUTES.values())))
        artifacts = oracle.build_fixture()["artifacts"]
        for (direction, channel, kind), semantic in oracle.ROUTES.items():
            artifact_name = f"route_{semantic.replace('-', '_')}"
            if semantic == "video-repair":
                artifact_name += "_reserved"
            record = bytes.fromhex(artifacts[artifact_name]["hex"])
            if semantic == "video-repair":
                with self.assertRaisesRegex(ValueError, "phase-one FEC disabled"):
                    oracle.validate_envelope(
                        record, direction, bytes(range(0xC0, 0xD0)), 1152
                    )
                continue
            self.assertEqual(
                oracle.validate_envelope(
                    record,
                    direction,
                    bytes(range(0xC0, 0xD0)),
                    1152,
                )[0],
                semantic,
            )

    def test_hostile_vectors_are_reproducible(self) -> None:
        fixture = oracle.build_fixture()
        self.assertGreaterEqual(len(fixture["hostile"]), 19)
        for hostile in fixture["hostile"]:
            self.assertTrue(hostile["candidate_hex"])
            self.assertTrue(hostile["context"])
            self.assertTrue(hostile["reason"])
            self.assertEqual(hostile["expected"], "reject")

    def test_negative_integer_cbor_is_deterministic(self) -> None:
        self.assertEqual(oracle.cbor(-1), b"\x20")
        self.assertEqual(oracle.cbor(-12_000), bytes.fromhex("392edf"))
        self.assertEqual(oracle.decode_cbor(bytes.fromhex("392edf")), (-12_000, 3))

    def test_cbor_text_boundary_is_exact(self) -> None:
        maximum = "x" * 65_535
        encoded = oracle.cbor(maximum)
        self.assertEqual(oracle.decode_cbor(encoded), (maximum, len(encoded)))
        with self.assertRaisesRegex(ValueError, "CBOR text limit"):
            oracle.cbor(maximum + "x")
        oversized = oracle._head(3, 65_536) + b"x" * 65_536
        with self.assertRaisesRegex(ValueError, "CBOR string limit"):
            oracle.decode_cbor(oversized)

    def test_lifecycle_and_every_route_have_artifacts(self) -> None:
        fixture = oracle.build_fixture()
        artifacts = fixture["artifacts"]
        for name in (
            "pair_recovery_client_hello",
            "pair_recovery_server_hello",
            "pair_recovery_request",
            "pair_recovery_response",
            "start_request",
            "start_response",
            "attach_request",
            "attach_response",
            "video_config",
            "video_config_ack",
            "audio_config",
            "audio_config_ack",
            "microphone_config",
            "microphone_config_ack",
            "stop_request",
            "stop_response",
            "session_stopping",
            "session_ended",
        ):
            self.assertIn(name, artifacts)
        self.assertEqual(
            len([name for name in artifacts if name.startswith("route_")]),
            10,
        )
        repair = next(
            item for item in fixture["routing"] if item["semantic"] == "video-repair"
        )
        self.assertTrue(repair["registered"])
        self.assertFalse(repair["phase_one_allowed"])

    def test_transport_telemetry_binds_generation_and_bounds_rtt_fields(self) -> None:
        fixture = oracle.build_fixture()
        record = bytes.fromhex(
            fixture["artifacts"]["route_transport_telemetry"]["hex"]
        )
        route, sequence, object_id, payload = oracle.validate_envelope(
            record, "h2c", bytes(range(0xC0, 0xD0)), 1152
        )
        self.assertEqual((route, sequence, object_id), ("transport-telemetry", 1, 1))
        self.assertEqual(struct.unpack(">QIIII", payload), (1, 4_000, 3_000, 1_000, 0))

    def test_start_host_audio_is_an_explicit_boolean(self) -> None:
        fixture = oracle.build_fixture()
        start = bytes.fromhex(fixture["artifacts"]["start_request"]["hex"])
        fields = oracle.validate_control(start, "c2h")
        self.assertEqual(set(fields), set(range(1, 19)))
        self.assertIs(fields[18], True)

        false_start = oracle.control(0x0100, 5, {**fields, 18: False})
        self.assertIs(oracle.validate_control(false_start, "c2h")[18], False)

    def test_invitation_and_bulk_headers_are_exact(self) -> None:
        fixture = oracle.build_fixture()
        invitation_hex = fixture["artifacts"]["invitation_bytes"]["hex"]
        invitation = bytes.fromhex(invitation_hex)
        self.assertEqual(invitation[:4], b"ULI3")
        self.assertEqual(int.from_bytes(invitation[6:8], "big"), 172)
        bulk = bytes.fromhex(fixture["artifacts"]["bulk_asset_header"]["hex"])
        self.assertEqual(len(bulk), 64)
        self.assertEqual(bulk[:4], b"ULB3")

    def test_no_application_crypto_schedule_exists(self) -> None:
        source = oracle.Path(oracle.__file__).read_text(encoding="utf-8")
        forbidden = (
            "AESGCM",
            "X25519",
            "HKDF",
            "exporter",
            "epoch_probe",
            "path_challenge",
        )
        for token in forbidden:
            self.assertNotIn(token, source)


if __name__ == "__main__":
    unittest.main()
