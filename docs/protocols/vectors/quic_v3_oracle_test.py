#!/usr/bin/env python3
"""Regression tests for the independent QUIC v3 oracle and checked-in fixture."""

from __future__ import annotations

import json
import struct
import unittest

import quic_v3_oracle as oracle


class QuicV3OracleTest(unittest.TestCase):
    @staticmethod
    def artifact_bytes(fixture: dict, name: str) -> bytes:
        return bytes.fromhex(fixture["artifacts"][name]["hex"])

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
        record = bytes.fromhex(fixture["artifacts"]["route_transport_telemetry"]["hex"])
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

    def test_compact_input_capability_is_server_advertised_only(self) -> None:
        fixture = oracle.build_fixture()
        artifacts = fixture["artifacts"]
        for name in ("client_hello", "pair_recovery_client_hello", "auth_client_hello"):
            fields = oracle.validate_control(
                bytes.fromhex(artifacts[name]["hex"]), "c2h"
            )
            self.assertEqual(fields[4], 0x17F)
            self.assertEqual(fields[4] & 0x200, 0)
        for name in ("server_hello", "pair_recovery_server_hello", "auth_server_hello"):
            fields = oracle.validate_control(
                bytes.fromhex(artifacts[name]["hex"]), "h2c"
            )
            self.assertEqual(fields[6], 0x37F)
            self.assertEqual(fields[6] & 0x200, 0x200)
        invitation = self.artifact_bytes(fixture, "invitation_bytes")
        self.assertEqual(int.from_bytes(invitation[160:168], "big"), 0x37F)

    def test_input_formats_pin_compatibility_and_exact_payload_boundaries(self) -> None:
        fixture = oracle.build_fixture()
        artifacts = fixture["artifacts"]
        self.assertEqual(
            artifacts["route_input_state"]["sha256"],
            "21705cbacc63ffeb6a5aa8fab3250e4b4c5d0e6014d6a0e86867d4921124b64e",
        )
        self.assertEqual(
            artifacts["input_format2_compatibility"]["hex"],
            artifacts["route_input_state"]["hex"],
        )
        self.assertEqual(
            artifacts["input_format2_compatibility"]["sha256"],
            artifacts["route_input_state"]["sha256"],
        )

        cases = {
            "input_format2_15_controllers_1104": (2, 15, 0, 1_104, 64),
            "input_format3_16_controllers_1040": (3, 16, 0, 1_040, 56),
            "input_format3_16_controllers_two_edges_1104": (3, 16, 2, 1_104, 56),
            "input_format3_touch_after_edge_ack_1072": (3, 16, 0, 1_072, 56),
        }
        session = bytes(range(0xC0, 0xD0))
        for name, (
            state_format,
            controllers,
            edges,
            payload_bytes,
            stride,
        ) in cases.items():
            record = bytes.fromhex(artifacts[name]["hex"])
            route, _, _, payload = oracle.validate_envelope(
                record, "c2h", session, 1_152
            )
            self.assertEqual(route, "input-state")
            self.assertEqual(len(payload), payload_bytes)
            state_length, edge_count, wrapper_format = struct.unpack(
                ">HHH", payload[16:22]
            )
            self.assertEqual((edge_count, wrapper_format), (edges, state_format))
            state = payload[32 : 32 + state_length]
            self.assertEqual(state[84], controllers)
            self.assertEqual(state[87], 3 if state_format == 3 else 0)
            self.assertEqual(
                state_length,
                112 + controllers * stride + (32 if name.endswith("1072") else 0),
            )
            oracle.validate_input_state(state, state_format)

    def test_compact_input_preserves_sixteen_heterogeneous_controller_records(
        self,
    ) -> None:
        fixture = oracle.build_fixture()
        record = self.artifact_bytes(fixture, "input_format3_16_controllers_1040")
        payload = record[44:]
        state_length = int.from_bytes(payload[16:18], "big")
        state = payload[32 : 32 + state_length]
        self.assertEqual(int.from_bytes(state[80:84], "big"), 0xFFFF)
        records = [state[112 + index * 56 : 168 + index * 56] for index in range(16)]
        self.assertEqual([record[0] for record in records], list(range(16)))
        self.assertEqual(
            [record[1] for record in records],
            [1 + index % 5 for index in range(16)],
        )
        self.assertEqual(len({record[2:56] for record in records}), 16)

    def test_input_budget_is_edges_before_dirty_touches_without_oversize(self) -> None:
        fixture = oracle.build_fixture()
        contract = fixture["input_contract"]
        self.assertEqual(
            contract["budget_order"],
            [
                "all-active-controllers",
                "largest-contiguous-edge-prefix",
                "dirty-touch-updates",
            ],
        )
        edge_record = self.artifact_bytes(
            fixture, "input_format3_16_controllers_two_edges_1104"
        )[44:]
        edge_state_length, edge_count = struct.unpack(">HH", edge_record[16:20])
        self.assertEqual((edge_count, edge_record[32 + 85]), (2, 0))
        first_edge = 32 + edge_state_length
        self.assertEqual(
            [
                int.from_bytes(
                    edge_record[first_edge + index * 32 : first_edge + index * 32 + 8],
                    "big",
                )
                for index in range(2)
            ],
            [1, 2],
        )

        touch_record = self.artifact_bytes(
            fixture, "input_format3_touch_after_edge_ack_1072"
        )[44:]
        _, touch_edge_count = struct.unpack(">HH", touch_record[16:20])
        self.assertEqual((touch_edge_count, touch_record[32 + 85]), (0, 1))
        self.assertEqual(len(edge_record), 1_104)
        self.assertEqual(len(touch_record), 1_072)

    def test_old_host_degrades_nonterminally_without_advancing_state(self) -> None:
        contract = oracle.build_fixture()["input_contract"]
        negotiation = contract["negotiation"]
        self.assertEqual(negotiation["selected_format_without_0x200"], 2)
        self.assertEqual(negotiation["selected_format_with_0x200"], 3)
        old_host = next(
            case
            for case in contract["cases"]
            if case["id"] == "old-host-15-controller-pending-edge"
        )
        self.assertEqual(old_host["would_be_payload_bytes"], 1_136)
        self.assertFalse(old_host["emitted"])
        self.assertFalse(old_host["state_sequence_advanced"])
        self.assertEqual(old_host["outcome"], "nonterminal-degradation")

    def test_rebind_generation_rejects_stale_and_accepts_current_feedback(self) -> None:
        fixture = oracle.build_fixture()
        contract = fixture["input_contract"]["generation_rebind"]
        self.assertEqual(
            (contract["first_generation"], contract["rebound_generation"]), (1, 2)
        )
        self.assertEqual(
            (
                contract["stale_feedback_generation"],
                contract["accepted_feedback_generation"],
            ),
            (1, 2),
        )
        state_record = self.artifact_bytes(fixture, contract["state_artifact"])
        _, _, _, state_payload = oracle.validate_envelope(
            state_record, "c2h", bytes(range(0xC0, 0xD0)), 1_152
        )
        state_length = int.from_bytes(state_payload[16:18], "big")
        arrival = state_payload[32 + state_length :]
        self.assertEqual((arrival[16], arrival[17]), (4, 0))
        self.assertEqual(int.from_bytes(arrival[:8], "big"), 17)
        feedback = self.artifact_bytes(fixture, contract["feedback_artifact"])
        _, _, _, feedback_payload = oracle.validate_envelope(
            feedback, "h2c", bytes(range(0xC0, 0xD0)), 1_152
        )
        self.assertEqual(struct.unpack(">II", feedback_payload[:8]), (1, 2))

    def test_input_hostiles_cover_format_cap_and_edge_prefix_fail_closed(self) -> None:
        fixture = oracle.build_fixture()
        hostiles = {item["name"]: item for item in fixture["hostile"]}
        required = {
            "input-format3-wrapper-marker2",
            "input-format2-wrapper-marker3",
            "input-edge-format3-rejected",
            "input-format2-15-plus-edge-1136",
            "input-format3-payload-1109",
            "input-format3-noncontiguous-edge-prefix",
            "input-format3-touch-before-edge-budget",
        }
        self.assertLessEqual(required, set(hostiles))
        oversized = bytes.fromhex(
            hostiles["input-format3-payload-1109"]["candidate_hex"]
        )
        self.assertEqual(len(oversized) - 44, 1_109)
        self.assertEqual(hostiles["input-format3-payload-1109"]["expected"], "reject")

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
