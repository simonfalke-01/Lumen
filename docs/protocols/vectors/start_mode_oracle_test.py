#!/usr/bin/env python3
"""Tests for the language-neutral START/mode vector oracle."""

import unittest

import start_mode_oracle as oracle


class StartModeOracleTests(unittest.TestCase):
    def test_schema_and_mandatory_host_audio_are_exact(self) -> None:
        fixture = oracle.load_fixture()
        contract = fixture["contract"]
        self.assertEqual(fixture["schema"], "umbra-lumen-start-mode/1")
        self.assertEqual(contract["start_keys"], list(range(1, 19)))
        self.assertEqual(contract["host_audio_key"], 18)
        self.assertEqual(contract["host_audio_type"], "bool")
        for vector in fixture["vectors"]:
            self.assertIn("bitrate_kbps", vector)
            self.assertIn("presentation", vector)
            self.assertIn("microphone", vector)
            self.assertIn("host_audio", vector)

    def test_every_vector_matches_the_independent_oracle(self) -> None:
        fixture = oracle.load_fixture()
        ids = set()
        for vector in fixture["vectors"]:
            self.assertNotIn(vector["id"], ids)
            ids.add(vector["id"])
            self.assertEqual(
                oracle.admit(vector, fixture["contract"]),
                vector["expected"],
                vector["id"],
            )
        self.assertGreaterEqual(len(ids), 27)


if __name__ == "__main__":
    unittest.main()
