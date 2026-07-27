#!/usr/bin/env python3

import json
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "tests" / "scenarios.json"
RUNNER = ROOT / "tests" / "exercise_runner.m"
SIM_HOST = ROOT / "sim_uitest" / "main.m"


class ScenarioManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.document = json.loads(MANIFEST.read_text(encoding="utf-8"))
        self.scenarios = self.document["scenarios"]

    def test_manifest_has_unique_stable_ids(self) -> None:
        ids = [item["id"] for item in self.scenarios]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertTrue(all(value.startswith("baseline.") for value in ids))

    def test_required_fields_and_platforms(self) -> None:
        allowed_platforms = {"mac", "sim", "device"}
        for item in self.scenarios:
            with self.subTest(item=item["id"]):
                self.assertIsInstance(item["trigger"], str)
                self.assertGreater(item["timeout_ms"], 0)
                self.assertTrue(set(item["platforms"]).issubset(allowed_platforms))
                self.assertIsInstance(item["expected_events"], list)

    def test_mac_scenarios_are_registered_in_runner(self) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        for item in self.scenarios:
            if "mac" in item["platforms"]:
                with self.subTest(item=item["id"]):
                    self.assertIn(f'"{item["id"]}"', source)

    def test_sim_scenarios_are_registered_in_test_app(self) -> None:
        source = SIM_HOST.read_text(encoding="utf-8")
        for item in self.scenarios:
            if "sim" in item["platforms"]:
                with self.subTest(item=item["id"]):
                    self.assertIn(f'@"{item["id"]}"', source)


if __name__ == "__main__":
    unittest.main()
