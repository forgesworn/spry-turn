"""Guard and protocol regressions; no socket traffic or performance measurements."""
import copy
import importlib.util
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
spec = importlib.util.spec_from_file_location("qualification", Path(__file__).resolve().parents[1] / "scripts/qualify-tcp.py")
qualification = importlib.util.module_from_spec(spec)
spec.loader.exec_module(qualification)


def rows():
    return [dict(server=arm, pair=pair, packets_per_second=100000,
                 cpu_seconds_per_verified_forward=0.00001,
                 loaded_rss_bytes=8_000_000, peak_sampled_rss_bytes=10_000_000,
                 loaded_round_trip_p99_us=100, scheduled_round_trip_p99_us=200,
                 seconds=8, server_cpu_seconds=0.1)
            for pair in range(1, 5) for arm in ("parent", "candidate")]


class QualificationTests(unittest.TestCase):
    def test_symmetric_measurements_pass(self):
        for profile in qualification.PROFILES:
            self.assertTrue(qualification.evaluate_profile(rows(), profile)["pass"])

    def test_adverse_control_and_worst_pair_are_not_hidden(self):
        data = rows()
        data[1]["packets_per_second"] *= 0.5
        result = qualification.evaluate_profile(data, qualification.PROFILES[2])
        self.assertIn("throughput guard", result["failures"])
        self.assertEqual(result["metrics"]["packets_per_second"]["median_ratio"], 1)
        data = rows()
        data[1]["cpu_seconds_per_verified_forward"] *= 1.2
        self.assertIn("CPU per verified forward guard", qualification.evaluate_profile(data, qualification.PROFILES[0])["failures"])

    def test_sparse_cpu_uses_absolute_utilisation_not_ratio(self):
        data = rows()
        for row in data:
            row["server_cpu_seconds"] = 0.001 if row["server"] == "parent" else 0.002
            row["cpu_seconds_per_verified_forward"] = row["server_cpu_seconds"] / 8000
        profile = qualification.PROFILES[-1]
        self.assertTrue(qualification.evaluate_profile(data, profile)["pass"])
        data[1]["server_cpu_seconds"] = 0.1
        self.assertIn("sparse absolute CPU overhead guard", qualification.evaluate_profile(data, profile)["failures"])

    def test_sparse_latency_and_incomplete_profiles_fail(self):
        profile = qualification.PROFILES[-1]
        data = rows()
        data[1]["scheduled_round_trip_p99_us"] = 1000
        self.assertIn("fixed-rate scheduled p99 guard", qualification.evaluate_profile(data, profile)["failures"])
        self.assertFalse(qualification.evaluate_profile(data[:-1], profile)["pass"])

    def test_sparse_missed_deadlines_reject_coordinated_omission(self):
        profile = qualification.PROFILES[-1]
        row = dict(round_trips=4000, loss_or_corruption=0, offered_round_trips_per_second=500,
                   missed_dispatch_slots=41, loaded_latency_observations=4000, seconds=8)
        self.assertIn("sparse sender missed offered schedule", qualification.row_failures(row, profile))
        row["missed_dispatch_slots"] = 0
        self.assertEqual(qualification.row_failures(row, profile), [])

    def test_host_noise_and_steal_are_binding(self):
        idle = dict(idle_fraction=0.99, steal_fraction=0, scheduler_p99_ms=1, scheduler_max_ms=2)
        self.assertFalse(qualification.host_failures(idle, {"steal_fraction": 0}))
        self.assertTrue(qualification.host_failures(idle, {"steal_fraction": 0.006}))
        idle["idle_fraction"] = 0.5
        self.assertTrue(qualification.host_failures(idle, {"steal_fraction": 0}))

    def test_pilot_freezes_six_second_counts_and_caps_work(self):
        count = qualification.pilot_count({"seconds": 2, "server_cpu_seconds": 1})
        self.assertEqual(count, 3_000_064)
        with self.assertRaises(ValueError):
            qualification.pilot_count({"seconds": 0.01, "server_cpu_seconds": 0.01})
        profile = copy.deepcopy(qualification.PROFILES[0])
        row = dict(round_trips=profile["packets"], loss_or_corruption=0,
                   offered_round_trips_per_second=0, seconds=5, server_cpu_seconds=2)
        self.assertIn("loaded CPU or wall interval below minimum", qualification.row_failures(row, profile))


if __name__ == "__main__":
    unittest.main()
