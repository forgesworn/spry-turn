"""Guard regressions for the control-request protocol; no socket traffic or measurements."""
import copy
import importlib.util
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
spec = importlib.util.spec_from_file_location("qualify_control", Path(__file__).resolve().parents[1] / "scripts/qualify-control.py")
control = importlib.util.module_from_spec(spec)
spec.loader.exec_module(control)


def row(profile, arm="parent", pair=1, cpu=0.15):
    return dict(server=arm, pair=pair, mode=profile["mode"], sources=profile["sources"], requests=profile["requests"],
                setup_requests=profile["sources"], offered_requests_per_second=profile["rate"],
                answered=profile["requests"], unanswered=0, stale_responses=0, missed_dispatch_slots=0,
                seconds=(profile["requests"] - 1) / profile["rate"] + 0.0001, server_cpu_seconds=cpu,
                cpu_seconds_per_request=cpu / (profile["requests"] + profile["sources"]), round_trip_p99_us=60)


def rows(profile):
    return [row(profile, arm, pair) for pair in range(1, 5) for arm in ("parent", "candidate")]


class ControlQualificationTests(unittest.TestCase):
    def test_symmetric_measurements_pass(self):
        for profile in control.PROFILES:
            self.assertEqual(control.row_failures(row(profile), profile), [])
            self.assertTrue(control.evaluate_profile(rows(profile))["pass"])

    def test_one_adverse_pair_fails_the_cpu_guard(self):
        profile = control.PROFILES[1]
        data = rows(profile)
        # 30 s of phase wall: 0.09 s more CPU adds 0.003 of one core.
        data[3]["server_cpu_seconds"] += 0.09
        result = control.evaluate_profile(data)
        self.assertFalse(result["pass"])
        self.assertIn("control-request absolute CPU overhead guard", result["failures"])

    def test_overhead_within_the_bound_passes(self):
        profile = control.PROFILES[0]
        data = rows(profile)
        data[1]["server_cpu_seconds"] += 0.03
        self.assertTrue(control.evaluate_profile(data)["pass"])

    def test_unanswered_or_stale_requests_invalidate_the_row(self):
        profile = control.PROFILES[0]
        for key, value in (("answered", profile["requests"] - 1), ("unanswered", 1), ("stale_responses", 1)):
            bad = row(profile)
            bad[key] = value
            self.assertIn("useful work mismatch", control.row_failures(bad, profile))

    def test_schedule_failures_are_reported(self):
        profile = control.PROFILES[0]
        late = row(profile)
        late["missed_dispatch_slots"] = profile["requests"] // 50
        self.assertIn("probe missed offered schedule", control.row_failures(late, profile))
        slow = row(profile)
        slow["seconds"] *= 1.05
        self.assertIn("probe elapsed time outside offered schedule", control.row_failures(slow, profile))

    def test_missing_arms_are_not_evaluated(self):
        profile = control.PROFILES[0]
        data = rows(profile)
        self.assertFalse(control.evaluate_profile(data[:-1])["pass"])
        swapped = copy.deepcopy(data)
        swapped[1]["server"] = "parent"
        self.assertFalse(control.evaluate_profile(swapped)["pass"])

    def test_profiles_stay_inside_every_budget(self):
        # The probe must measure ordinary traffic, not refusals: 2,000 a second
        # is the smallest shared budget in either arm, and 5 a second the
        # unverified allowance for one source.
        for profile in control.PROFILES:
            self.assertLess(profile["rate"], 2000)
            self.assertLessEqual(profile["rate"] / profile["sources"], 1)


if __name__ == "__main__":
    unittest.main()
