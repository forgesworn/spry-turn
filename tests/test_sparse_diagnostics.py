"""Protocol and proc-counter fixtures only; no relay load or measurements."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
spec = importlib.util.spec_from_file_location("diagnostics", Path(__file__).resolve().parents[1] / "scripts/sparse-diagnostics.py")
diag = importlib.util.module_from_spec(spec)
spec.loader.exec_module(diag)


def markers():
    return [json.dumps(dict(event="spry-load-phase-v1", phase=phase)) + "\n" for phase in diag.PHASES]


class ProtocolTests(unittest.TestCase):
    def test_observation_precedes_each_ack_and_final_result_is_unchanged(self):
        result = dict(round_trips=4000, seconds=7.998, scheduled_round_trip_p99_us=180)
        lines = iter(markers() + [json.dumps(result)])
        events = []
        def snapshot(phase):
            events.append(("observe", phase))
            return dict(phase=phase)
        measured, observations = diag.read_protocol(lambda: next(lines), lambda: events.append(("ack",)), snapshot)
        self.assertEqual(measured, result)
        self.assertEqual([x["phase"] for x in observations], list(diag.PHASES))
        self.assertEqual(events, [event for phase in diag.PHASES for event in (("observe", phase), ("ack",))])

    def test_no_ack_if_observation_fails(self):
        acks = []
        def fail(_):
            raise diag.DiagnosticError("scheduler runtime counters unavailable")
        with self.assertRaises(diag.DiagnosticError):
            diag.read_protocol(lambda: markers()[0], lambda: acks.append(True), fail)
        self.assertEqual(acks, [])

    def test_out_of_order_duplicate_missing_and_oversized_markers_fail(self):
        for lines in ([markers()[1]], [markers()[0], markers()[0]], [""],
                      ["x" * 65537], [json.dumps(dict(round_trips=4000))]):
            with self.subTest(lines=lines[:1]):
                source = iter(lines)
                with self.assertRaises(diag.DiagnosticError):
                    diag.read_protocol(lambda: next(source, ""), lambda: None, lambda phase: {})

    def test_invalid_and_missing_final_result_fail(self):
        for final in ("", "[]", '{"event":"unexpected"}', "x" * 65537):
            source = iter(markers() + [final])
            with self.assertRaises(diag.DiagnosticError):
                diag.read_protocol(lambda: next(source), lambda: None, lambda phase: {})

    def test_ack_failure_stops_before_next_phase(self):
        observed = []
        def acknowledge():
            raise BrokenPipeError()
        source = iter(markers())
        with self.assertRaises(BrokenPipeError):
            diag.read_protocol(lambda: next(source), acknowledge, lambda phase: observed.append(phase))
        self.assertEqual(observed, [diag.PHASES[0]])

    def test_phase_deltas_include_every_interval_and_reject_regression(self):
        rows = [dict(phase=phase, cpu_ns=100 + i * 30, runqueue_ns=i * 4, timeslices=1 + i)
                for i, phase in enumerate(diag.PHASES)]
        intervals = diag.phase_intervals(rows)
        self.assertEqual(len(intervals), 4)
        self.assertEqual([x["cpu_ns"] for x in intervals], [30] * 4)
        self.assertEqual(intervals[-1]["start"], "before_work")
        with self.assertRaises(diag.DiagnosticError):
            diag.phase_intervals(rows[:-1])
        rows[-1]["cpu_ns"] = 0
        with self.assertRaises(diag.DiagnosticError):
            diag.phase_intervals(rows)


class SchedulerFixtureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.proc = Path(self.temp.name)
        (self.proc / "sys/kernel").mkdir(parents=True)
        (self.proc / "sys/kernel/sched_schedstats").write_text("1")
        self.pid = self.proc / "123"
        (self.pid / "task/123").mkdir(parents=True)
        self.write_identity(77)
        (self.pid / "schedstat").write_text("1000 200 3\n")
        self.observer = diag.SchedulerObserver(123, self.proc)

    def tearDown(self):
        self.temp.cleanup()

    def write_identity(self, start):
        (self.pid / "stat").write_text("123 (relay with ) space) S " + "0 " * 18 + str(start))

    def test_single_thread_identity_and_monotonic_counters(self):
        first = self.observer.snapshot("before_setup")
        (self.pid / "schedstat").write_text("1200 210 4")
        last = self.observer.snapshot("after_setup")
        self.assertEqual(last["cpu_ns"] - first["cpu_ns"], 200)
        self.assertEqual(last["thread_count"], 1)
        self.assertGreaterEqual(last["observed_end_ns"], last["observed_start_ns"])

    def test_disabled_runqueue_is_unavailable_and_setting_changes_fail(self):
        (self.proc / "sys/kernel/sched_schedstats").write_text("0")
        first = self.observer.snapshot("before_setup")
        self.assertIsNone(first["runqueue_ns"])
        self.assertEqual(first["cpu_ns"], 1000)
        self.assertEqual(first["sched_schedstats"], 0)
        (self.proc / "sys/kernel/sched_schedstats").write_text("1")
        with self.assertRaisesRegex(diag.DiagnosticError, "setting changed"):
            self.observer.snapshot("after_setup")

    def test_thread_topology_rejected_instead_of_under_counting(self):
        (self.pid / "task/456").mkdir()
        with self.assertRaisesRegex(diag.DiagnosticError, "thread topology"):
            self.observer.snapshot("before_setup")

    def test_pid_reuse_rejected(self):
        self.observer.snapshot("before_setup")
        self.write_identity(78)
        with self.assertRaisesRegex(diag.DiagnosticError, "identity changed"):
            self.observer.snapshot("after_setup")

    def test_counter_regression_rejected_for_each_counter(self):
        self.observer.snapshot("before_setup")
        for text in ("999 200 3", "1000 199 3", "1000 200 2"):
            (self.pid / "schedstat").write_text(text)
            with self.assertRaisesRegex(diag.DiagnosticError, "regressed"):
                self.observer.snapshot("after_setup")

    def test_missing_disabled_and_malformed_counters_fail(self):
        for text in ("", "0 0 0", "1 2", "1 2 3 4", "-1 2 3", "1.5 2 3"):
            with self.subTest(text=text), self.assertRaises(diag.DiagnosticError):
                diag.parse_schedstat(text)
        (self.pid / "schedstat").unlink()
        with self.assertRaises(FileNotFoundError):
            self.observer.snapshot("before_setup")



class ProvenanceAndStreamTests(unittest.TestCase):
    def test_manifest_binds_all_builds_to_source_compiler_and_bytes(self):
        identities = {name: dict(sha256=name) for name in ("baseline", "release", "loader")}
        builds = {name: dict(source=sha, sha256=name, rustc="pinned", profile="release", features=["tls"], locked=True,
                            target="example:load" if name == "loader" else "bin:spry-turn")
                  for name, sha in dict(baseline=diag.BASELINE, release=diag.RELEASE, loader="loader-head").items()}
        manifest = dict(schema=1, builds=builds)
        diag.validate_manifest(manifest, identities, "loader-head", "pinned")
        for name in builds:
            for key in ("source", "sha256", "rustc", "profile", "features", "locked", "target"):
                altered = json.loads(json.dumps(manifest))
                altered["builds"][name][key] = "wrong"
                with self.subTest(name=name, key=key), self.assertRaises(diag.DiagnosticError):
                    diag.validate_manifest(altered, identities, "loader-head", "pinned")

    def test_prefetched_trailing_marker_rejected_by_same_reader(self):
        # Both lines arrive in one write, so readline may prefetch the tail.
        code = "import sys; sys.stdout.write('result\\ntrailing-marker\\n'); sys.stdout.flush(); sys.stdin.read(1)"
        with subprocess.Popen([sys.executable, "-c", code], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, text=True) as process:
            self.assertEqual(process.stdout.readline(), "result\n")
            with self.assertRaisesRegex(diag.DiagnosticError, "trailing output"):
                diag.release_loader(process)


@unittest.skipUnless(os.environ.get("SPRY_DIAGNOSTIC_LOADER"), "requires explicitly supplied built loader; no build in unit fixtures")
class LoaderBoundaryTests(unittest.TestCase):
    def start_loader(self):
        return subprocess.Popen([os.environ["SPRY_DIAGNOSTIC_LOADER"], "127.0.0.1:9", "1", "1", "160", "1",
                                 "--diagnostic-phases", "1"],
                                env={**os.environ, "SPRY_TURN_SECRET": "diagnostic-fixture-only-32-bytes-minimum"},
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    def test_all_phases_complete_and_disabled_mode_keeps_one_result(self):
        relay = Path(os.environ.get("SPRY_TEST_RELAY_BINARY", "target/release/spry-turn")).resolve()
        fixture = diag.Server(relay)
        try:
            base = [os.environ["SPRY_DIAGNOSTIC_LOADER"], f"127.0.0.1:{fixture.port}",
                    "1", "1", "160", "1", "--transport", "tcp"]
            enabled = subprocess.run(base + ["--diagnostic-phases", "1", "--resource-hold-ms", "1000"],
                env={**os.environ, "SPRY_TURN_SECRET": fixture.secret}, input="+++++\n",
                capture_output=True, text=True, timeout=10, check=True)
            rows = [json.loads(line) for line in enabled.stdout.splitlines()]
            self.assertEqual(rows[:-1], [json.loads(line) for line in markers()])
            self.assertEqual(rows[-1]["round_trips"], 1)
            self.assertEqual(rows[-1]["loss_or_corruption"], 0)
            disabled = subprocess.run(base, env={**os.environ, "SPRY_TURN_SECRET": fixture.secret},
                capture_output=True, text=True, timeout=10, check=True)
            ordinary = json.loads(disabled.stdout)
            self.assertEqual(set(ordinary), set(rows[-1]))
            self.assertEqual(ordinary["round_trips"], 1)
            self.assertEqual(ordinary["loss_or_corruption"], 0)
        finally:
            fixture.close()

    def test_invalid_ack_and_eof_fail_before_any_network_work(self):
        for response in ("?", ""):
            with self.subTest(response=response), self.start_loader() as process:
                output, error = process.communicate(response, timeout=8)
                self.assertNotEqual(process.returncode, 0)
                self.assertEqual(json.loads(output), dict(event="spry-load-phase-v1", phase="before_setup"))
                self.assertIn("load test failed", error)

    def test_missing_ack_times_out_before_any_network_work(self):
        with self.start_loader() as process:
            try:
                self.assertNotEqual(process.wait(timeout=8), 0)
                self.assertIn("diagnostic acknowledgement timed out", process.stderr.read())
                self.assertEqual(json.loads(process.stdout.read())["phase"], "before_setup")
            finally:
                if process.poll() is None:
                    process.kill(); process.wait()


if __name__ == "__main__":
    unittest.main()
