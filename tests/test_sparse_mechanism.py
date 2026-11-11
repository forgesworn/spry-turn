"""Check rejection and interpretation of the bounded sparse experiment."""
import importlib.util
import math
import os
from pathlib import Path
import platform
import random
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
spec = importlib.util.spec_from_file_location('mechanism', Path(__file__).resolve().parents[1] / 'scripts/sparse-mechanism.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def rows(deltas):
    result = []
    i = 0
    for pair, (stage, order) in enumerate(m.PLAN, 1):
        delta = deltas[i] if stage == 'source' else .0001
        i += stage == 'source'
        for arm in order:
            result.append(dict(pair=pair, stage=stage, arm=arm, seconds=40,
                offered=dict(cpu_ns=int((1 + (delta * 40 if arm == 'B' else 0)) * 1e9), timeslices=40000),
                validity_failures=[]))
    return result


class InterpretationTests(unittest.TestCase):
    def test_predeclared_stratified_randomisation_is_balanced(self):
        rng = random.Random(20261111)
        stages = []
        for _ in range(4):
            block = ['source', 'source', 'identical']; rng.shuffle(block); stages += block
        orders = {stage: iter(rng.sample(['AB'] * (n // 2) + ['BA'] * (n // 2), n))
                  for stage, n in [('source', 8), ('identical', 4)]}
        self.assertEqual(m.PLAN, [(stage, next(orders[stage])) for stage in stages])

    def test_below_reference_mean_does_not_claim_equivalence_or_qualification(self):
        result = m.analyse(rows([.0002] * 8))
        self.assertEqual(result['mean_diagnostic'], 'estimated_mean_below_budget')
        self.assertIsNone(result['qualification_pass'])
        self.assertFalse(result['equivalence_claim'])
        self.assertTrue(result['source_interval_excludes_zero'])
        self.assertEqual(len(result['identical_deltas']), 4)

    def test_identical_arms_select_the_same_exact_binary_and_ba_keeps_signed_delta(self):
        paths = dict(baseline='original', release='same-release')
        self.assertEqual(m.arm_binary(paths, 'source', 'A'), 'original')
        for stage, arm in [('source', 'B'), ('identical', 'A'), ('identical', 'B')]:
            self.assertEqual(m.arm_binary(paths, stage, arm), 'same-release')
        result = m.analyse(rows([-.001] * 8))
        self.assertTrue(all(pair['one_core_delta'] < 0 for pair in result['pairs'] if pair['stage'] == 'source'))

    def test_above_budget_and_inconclusive_intervals_stay_distinct(self):
        self.assertEqual(m.analyse(rows([.003] * 8))['mean_diagnostic'], 'estimated_mean_above_budget')
        result = m.analyse(rows([-.004, .008] * 4))
        self.assertEqual(result['mean_diagnostic'], 'mean_budget_unresolved')
        self.assertFalse(result['all_source_pairs_within_reference_budget'])
        self.assertAlmostEqual(result['source']['mean'], .002)

    def test_interval_uses_eight_paired_differences_and_df7(self):
        result = m.interval([0, .001] * 4)
        self.assertAlmostEqual(result['mean'], .0005)
        self.assertAlmostEqual(result['student_95'][1], .0005 + 2.364624251 * math.sqrt(8 * .0005 ** 2 / 7) / math.sqrt(8))
        for values in ([0] * 16, [0] * 7, [0] * 7 + [float('nan')]):
            with self.assertRaises(ValueError):
                m.interval(values)

    def test_missing_duplicate_and_invalid_rows_rejected(self):
        data = rows([0] * 8)
        for changed in (data[:-1], data + [data[0]], [dict(data[0], arm=data[1]['arm'])] + data[1:],
                        [dict(data[0], validity_failures=['bad'])] + data[1:]):
            with self.assertRaises(ValueError):
                m.analyse(changed)

    def test_only_single_positive_ir_summary_is_accepted(self):
        self.assertEqual(m.instruction_summary('events: Ir\nsummary: 1234\n'), 1234)
        for text in ('events: Ir\nsummary: 0\n', 'events: Ir\nsummary: -1\n',
                     'events: Ir Dr\nsummary: 1 2\n', 'events: Ir\nsummary: 2\nsummary: 3\n',
                     'events: Ir\n', 'summary: 123\n'):
            with self.assertRaises(m.diag.DiagnosticError):
                m.instruction_summary(text)


class CounterTests(unittest.TestCase):
    def test_context_switch_fields_are_required(self):
        with tempfile.TemporaryDirectory() as name:
            proc = Path(name)
            (proc / 'sys/kernel').mkdir(parents=True)
            (proc / 'sys/kernel/sched_schedstats').write_text('0')
            root = proc / '123'
            (root / 'task/123').mkdir(parents=True)
            (root / 'stat').write_text('123 (relay) S ' + '0 ' * 18 + '77')
            (root / 'schedstat').write_text('1000 0 3')
            status = root / 'status'
            status.write_text('voluntary_ctxt_switches: 7\nnonvoluntary_ctxt_switches: 2\n')
            snapshot = m.Observer(123, proc).snapshot('before_work')
            self.assertEqual(snapshot['voluntary_ctxt_switches'], 7)
            self.assertEqual(snapshot['nonvoluntary_ctxt_switches'], 2)
            status.write_text('voluntary_ctxt_switches: 7\n')
            with self.assertRaises(m.diag.DiagnosticError):
                m.Observer(123, proc).snapshot('before_work')


@unittest.skipUnless(os.environ.get('SPRY_DIAGNOSTIC_LOADER') and platform.system() == 'Linux',
                     'requires explicitly supplied Linux binaries')
class ProcessTests(unittest.TestCase):
    def test_real_process_completes_all_boundaries_and_counter_observations(self):
        relay = Path(os.environ.get('SPRY_TEST_RELAY_BINARY', 'target/release/spry-turn')).resolve()
        row = m.run(relay, Path(os.environ['SPRY_DIAGNOSTIC_LOADER']).resolve(), 1)
        self.assertEqual(row['round_trips'], 1)
        self.assertEqual(row['loss_or_corruption'], 0)
        self.assertEqual([x['phase'] for x in row['phase_snapshots']], list(m.diag.PHASES))
        self.assertGreater(row['offered']['cpu_ns'], 0)
        self.assertGreaterEqual(row['offered']['voluntary_ctxt_switches'], 0)


if __name__ == '__main__':
    unittest.main()
