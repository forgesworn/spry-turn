#!/usr/bin/env python3
"""Predeclared sparse source/noise experiment; never a qualification rerun."""
import argparse
import importlib.util
import json
import math
import os
from pathlib import Path
import platform
import queue
import shlex
import statistics
import subprocess
import tempfile
import threading
import time

from compare import Server, binary_identity, finish


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


diag = module('phase_diagnostics', 'sparse-diagnostics.py')
frozen = module('frozen_qualification', 'qualify-tcp.py')
PROFILE = dict(diag.PROFILE, packets=20000)
# Fixed before measurement. Seed 20261111; each three-pair stratum shuffled
# source/source/identical, then balanced orders independently shuffled by stage.
PLAN = [('source', 'AB'), ('identical', 'BA'), ('source', 'BA'),
        ('identical', 'AB'), ('source', 'AB'), ('source', 'BA'),
        ('source', 'AB'), ('identical', 'AB'), ('source', 'AB'),
        ('source', 'BA'), ('source', 'BA'), ('identical', 'BA')]


class Observer(diag.SchedulerObserver):
    def snapshot(self, phase):
        result = super().snapshot(phase)
        status = dict(line.split(':', 1) for line in (self.root / 'status').read_text().splitlines() if ':' in line)
        for name in ('voluntary_ctxt_switches', 'nonvoluntary_ctxt_switches'):
            value = status.get(name, '').strip()
            if not value.isdecimal():
                raise diag.DiagnosticError('missing context-switch counter')
            result[name] = int(value)
        return result


def run(binary, loader, packets, instrumented=False):
    fixture = Server(binary, coturn=False, tls=False)
    process = reader = None
    try:
        observer = None if instrumented else Observer(fixture.process.pid)
        observations = []
        command = [str(loader), f'127.0.0.1:{fixture.port}', '1', str(packets), '160', '1',
                   '--transport', 'tcp', '--workers', '1', '--rate', '500',
                   '--diagnostic-phases', '1', '--resource-hold-ms', '30000']
        process = subprocess.Popen(command, env={**os.environ, 'SPRY_TURN_SECRET': fixture.secret},
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True)
        output = queue.Queue(maxsize=len(diag.PHASES) + 1)
        def read_lines():
            for _ in range(len(diag.PHASES) + 1):
                line = process.stdout.readline(65537)
                output.put(line)
                if not line:
                    break
        reader = threading.Thread(target=read_lines, daemon=True)
        reader.start()
        deadline = time.monotonic() + 90
        def next_line():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise diag.DiagnosticError('mechanism workload exceeded finite timeout')
            try:
                return output.get(timeout=remaining)
            except queue.Empty:
                raise diag.DiagnosticError('mechanism workload exceeded finite timeout') from None
        def acknowledge():
            process.stdin.write('+'); process.stdin.flush()
        result, observations = diag.read_protocol(next_line, acknowledge,
            observer.snapshot if observer else lambda phase: dict(phase=phase))
        if process.poll() is not None:
            raise diag.DiagnosticError('loader exited before release')
        reader.join(timeout=1)
        if reader.is_alive():
            raise diag.DiagnosticError('reader did not finish')
        diag.release_loader(process)
        result['server_cpu_seconds'] = finish(fixture)
        if observer:
            result['phase_snapshots'] = observations
            result['phase_intervals'] = diag.phase_intervals(observations)
            before, after = observations[-2:]
            result['offered'] = {name: after[name] - before[name] for name in
                ('cpu_ns', 'timeslices', 'voluntary_ctxt_switches', 'nonvoluntary_ctxt_switches')}
            if any(value < 0 for value in result['offered'].values()):
                raise diag.DiagnosticError('mechanism counters regressed')
        return result
    finally:
        if process:
            if process.poll() is None:
                process.kill(); process.wait()
            if reader:
                reader.join(timeout=1)
            for stream in (process.stdin, process.stdout, process.stderr):
                stream.close()
        fixture.close()


def interval(values):
    """Descriptive 95% Student interval; eight pairs, no IID guarantee on one VM."""
    if len(values) != 8 or any(not math.isfinite(value) for value in values):
        raise ValueError('requires all eight finite source differences')
    mean = statistics.mean(values)
    half = 2.364624251 * statistics.stdev(values) / math.sqrt(8)
    return dict(mean=mean, median=statistics.median(values), minimum=min(values), maximum=max(values),
                sample_stdev=statistics.stdev(values), student_95=[mean - half, mean + half],
                interval_assumption='approximately normal independent paired errors; shared-VM dependence unverified')


def arm_binary(paths, stage, arm):
    if stage not in ('source', 'identical') or arm not in ('A', 'B'):
        raise ValueError('unknown mechanism arm')
    return paths['baseline'] if stage == 'source' and arm == 'A' else paths['release']


def analyse(rows):
    if len(rows) != len(PLAN) * 2:
        raise ValueError('requires exactly the predeclared rows')
    values = {'source': [], 'identical': []}
    differences = []
    for pair, (stage, order) in enumerate(PLAN, 1):
        arms = {row['arm']: row for row in rows if row['pair'] == pair}
        if set(arms) != {'A', 'B'} or any(row['stage'] != stage or row['validity_failures'] for row in arms.values()):
            raise ValueError('incomplete or invalid mechanism pair')
        a, b = arms['A'], arms['B']
        delta = b['offered']['cpu_ns'] / 1e9 / b['seconds'] - a['offered']['cpu_ns'] / 1e9 / a['seconds']
        values[stage].append(delta)
        differences.append(dict(pair=pair, stage=stage, order=order, one_core_delta=delta,
            cpu_ns=b['offered']['cpu_ns'] - a['offered']['cpu_ns'],
            timeslices=b['offered']['timeslices'] - a['offered']['timeslices']))
    summary = interval(values['source'])
    low, high = summary['student_95']
    # These labels describe this mean estimate only, never equivalence,
    # worst-pair acceptance, or a confidence bound validated for shared hosts.
    label = ('estimated_mean_above_budget' if low > .002 else
             'estimated_mean_below_budget' if high < .002 else 'mean_budget_unresolved')
    return dict(pairs=differences, source=summary, identical_deltas=values['identical'],
                mean_diagnostic=label, qualification_pass=None, equivalence_claim=False,
                source_interval_excludes_zero=low > 0 or high < 0,
                guard=.002, all_source_pairs_within_reference_budget=max(values['source']) <= .002)


def instruction_summary(text):
    events = [line.removeprefix('events: ').split() for line in text.splitlines() if line.startswith('events: ')]
    totals = [line.removeprefix('summary: ').split() for line in text.splitlines() if line.startswith('summary: ')]
    if events != [['Ir']] or len(totals) != 1 or len(totals[0]) != 1 or not totals[0][0].isdigit() or int(totals[0][0]) <= 0:
        raise diag.DiagnosticError('unsupported or empty Callgrind instruction summary')
    return int(totals[0][0])


def callgrind(binary, loader):
    with tempfile.TemporaryDirectory(prefix='spry-callgrind-') as temp:
        root = Path(temp)
        wrapper = root / 'relay'
        wrapper.write_text('#!/bin/sh\nexec valgrind --tool=callgrind --callgrind-out-file=' +
            shlex.quote(str(root / 'profile.%p')) + ' ' + shlex.quote(str(binary)) + ' "$@"\n')
        wrapper.chmod(0o700)
        row = run(wrapper, loader, 4000, instrumented=True)
        profiles = list(root.glob('profile.*'))
        if len(profiles) != 1:
            raise diag.DiagnosticError('missing or multiple Callgrind profiles')
        text = profiles[0].read_text()
        return dict(round_trips=row['round_trips'], loss_or_corruption=row['loss_or_corruption'],
            user_instructions=instruction_summary(text), scope='whole relay lifetime including setup and probes; excludes kernel instructions; timing perturbed',
            offered_schedule_misses=row['missed_dispatch_slots'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('baseline', 'release', 'loader', 'manifest', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    if platform.system() != 'Linux' or args.output.exists():
        parser.error('requires Linux and a fresh receipt')
    source = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    if subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=no'], text=True):
        parser.error('requires a clean measured revision')
    rustc = subprocess.check_output(['rustc', '--version'], text=True).strip()
    if not rustc.startswith('rustc 1.94.1 '):
        parser.error('requires pinned Rust 1.94.1')
    paths = {name: getattr(args, name).resolve() for name in ('baseline', 'release', 'loader')}
    identities = {name: binary_identity(path) for name, path in paths.items()}
    if any(value['architectures'] != ['x86_64'] for value in identities.values()):
        parser.error('requires native x86_64 Linux binaries')
    manifest = diag.validate_manifest(json.loads(args.manifest.read_text()), identities, source, rustc)
    for name in ('src', 'crates', 'Cargo.toml', 'Cargo.lock', 'examples/load.rs', 'scripts/qualify-tcp.py',
                 'scripts/compare.py', 'scripts/sparse-diagnostics.py', 'tests/interop.py',
                 'docs/tcp-hosted-qualification-2026-11-11.md', '.github/workflows/perf-tcp.yml'):
        subprocess.run(['git', 'diff', '--exit-code', diag.RELEASE if name != 'examples/load.rs' and name != 'scripts/sparse-diagnostics.py' else 'bda6cc30179d4ed645e2568542c3c56475c0cdf2', source, '--', name], check=True)
    script_paths = ['scripts/sparse-mechanism.py', 'scripts/sparse-diagnostics.py', 'scripts/compare.py',
                    'scripts/qualify-tcp.py', 'examples/load.rs', 'tests/interop.py',
                    '.github/workflows/sparse-diagnostics.yml', 'docs/sparse-cpu-mechanism-plan-2026-11-11.md']
    hashes = {name: diag.digest(name) for name in script_paths}
    receipt = dict(schema=1, kind='sparse-cpu-mechanism', source=source, qualification_pass=None,
        complete=False, builds=manifest, binaries=identities, scripts=hashes,
        method=dict(profile=PROFILE, plan=PLAN, reference_one_core_budget=.002,
                    no_replacement_rows=True, timing_scope='offered phase schedstat, not frozen lifetime guard'),
        host=dict(cpu=frozen.cpu_brand(), kernel=platform.release(), rustc=rustc,
                  affinity=sorted(os.sched_getaffinity(0))), runs=[], callgrind=[], failures=[])
    args.output.parent.mkdir(parents=True, exist_ok=True)
    def save():
        args.output.write_text(json.dumps(receipt, indent=2) + '\n')
    save()
    active = None
    try:
        for pair, (stage, order) in enumerate(PLAN, 1):
            for arm in order:
                active = dict(stage=stage, pair=pair, arm=arm)
                binary = arm_binary(paths, stage, arm)
                idle = frozen.idle_probe()
                before = frozen.snapshot()
                row = run(binary, paths['loader'], PROFILE['packets'])
                host = frozen.cpu_delta(before, frozen.snapshot())
                row.update(**active, idle_probe=idle, host_active=host,
                    validity_failures=frozen.host_failures(idle, host) + frozen.row_failures(row, PROFILE))
                receipt['runs'].append(row); save()
                print(json.dumps(dict(**active, offered=row['offered'], failures=row['validity_failures'])), flush=True)
                if row['validity_failures']:
                    raise diag.DiagnosticError('mechanism host or useful-work validity failed')
        receipt['analysis'] = analyse(receipt['runs']); save()
        receipt['valgrind_version'] = subprocess.check_output(['valgrind', '--version'], text=True).strip()
        for arm in 'ABBA':
            active = dict(stage='callgrind', arm=arm)
            row = callgrind(paths['baseline' if arm == 'A' else 'release'], paths['loader'])
            receipt['callgrind'].append(dict(**active, **row)); save()
            if row['round_trips'] != 4000 or row['loss_or_corruption']:
                raise diag.DiagnosticError('Callgrind useful-work mismatch')
        receipt['complete'] = True
    except Exception as error:
        receipt['failures'].append(dict(active=active, kind=type(error).__name__,
            reason=str(error) if isinstance(error, diag.DiagnosticError) else 'unexpected mechanism failure; inspect private job log'))
    finally:
        receipt['binaries_after'] = {name: binary_identity(path) for name, path in paths.items()}
        receipt['scripts_after'] = {name: diag.digest(name) for name in script_paths}
        if receipt['binaries_after'] != identities or receipt['scripts_after'] != hashes:
            receipt['failures'].append(dict(reason='input identities changed')); receipt['complete'] = False
        save()
    return 0 if receipt['complete'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
