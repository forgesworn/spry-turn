#!/usr/bin/env python3
"""Check the source reconstruction without building or changing a checkout."""

import hashlib
import json
from pathlib import Path
import statistics
import subprocess
import tempfile


HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def require(condition, message):
    if not condition:
        raise SystemExit(message)


def base_file(commit, name):
    return subprocess.check_output(["git", "-C", str(REPO), "show", f"{commit}:{name}"])


def apply(root, name):
    patch = HERE / name
    subprocess.run(
        ["git", "apply", "--check", "--whitespace=error-all", str(patch)],
        cwd=root, check=True,
    )
    subprocess.run(["git", "apply", str(patch)], cwd=root, check=True)


def check_format(root):
    subprocess.run(
        ["rustfmt", "--check", "--edition", "2024", str(root / "src/turn.rs")],
        check=True,
    )


def main():
    manifest = json.loads((HERE / "manifest.json").read_text())
    for name, expected in manifest["patches"].items():
        data = (HERE / name).read_bytes()
        require(len(data) == expected["bytes"], f"Size mismatch: {name}")
        require(digest(data) == expected["sha256"], f"Hash mismatch: {name}")
    for name, expected in manifest["unchanged_build_inputs"].items():
        data = base_file(manifest["base_commit"], name)
        require(len(data) == expected["bytes"], f"Base size mismatch: {name}")
        require(digest(data) == expected["sha256"], f"Base hash mismatch: {name}")

    with tempfile.TemporaryDirectory(prefix="spry-buffer-source-check-") as temporary:
        root = Path(temporary)
        (root / "src").mkdir()
        for name in ("Cargo.toml", "src/turn.rs"):
            (root / name).write_bytes(base_file(manifest["base_commit"], name))
        parent_source = None
        for stage in manifest["stages"]:
            apply(root, stage["patch"])
            for name, expected in stage["files"].items():
                require(digest((root / name).read_bytes()) == expected,
                        f"Reconstruction mismatch after {stage['patch']}: {name}")
            check_format(root)
            if stage["patch"] == "baseline.patch":
                parent_source = (root / "src/turn.rs").read_bytes()
        require(parent_source is not None, "Missing parent stage")
        (root / "src/turn.rs").write_bytes(parent_source)
        regression = manifest["parent_regression"]
        apply(root, regression["patch"])
        require(digest((root / "src/turn.rs").read_bytes()) == regression["turn_sha256"],
                "Parent regression reconstruction mismatch")
        check_format(root)

    results = json.loads((HERE / "results.json").read_text())
    require(sum(row["verified_forwards"] for row in results["rows"])
            == results["verified_payload_forwards"], "Verified-forward total mismatch")
    require(len(results["rows"]) == 10, "Expected two controls and eight timed rows")
    timed = [row for row in results["rows"] if row["phase"] == "rows"]
    require(len(timed) == 8, "Expected eight timed rows")
    for row in results["rows"]:
        require(row["status"] == "passed" and row["loss_or_corruption"] == 0,
                "Recorded row failed delivery")
        require(row["loaded_latency_retained"] > 0, "Missing latency samples")
        if row["phase"] == "rows":
            require(row["round_trips"] >= results["workload"]["loaded_round_trip_floor"]
                    and row["loaded_seconds"] >= results["workload"]["minimum_loaded_seconds"],
                    "Incomplete saturated row")
    for name, metric in results["metrics"].items():
        ratios = metric["four_ratios"]
        require(len(ratios) == 4, f"Missing paired ratio: {name}")
        field = "p99_us" if name == "loaded_round_trip_p99_us" else name
        for pair_index in range(4):
            pair = {row["arm"]: row for row in timed[2 * pair_index:2 * pair_index + 2]}
            observed = pair["candidate"][field] / pair["original"][field]
            require(abs(observed - ratios[pair_index]) < 1e-12,
                    f"Row ratio mismatch: {name}, pair {pair_index + 1}")
        require(statistics.median(ratios) == metric["median"], f"Median mismatch: {name}")
        require(abs((metric["median"] - 1) * 100 - metric["median_percent_change"]) < 1e-12,
                f"Percentage mismatch: {name}")
        if name == "packets_per_second":
            gate = results["acceptance"]["saturated_throughput_ratio"]
            passed = metric["median"] >= gate["median_min"] and min(ratios) >= gate["each_pair_min"]
        else:
            key = "p99_ratio" if name == "loaded_round_trip_p99_us" else "cpu_and_rss_ratio"
            gate = results["acceptance"][key]
            passed = metric["median"] <= gate["median_max"] and max(ratios) <= gate["each_pair_max"]
        require(passed and metric["passed_screen"], f"Screen guard failed: {name}")
    require(results["metrics"]["loaded_rss_bytes"]["median"]
            <= results["acceptance"]["memory_optimisation_loaded_rss_ratio_median_max"],
            "Memory improvement guard failed")
    print("PASS: exact source chain, parent regression, formatting and result arithmetic")
    print("No build, native test or benchmark was run by this check.")


if __name__ == "__main__":
    main()
