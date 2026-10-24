#!/usr/bin/env python3
"""Collect licences of resolved dependencies without committing local paths."""
import json
from pathlib import Path
import subprocess

root = Path(__file__).resolve().parents[1]
packages = {}
targets = [(platform, ["--all-features"]) for platform in
           ["aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "x86_64-unknown-linux-gnu"]]
targets.append(("wasm32-unknown-unknown", ["--no-default-features", "--features", "wasm"]))
for platform, features in targets:
    metadata = json.loads(subprocess.check_output(["cargo", "metadata", "--format-version", "1", "--locked", *features, "--filter-platform", platform], cwd=root))
    nodes = {n["id"]: n for n in metadata["resolve"]["nodes"]}
    # Native distributions can include the standalone service as well as the
    # relay. The browser codec only contains the root crate's dependency tree.
    pending = (metadata["workspace_members"][:] if platform != "wasm32-unknown-unknown"
               else [metadata["resolve"]["root"]]); active = set()
    while pending:
        node = pending.pop()
        if node in active: continue
        active.add(node); pending.extend(dep["pkg"] for dep in nodes[node]["deps"])
    packages.update({p["id"]: p for p in metadata["packages"] if p["id"] in active})
sections = ["Third-party dependencies for all features on macOS arm64 and Linux arm64/x86_64,\nand for the wasm feature on wasm32-unknown-unknown.\nOther targets require their own licence collection before distribution.\nRegenerate: python3 scripts/licences.py\n"]
for package in sorted(packages.values(), key=lambda p: (p["name"], p["version"])):
    if package["source"] is None: continue
    base = Path(package["manifest_path"]).parent
    files = set()
    for pattern in ["LICENSE*", "LICENCE*", "COPYING*", "COPYRIGHT*"]:
        files.update(p for p in base.rglob(pattern) if p.is_file())
    if package.get("license_file"):
        files.add(base / package["license_file"])
    if not files and (base / "AUTHORS").is_file():
        files.add(base / "AUTHORS")
    if not files: raise RuntimeError("missing licence files for " + package["name"])
    sections.append(f"\n{'=' * 72}\n{package['name']} {package['version']}\nSPDX: {package.get('license')}\n")
    for path in sorted(files):
        sections.append(f"\n--- {path.name} ---\n" + path.read_text(errors="replace"))
text = "\n".join(line.rstrip() for line in "\n".join(sections).splitlines()).rstrip() + "\n"
(root / "THIRD_PARTY_LICENSES.txt").write_text(text)
print(f"Collected {sum(p['source'] is not None for p in packages.values())} dependency notices")
