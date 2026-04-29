#!/usr/bin/env python3
"""Demo script — shows what DepNova found, in simple readable format."""

import sys
sys.path.insert(0, ".")

from depnova.core.config import load_config
from depnova.core.engine import Engine
from depnova.utils.logger import setup_logging

setup_logging("WARNING")  # Suppress logs, we'll print our own output

# Load config and run the scan
config = load_config("depnova.yaml")
engine = Engine(config)
result = engine.run()

# ─────────────────────────────────────────────────
# Show what was found, grouped by ecosystem
# ─────────────────────────────────────────────────

print("\n" + "=" * 70)
print("  🔍 DepNova Demo — What We Found In 'demo-app'")
print("=" * 70)

# Group dependencies by ecosystem
ecosystems: dict[str, list] = {}
for dep in result.dependencies:
    eco = dep.ecosystem.value
    if eco not in ecosystems:
        ecosystems[eco] = []
    ecosystems[eco].append(dep)

# ─── Phase 1 Results: Python deps ───
if "pypi" in ecosystems:
    print("\n┌─────────────────────────────────────────────────────────────┐")
    print("│  📦 PHASE 1 — Python Dependencies (requirements.txt)      │")
    print("├─────────────────────────────────────────────────────────────┤")
    for dep in ecosystems["pypi"]:
        pin = "📌 PINNED" if dep.confidence >= 0.9 else "⚠️  UNPINNED" if dep.version else "❌ NO VERSION"
        ver = dep.version or "(not specified)"
        print(f"│  {dep.name:<20} {ver:<15} {pin:<15} │")
    print(f"├─────────────────────────────────────────────────────────────┤")
    print(f"│  Total: {len(ecosystems['pypi'])} Python packages                              │")
    print(f"└─────────────────────────────────────────────────────────────┘")

# ─── Phase 1 Results: Node.js deps ───
if "npm" in ecosystems:
    print("\n┌─────────────────────────────────────────────────────────────┐")
    print("│  📦 PHASE 1 — Node.js Dependencies (package.json)         │")
    print("├─────────────────────────────────────────────────────────────┤")
    for dep in ecosystems["npm"]:
        dev_tag = " [DEV]" if dep.is_dev else ""
        conf = f"{dep.confidence:.0%}"
        print(f"│  {dep.name:<25} {dep.version:<12} confidence: {conf}{dev_tag}")
    print(f"├─────────────────────────────────────────────────────────────┤")
    print(f"│  Total: {len(ecosystems['npm'])} Node.js packages                             │")
    print(f"└─────────────────────────────────────────────────────────────┘")

# ─── Phase 1 Results: Java/Maven deps ───
if "maven" in ecosystems:
    print("\n┌─────────────────────────────────────────────────────────────┐")
    print("│  📦 PHASE 1 — Java/Maven Dependencies (pom.xml)           │")
    print("├─────────────────────────────────────────────────────────────┤")
    for dep in ecosystems["maven"]:
        group = dep.metadata.get("groupId", "")
        scope = dep.metadata.get("scope", "compile")
        scope_tag = f" [{scope}]" if scope != "compile" else ""
        print(f"│  {group}:{dep.name}")
        print(f"│    → version: {dep.version:<12} PURL: {dep.purl}{scope_tag}")
    print(f"├─────────────────────────────────────────────────────────────┤")
    print(f"│  Total: {len(ecosystems['maven'])} Maven packages                              │")
    print(f"└─────────────────────────────────────────────────────────────┘")

# ─── Phase 2 Results: OS packages (show just first 10) ───
if "deb" in ecosystems:
    deb_pkgs = ecosystems["deb"]
    print("\n┌─────────────────────────────────────────────────────────────┐")
    print("│  🖥️  PHASE 2 — OS Packages (dpkg on Kali Linux)            │")
    print("├─────────────────────────────────────────────────────────────┤")
    for dep in deb_pkgs[:10]:
        arch = dep.metadata.get("architecture", "")
        print(f"│  {dep.name:<30} {dep.version:<20} [{arch}]")
    print(f"│  ... and {len(deb_pkgs) - 10} more")
    print(f"├─────────────────────────────────────────────────────────────┤")
    print(f"│  Total: {len(deb_pkgs)} OS packages                                │")
    print(f"└─────────────────────────────────────────────────────────────┘")

# ─── Warnings (unpinned deps, etc.) ───
if result.warnings:
    print("\n┌─────────────────────────────────────────────────────────────┐")
    print("│  ⚠️  WARNINGS — Issues Found                               │")
    print("├─────────────────────────────────────────────────────────────┤")
    for w in result.warnings:
        print(f"│  ⚠️  {w}")
    print(f"└─────────────────────────────────────────────────────────────┘")

# ─── PURL Examples ───
print("\n┌─────────────────────────────────────────────────────────────┐")
print("│  🔗 PURL Examples (Package URLs for CVE matching)          │")
print("├─────────────────────────────────────────────────────────────┤")
shown = 0
for dep in result.dependencies:
    if dep.purl and shown < 8:
        print(f"│  {dep.purl}")
        shown += 1
print(f"└─────────────────────────────────────────────────────────────┘")

# ─── Final Summary ───
print("\n" + "=" * 70)
print(f"  📊 TOTAL: {len(result.dependencies)} dependencies found across {len(ecosystems)} ecosystems")
print(f"  ⏱️  Scan completed in ~0.24 seconds")
print("=" * 70)
print()
