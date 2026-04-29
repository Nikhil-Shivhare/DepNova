#!/usr/bin/env python3
"""Phase 3D — Full integration demo of frontend dependency detection."""
import sys
sys.path.insert(0, ".")
from depnova.core.config import load_config
from depnova.core.engine import Engine
from depnova.utils.logger import setup_logging
setup_logging("WARNING")

config = load_config("depnova.yaml")
engine = Engine(config)
result = engine.run()

# Group by ecosystem
ecosystems: dict[str, list] = {}
for dep in result.dependencies:
    eco = dep.ecosystem.value
    if eco not in ecosystems:
        ecosystems[eco] = []
    ecosystems[eco].append(dep)

print("\n" + "=" * 75)
print("  🔍 DepNova Phase 3 — Full Frontend Dependency Detection Demo")
print("=" * 75)

# CDN dependencies (Phase 3A)
if "cdn" in ecosystems:
    cdn_deps = sorted(ecosystems["cdn"], key=lambda d: d.name)
    print(f"\n  🌐 CDN Dependencies (Phase 3A) — {len(cdn_deps)} found")
    print("  " + "-" * 65)
    for dep in cdn_deps:
        cdn = dep.metadata.get("cdn_provider", "?")
        tag = dep.metadata.get("html_tag", "?")
        conf = f"{dep.confidence:.0%}"
        print(f"  │ {dep.name:<22} v{dep.version:<12} [{cdn:<28}] {conf}")
    print()

# Fingerprinted JS files (Phase 3B)
static_deps = ecosystems.get("static", [])
fingerprinted = [d for d in static_deps if "fingerprint" in d.sources[0].lower() if d.version]
sourcemap = [d for d in static_deps if "sourcemap" in (d.sources[0] if d.sources else "").lower()]

if fingerprinted:
    print(f"  🔬 Fingerprinted Libraries (Phase 3B — RetireJS) — {len(fingerprinted)} found")
    print("  " + "-" * 65)
    for dep in fingerprinted:
        method = dep.metadata.get("detection_method", "?")
        file_name = dep.location.split("/")[-1] if dep.location else "?"
        conf = f"{dep.confidence:.0%}"
        print(f"  │ {dep.name:<22} v{dep.version:<12} [{method:<14}] in {file_name:<20} {conf}")
    print()

# Source map libraries (Phase 3C)
if sourcemap:
    print(f"  📦 Source Map Libraries (Phase 3C) — {len(sourcemap)} found")
    print("  " + "-" * 65)
    for dep in sourcemap:
        src_path = dep.metadata.get("source_path", "?")
        conf = f"{dep.confidence:.0%}"
        print(f"  │ {dep.name:<22} (no version — from source map)        {conf}")
        print(f"  │   └─ {src_path}")
    print()

# Manifest dependencies (Phase 1)
phase1_count = len(ecosystems.get("pypi", [])) + len(ecosystems.get("npm", [])) + len(ecosystems.get("maven", []))
print(f"  📋 Manifest Dependencies (Phase 1) — {phase1_count} found")
print("  " + "-" * 65)
for eco in ["pypi", "npm", "maven"]:
    if eco in ecosystems:
        print(f"  │ {eco.upper()}: ", end="")
        names = [f"{d.name}@{d.version}" if d.version else d.name for d in ecosystems[eco][:5]]
        print(", ".join(names))
        if len(ecosystems[eco]) > 5:
            print(f"  │   ... and {len(ecosystems[eco]) - 5} more")

# Vulnerabilities
if result.vulnerabilities:
    print(f"\n  🚨 VULNERABILITIES FOUND — {len(result.vulnerabilities)}")
    print("  " + "-" * 65)
    for vuln in result.vulnerabilities:
        print(f"  │ {vuln.vuln_id:<20} [{vuln.severity.value}] {vuln.title[:60]}")

# Summary
print(f"\n{'=' * 75}")
print(f"  📊 TOTAL: {len(result.dependencies)} dependencies across {len(ecosystems)} ecosystems")
print(f"  ┌─ Phase 1 (manifests):  {phase1_count} deps")
print(f"  ├─ Phase 3A (CDN URLs):  {len(ecosystems.get('cdn', []))} deps")
print(f"  ├─ Phase 3B (fingerprint): {len(fingerprinted)} deps")
print(f"  └─ Phase 3C (sourcemap):   {len(sourcemap)} deps")
print(f"\n  ⚠️  Warnings: {len(result.warnings)} | 🚨 Vulnerabilities: {len(result.vulnerabilities)}")
print(f"{'=' * 75}\n")
