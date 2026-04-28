# DepNova# DependencyTracker

Comprehensive dependency inventory and CVE scanning across backend, frontend, and OS packages.

## Problem

- No single tool (Syft, Trivy, etc.) provides 100% dependency coverage
- Frontend assets (CDN, bundled JS) are routinely missed
- Version accuracy degrades without lock files
- CVE matching becomes unreliable

## Solution

Multi-source dependency aggregation with runtime validation to produce a single, accurate SBOM.

## Approach

### Phase 1 — Lock File Extraction
Parse lock files for exact versions across ecosystems:
- JavaScript/TypeScript: `package-lock.json`, `yarn.lock`
- Python: `poetry.lock`, `Pipfile.lock`
- Java: `gradle.lockfile`, `pom.xml`

### Phase 2 — OS & Container Inventory
Generate SBOM from container image or filesystem using Syft.

### Phase 3 — Frontend Discovery
- Scan HTML for `<script>` and `<link>` tags
- Extract CDN URLs and versions
- Walk static assets (.js, .css) and fingerprint content
- Parse source maps for original library info
- Cross-reference with frontend `package.json`

### Phase 4 — Runtime Validation
Execute commands inside container/runtime to verify actual installed versions:
- `npm list --all --json`
- `pip freeze --all`
- `mvn dependency:tree`
- Binary inspection for non-package-manager artifacts

### Phase 5 — Merge & Deduplication
Combine all sources using conflict resolution hierarchy:
- Runtime validation > Lock file > Syft > Fingerprint
- Normalize versions and tag provenance
- Export unified CycloneDX 1.4 SBOM

### Phase 6 — Vulnerability Scanning
Scan final SBOM with Trivy or Grype for CVEs.

## Output

- Unified `dependency-inventory.json` with all components and exact versions
- `sbom.json` — CycloneDX 1.4 compliant
- `vulnerabilities.json` — CVE matches and risk assessment

## Usage

```bash
# Analyze built container
kilo tracker analyze-image --image myapp:latest --output ./reports

# Analyze running environment
kilo tracker analyze-runtime --target localhost:8080

# Generate CycloneDX SBOM
kilo tracker sbom --format cyclonedx-json
```
