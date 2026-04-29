"""Data models for DepNova dependency tracking.

All dependency data flows through these models. Every plugin produces
and consumes DependencyGraph objects, making the pipeline composable.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class Ecosystem(str, Enum):
    """Supported package ecosystems.

    Using str mixin so values serialize cleanly to JSON/YAML.
    """

    NPM = "npm"
    YARN = "yarn"
    PNPM = "pnpm"
    PYPI = "pypi"
    MAVEN = "maven"
    GRADLE = "gradle"
    CARGO = "cargo"
    GO = "golang"
    NUGET = "nuget"
    COMPOSER = "composer"
    OS_DPKG = "deb"
    OS_RPM = "rpm"
    OS_APK = "apk"
    CDN = "cdn"
    STATIC = "static"
    UNKNOWN = "unknown"


class SourceType(str, Enum):
    """How a dependency was discovered — used for provenance tagging."""

    LOCKFILE = "lockfile"
    MANIFEST = "manifest"
    SYFT = "syft"
    OS_QUERY = "os-query"
    FRONTEND_HTML = "frontend-html"
    CDN_URL = "cdn-url"
    FINGERPRINT = "fingerprint"
    SOURCEMAP = "sourcemap"
    RUNTIME_NPM = "runtime-npm"
    RUNTIME_PIP = "runtime-pip"
    RUNTIME_MAVEN = "runtime-maven"
    BINARY_INSPECT = "binary-inspect"
    MANUAL = "manual"
    UNKNOWN = "unknown"


class Severity(str, Enum):
    """Vulnerability severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    NONE = "none"


# ---------------------------------------------------------------------------
# Confidence scores — how much we trust a version number
# ---------------------------------------------------------------------------

class ConfidenceLevel:
    """Pre-defined confidence scores for different discovery methods.

    Higher = more trustworthy.  Scale is 0.0 → 1.0.
    """

    VERIFIED = 0.99      # Runtime-validated (pip freeze, npm list)
    LOCKED = 0.95        # From a lock file with pinned hash
    SCANNED = 0.85       # From Syft / container SBOM
    FINGERPRINTED = 0.70 # SHA-256 hash match against known library
    MANIFEST = 0.50      # From manifest with version range (e.g. ^1.2.0)
    INFERRED = 0.30      # From manifest without version
    GUESSED = 0.15       # Heuristic extraction (strings on binary)
    UNKNOWN = 0.05       # No version information at all


# ---------------------------------------------------------------------------
# Core data classes
# ---------------------------------------------------------------------------

@dataclass
class Dependency:
    """A single dependency component.

    Attributes:
        name:        Package name (e.g. "lodash", "requests")
        version:     Resolved version string (e.g. "4.17.21")
        ecosystem:   Which ecosystem this belongs to
        purl:        Package URL (pkg:npm/lodash@4.17.21)
        is_direct:   True if directly declared, False if transitive
        is_dev:      True if dev/test dependency
        confidence:  How confident we are in the version (0.0-1.0)
        sources:     List of SourceTypes that discovered this dep
        license_id:  SPDX license identifier (e.g. "MIT", "Apache-2.0")
        hash_sha256: SHA-256 of the package artifact, if available
        cpe:         CPE identifier for CVE matching
        location:    File path or URL where this dep was found
        metadata:    Arbitrary extra data from plugins
    """

    name: str
    version: str
    ecosystem: Ecosystem
    purl: str

    is_direct: bool = True
    is_dev: bool = False
    confidence: float = ConfidenceLevel.UNKNOWN
    sources: list[str] = field(default_factory=list)
    license_id: Optional[str] = None
    hash_sha256: Optional[str] = None
    cpe: Optional[str] = None
    location: Optional[str] = None
    metadata: dict = field(default_factory=dict)

    def add_source(self, source: str | SourceType) -> None:
        """Add a provenance source, avoiding duplicates."""
        val = source.value if isinstance(source, SourceType) else source
        if val not in self.sources:
            self.sources.append(val)

    @property
    def unique_key(self) -> str:
        """PURL-based unique key for deduplication."""
        return self.purl if self.purl else f"{self.ecosystem.value}:{self.name}@{self.version}"

    def __repr__(self) -> str:
        return f"Dependency({self.purl or self.name}@{self.version})"


@dataclass
class Vulnerability:
    """A CVE or advisory matched to a dependency.

    Attributes:
        vuln_id:      CVE ID or advisory ID (e.g. "CVE-2021-44228")
        severity:     Severity level
        score:        CVSS score (0.0-10.0)
        title:        Short description
        description:  Full description
        fix_version:  Version that fixes this vulnerability, if known
        source:       Database source (e.g. "nvd", "osv", "ghsa")
        url:          Link to advisory
        dependency_purl: PURL of the affected dependency
    """

    vuln_id: str
    severity: Severity
    score: float = 0.0
    title: str = ""
    description: str = ""
    fix_version: Optional[str] = None
    source: str = ""
    url: str = ""
    dependency_purl: str = ""


@dataclass
class DependencyGraph:
    """Container for all discovered dependencies from a plugin or merged result.

    This is the primary data structure that flows through the pipeline.
    Each plugin produces a DependencyGraph; the merger combines them.

    Attributes:
        dependencies:   List of discovered dependencies
        vulnerabilities: List of matched vulnerabilities (populated in Phase 6)
        errors:         Non-fatal errors encountered during scanning
        warnings:       Warnings (e.g. unpinned versions, missing lock files)
        source_plugin:  Name of the plugin that produced this graph
        metadata:       Plugin-specific metadata
    """

    dependencies: list[Dependency] = field(default_factory=list)
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    source_plugin: str = ""
    metadata: dict = field(default_factory=dict)

    def add_dependency(self, dep: Dependency) -> None:
        """Add a dependency to the graph."""
        self.dependencies.append(dep)

    def add_error(self, message: str) -> None:
        """Record a non-fatal error."""
        self.errors.append(message)

    def add_warning(self, message: str) -> None:
        """Record a warning."""
        self.warnings.append(message)

    @property
    def dependency_count(self) -> int:
        return len(self.dependencies)

    @property
    def has_errors(self) -> bool:
        return len(self.errors) > 0

    def get_dependencies_by_ecosystem(self, ecosystem: Ecosystem) -> list[Dependency]:
        """Filter dependencies by ecosystem."""
        return [d for d in self.dependencies if d.ecosystem == ecosystem]

    def get_purls(self) -> set[str]:
        """Get all unique PURLs in this graph."""
        return {d.purl for d in self.dependencies if d.purl}

    def merge_from(self, other: DependencyGraph) -> None:
        """Merge another graph into this one (simple append, no dedup)."""
        self.dependencies.extend(other.dependencies)
        self.vulnerabilities.extend(other.vulnerabilities)
        self.errors.extend(other.errors)
        self.warnings.extend(other.warnings)

    def summary(self) -> dict:
        """Return a summary dict for logging/reporting."""
        ecosystems: dict[str, int] = {}
        for dep in self.dependencies:
            eco = dep.ecosystem.value
            ecosystems[eco] = ecosystems.get(eco, 0) + 1

        return {
            "total_dependencies": self.dependency_count,
            "ecosystems": ecosystems,
            "errors": len(self.errors),
            "warnings": len(self.warnings),
            "vulnerabilities": len(self.vulnerabilities),
            "source_plugin": self.source_plugin,
        }
