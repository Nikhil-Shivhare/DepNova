"""JS Fingerprinter plugin — Phase 3B.

Identifies JavaScript libraries by analyzing file contents and matching
against the RetireJS vulnerability database. Uses three detection layers:

    Layer 1: File content pattern matching (RetireJS `filecontent` extractors)
    Layer 2: Filename pattern matching (RetireJS `filename`/`uri` extractors)
    Layer 3: SHA-256 hash matching (RetireJS `hashes` extractor)

The RetireJS database (jsrepository.json) is downloaded and cached locally.
It covers 70+ popular JS libraries including jQuery, React, Angular, Vue,
Lodash, Moment.js, Bootstrap, D3, etc.

Config example:
    - plugin: "js_fingerprinter"
      enabled: true
      config:
        use_retirejs_db: true
        retirejs_repo_url: "https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository.json"
        cache_dir: "~/.depnova/cache"
        cache_ttl_hours: 24
        scan_sourcemaps: true
        include_vulnerabilities: true
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from pathlib import Path
from typing import Any, Optional

from depnova.core.models import (
    ConfidenceLevel,
    Dependency,
    DependencyGraph,
    Ecosystem,
    SourceType,
    Vulnerability,
    Severity,
)
from depnova.core.purl import generate_purl
from depnova.plugins.base import BasePlugin, PipelineContext
from depnova.utils.logger import get_logger

log = get_logger(__name__)

# Default RetireJS repository URL
_DEFAULT_RETIREJS_URL = (
    "https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository.json"
)

# The §§version§§ placeholder in RetireJS patterns gets replaced with this
_VERSION_CAPTURE = r"([\d]+\.[\d]+\.[\d]+[a-zA-Z0-9._\-]*)"


class JSFingerprinter(BasePlugin):
    """Identifies JS libraries by content fingerprinting using RetireJS DB.

    Detection layers (in order of accuracy):
        1. filecontent — regex patterns matching version strings inside JS files
        2. filename — regex patterns matching version in filenames
        3. hashes — SHA-256 hash lookup against known library hashes

    Config options:
        use_retirejs_db:        Use RetireJS database (default: true)
        retirejs_repo_url:      URL to download the DB from
        cache_dir:              Where to cache the DB (default: ~/.depnova/cache)
        cache_ttl_hours:        How long before refreshing cache (default: 24)
        scan_sourcemaps:        Also parse .map files (default: true)
        include_vulnerabilities: Report RetireJS vulns (default: true)
        max_file_read_bytes:    Max bytes to read from each file (default: 1MB)
    """

    def get_name(self) -> str:
        return "js_fingerprinter"

    def get_phase(self) -> int:
        return 3

    def get_description(self) -> str:
        return "Identify JS libraries by content fingerprinting using RetireJS database"

    def get_supported_ecosystems(self) -> list[str]:
        return ["npm", "cdn", "static"]

    def scan(self, context: PipelineContext) -> DependencyGraph:
        graph = DependencyGraph(source_plugin=self.get_name())

        # Load RetireJS database
        retirejs_db = self._load_retirejs_db()
        if not retirejs_db:
            graph.add_error("Failed to load RetireJS database")
            return graph

        log.info("retirejs_db_loaded", libraries=len(retirejs_db))

        # Compile extractor patterns for all libraries
        compiled_db = self._compile_extractors(retirejs_db)

        # Get files to scan from two sources:
        # 1. Local scripts shared by frontend_scanner (Phase 3A)
        # 2. Walk the project directory for JS files
        files_to_scan = self._collect_files(context)
        log.info("files_to_scan", count=len(files_to_scan))

        include_vulns = self.config.get("include_vulnerabilities", True)
        max_read = self.config.get("max_file_read_bytes", 1 * 1024 * 1024)  # 1MB
        seen_deps: set[str] = set()

        for file_path in files_to_scan:
            path = Path(file_path)
            if not path.exists() or not path.is_file():
                continue

            matches = self._scan_file(path, compiled_db, retirejs_db, max_read)

            for match in matches:
                dep = match["dependency"]
                key = dep.unique_key
                if key in seen_deps:
                    continue
                seen_deps.add(key)

                graph.add_dependency(dep)

                # Attach vulnerabilities from RetireJS
                if include_vulns and match.get("vulnerabilities"):
                    for vuln in match["vulnerabilities"]:
                        graph.vulnerabilities.append(vuln)

        # Source map scanning (Phase 3C)
        scan_sourcemaps = self.config.get("scan_sourcemaps", True)
        if scan_sourcemaps:
            sourcemap_deps = self._scan_sourcemaps(context, seen_deps)
            for dep in sourcemap_deps:
                graph.add_dependency(dep)

        log.info(
            "fingerprint_scan_complete",
            deps_found=graph.dependency_count,
            vulns_found=len(graph.vulnerabilities),
        )
        return graph

    # -------------------------------------------------------------------
    # RetireJS database loading & caching
    # -------------------------------------------------------------------

    def _load_retirejs_db(self) -> Optional[dict]:
        """Load the RetireJS database, with caching."""
        use_db = self.config.get("use_retirejs_db", True)
        if not use_db:
            return None

        cache_dir = Path(self.config.get("cache_dir", "~/.depnova/cache")).expanduser()
        cache_file = cache_dir / "jsrepository.json"
        cache_ttl = self.config.get("cache_ttl_hours", 24) * 3600
        repo_url = self.config.get("retirejs_repo_url", _DEFAULT_RETIREJS_URL)

        # Check cache
        if cache_file.exists():
            cache_age = time.time() - cache_file.stat().st_mtime
            if cache_age < cache_ttl:
                log.debug("retirejs_using_cache", age_hours=round(cache_age / 3600, 1))
                try:
                    with open(cache_file) as f:
                        return json.load(f)
                except Exception:
                    pass  # Fall through to download

        # Download fresh copy
        log.info("retirejs_downloading", url=repo_url)
        try:
            import httpx
            resp = httpx.get(repo_url, timeout=30, follow_redirects=True)
            resp.raise_for_status()
            data = resp.json()

            # Save to cache
            cache_dir.mkdir(parents=True, exist_ok=True)
            with open(cache_file, "w") as f:
                json.dump(data, f)

            log.info("retirejs_downloaded", libraries=len(data))
            return data

        except Exception as e:
            log.warning("retirejs_download_failed", error=str(e))

            # Try cached version even if expired
            if cache_file.exists():
                log.info("retirejs_using_expired_cache")
                with open(cache_file) as f:
                    return json.load(f)

            return None

    # -------------------------------------------------------------------
    # Extractor compilation
    # -------------------------------------------------------------------

    def _compile_extractors(self, db: dict) -> dict[str, dict]:
        """Pre-compile all regex patterns from RetireJS extractors.

        The §§version§§ placeholder is replaced with a version-capturing regex.

        Returns:
            Dict mapping library_name → {
                "filecontent": list of compiled regex,
                "filename": list of compiled regex,
                "uri": list of compiled regex,
                "hashes": dict of hash → version,
            }
        """
        compiled = {}

        for lib_name, lib_data in db.items():
            if lib_name in ("retire-example",):  # Skip example entries
                continue

            extractors = lib_data.get("extractors", {})
            if not extractors:
                continue

            entry = {
                "filecontent": [],
                "filename": [],
                "uri": [],
                "hashes": extractors.get("hashes", {}),
            }

            # Compile filecontent patterns
            for pattern in extractors.get("filecontent", []):
                regex = self._retirejs_pattern_to_regex(pattern)
                if regex:
                    entry["filecontent"].append(regex)

            # Compile filename patterns
            for pattern in extractors.get("filename", []):
                regex = self._retirejs_pattern_to_regex(pattern)
                if regex:
                    entry["filename"].append(regex)

            # Compile URI patterns
            for pattern in extractors.get("uri", []):
                regex = self._retirejs_pattern_to_regex(pattern)
                if regex:
                    entry["uri"].append(regex)

            compiled[lib_name] = entry

        return compiled

    def _retirejs_pattern_to_regex(self, pattern: str) -> Optional[re.Pattern]:
        """Convert a RetireJS pattern (with §§version§§) to a compiled regex.

        RetireJS patterns use §§version§§ as a placeholder for the version
        to be captured. We replace it with a version-matching capture group.
        """
        try:
            # Replace the version placeholder with our capture group
            regex_str = pattern.replace("§§version§§", _VERSION_CAPTURE)
            return re.compile(regex_str, re.IGNORECASE | re.DOTALL)
        except re.error as e:
            log.debug("regex_compile_failed", pattern=pattern[:80], error=str(e))
            return None

    # -------------------------------------------------------------------
    # File scanning
    # -------------------------------------------------------------------

    def _collect_files(self, context: PipelineContext) -> list[str]:
        """Collect files to scan from Phase 3A output + filesystem walk."""
        files: set[str] = set()

        # Source 1: Local scripts collected by frontend_scanner
        shared_scripts = context.get_shared("local_scripts_for_fingerprinting", [])
        for script_info in shared_scripts:
            path = script_info.get("path", "")
            if path:
                # Resolve relative paths from HTML against project root
                resolved = Path(context.project_root) / path.lstrip("/")
                if resolved.exists():
                    files.add(str(resolved.resolve()))

        # Source 2: Walk project for JS files
        root = Path(context.project_root)
        skip_dirs = {"node_modules", ".git", "__pycache__", ".venv", "venv", "depnova-reports"}
        min_size = self.config.get("min_file_size_bytes", 500)
        max_size = self.config.get("max_file_size_mb", 50) * 1024 * 1024

        for ext in ("*.js", "*.mjs"):
            for f in root.rglob(ext):
                if any(skip in f.parts for skip in skip_dirs):
                    continue
                try:
                    size = f.stat().st_size
                    if min_size <= size <= max_size:
                        files.add(str(f.resolve()))
                except OSError:
                    continue

        return sorted(files)

    def _scan_file(
        self,
        path: Path,
        compiled_db: dict[str, dict],
        raw_db: dict,
        max_read: int,
    ) -> list[dict]:
        """Scan a single file against all libraries in the compiled DB.

        Returns list of matches: [{"dependency": Dep, "vulnerabilities": [...]}]
        """
        matches = []
        filename = path.name

        # Read file content (up to max_read bytes)
        try:
            content = path.read_text(errors="ignore")[:max_read]
        except Exception as e:
            log.debug("file_read_error", path=str(path), error=str(e))
            return matches

        # Compute SHA-256 hash
        try:
            file_hash = hashlib.sha256(path.read_bytes()).hexdigest()
        except Exception:
            file_hash = ""

        for lib_name, extractors in compiled_db.items():
            version = None
            method = ""

            # Layer 1: File content matching (highest accuracy for content)
            for regex in extractors.get("filecontent", []):
                match = regex.search(content)
                if match:
                    version = match.group(1)
                    method = "filecontent"
                    break

            # Layer 2: Filename matching
            if not version:
                for regex in extractors.get("filename", []):
                    match = regex.search(filename)
                    if match:
                        version = match.group(1)
                        method = "filename"
                        break

            # Also try URI patterns against the full path
            if not version:
                for regex in extractors.get("uri", []):
                    match = regex.search(str(path))
                    if match:
                        version = match.group(1)
                        method = "uri"
                        break

            # Layer 3: Hash matching
            if not version and file_hash:
                hashes = extractors.get("hashes", {})
                if file_hash in hashes:
                    version = hashes[file_hash]
                    method = "hash"

            if version:
                confidence = {
                    "hash": ConfidenceLevel.SCANNED,         # 0.85
                    "filecontent": ConfidenceLevel.FINGERPRINTED + 0.05,  # 0.75
                    "filename": ConfidenceLevel.FINGERPRINTED,  # 0.70
                    "uri": ConfidenceLevel.FINGERPRINTED,       # 0.70
                }.get(method, ConfidenceLevel.FINGERPRINTED)

                # Get npm name if available
                npm_name = raw_db.get(lib_name, {}).get("npmname", lib_name)

                dep = Dependency(
                    name=npm_name,
                    version=version,
                    ecosystem=Ecosystem.STATIC,
                    purl=generate_purl(npm_name, version, Ecosystem.NPM),
                    is_direct=True,
                    is_dev=False,
                    confidence=confidence,
                    sources=[SourceType.FINGERPRINT.value],
                    location=str(path),
                    metadata={
                        "detection_method": method,
                        "retirejs_name": lib_name,
                        "file_hash": file_hash,
                    },
                )

                # Check for known vulnerabilities
                vulns = self._check_vulnerabilities(lib_name, version, raw_db)

                matches.append({
                    "dependency": dep,
                    "vulnerabilities": vulns,
                })

                log.info(
                    "library_identified",
                    library=npm_name,
                    version=version,
                    method=method,
                    file=filename,
                    vulns=len(vulns),
                )

        return matches

    # -------------------------------------------------------------------
    # Vulnerability checking against RetireJS DB
    # -------------------------------------------------------------------

    def _check_vulnerabilities(
        self,
        lib_name: str,
        version: str,
        db: dict,
    ) -> list[Vulnerability]:
        """Check if a library version has known vulnerabilities in RetireJS DB."""
        vulns = []
        lib_data = db.get(lib_name, {})
        lib_vulns = lib_data.get("vulnerabilities", [])
        npm_name = lib_data.get("npmname", lib_name)

        for vuln_entry in lib_vulns:
            at_or_above = vuln_entry.get("atOrAbove", "0")
            below = vuln_entry.get("below", "")

            if not below:
                continue

            # Simple version comparison (semver)
            if self._version_in_range(version, at_or_above, below):
                severity_str = vuln_entry.get("severity", "medium")
                severity = _SEVERITY_MAP.get(severity_str, Severity.MEDIUM)

                identifiers = vuln_entry.get("identifiers", {})
                cve_ids = identifiers.get("CVE", [])
                summary = identifiers.get("summary", "")
                github_id = identifiers.get("githubID", "")

                vuln_id = cve_ids[0] if cve_ids else github_id or f"RETIREJS-{lib_name}"
                info_urls = vuln_entry.get("info", [])

                vuln = Vulnerability(
                    vuln_id=vuln_id,
                    severity=severity,
                    title=summary[:200] if summary else f"Vulnerability in {lib_name}",
                    description=summary,
                    source="retirejs",
                    url=info_urls[0] if info_urls else "",
                    dependency_purl=generate_purl(npm_name, version, Ecosystem.NPM),
                )
                vulns.append(vuln)

        return vulns

    def _version_in_range(self, version: str, at_or_above: str, below: str) -> bool:
        """Check if version is in range [at_or_above, below).

        Uses simple tuple comparison of version parts.
        """
        try:
            v = _parse_version_tuple(version)
            low = _parse_version_tuple(at_or_above)
            high = _parse_version_tuple(below)

            return low <= v < high
        except Exception:
            return False

    # -------------------------------------------------------------------
    # Source map scanning (Phase 3C)
    # -------------------------------------------------------------------

    def _scan_sourcemaps(
        self,
        context: PipelineContext,
        seen_deps: set[str],
    ) -> list[Dependency]:
        """Scan .map files for library names in the sources array."""
        deps = []
        root = Path(context.project_root)
        skip_dirs = {"node_modules", ".git", "__pycache__", ".venv"}

        for map_file in root.rglob("*.map"):
            if any(skip in map_file.parts for skip in skip_dirs):
                continue

            try:
                with open(map_file) as f:
                    data = json.load(f)
            except Exception:
                continue

            sources = data.get("sources", [])
            for source in sources:
                # Extract library name from node_modules paths
                # e.g. "webpack:///./node_modules/lodash/lodash.js"
                match = re.search(r"node_modules/(@[^/]+/[^/]+|[^/]+)", source)
                if not match:
                    continue

                lib_name = match.group(1)

                # Skip internal/project files
                if lib_name.startswith(".") or lib_name in ("webpack", "babel"):
                    continue

                dep = Dependency(
                    name=lib_name,
                    version="",  # Source maps don't contain versions
                    ecosystem=Ecosystem.STATIC,
                    purl="",  # No version = no PURL
                    is_direct=False,
                    confidence=ConfidenceLevel.INFERRED,  # 0.30 — low confidence
                    sources=[SourceType.SOURCEMAP.value],
                    location=str(map_file),
                    metadata={"source_path": source},
                )

                key = f"sourcemap:{lib_name}"
                if key not in seen_deps:
                    seen_deps.add(key)
                    deps.append(dep)

        if deps:
            log.info("sourcemap_libs_found", count=len(deps))

        return deps


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "none": Severity.NONE,
}


def _parse_version_tuple(version: str) -> tuple[int, ...]:
    """Parse a version string into a comparable tuple.

    Examples:
        "3.6.0" → (3, 6, 0)
        "2.29.4" → (2, 29, 4)
        "1.0.0-beta.1" → (1, 0, 0)
    """
    # Strip pre-release suffixes for comparison
    clean = re.match(r"^([\d.]+)", version)
    if clean:
        parts = clean.group(1).split(".")
        return tuple(int(p) for p in parts if p.isdigit())
    return (0,)
