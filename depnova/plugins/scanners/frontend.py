"""Frontend HTML scanner plugin — Phase 3A.

Scans HTML files for <script> and <link> tags, extracts dependency
information from CDN URLs, and collects local static asset paths
for fingerprinting by the js_fingerprinter plugin (Phase 3B).

This is the CRITICAL GAP plugin — it finds frontend dependencies
that no other tool (Syft, Trivy, etc.) detects.

Supported CDN providers:
    - cdnjs.cloudflare.com
    - cdn.jsdelivr.net
    - unpkg.com
    - ajax.googleapis.com
    - ajax.aspnetcdn.com
    - code.jquery.com
    - stackpath.bootstrapcdn.com

Config example:
    - plugin: "frontend_scanner"
      enabled: true
      config:
        html_scan_paths: ["./public", "./src", "./dist", "./templates"]
        detect_cdn: true
        cdn_patterns: ["cdnjs.cloudflare.com", "cdn.jsdelivr.net", "unpkg.com"]
        scan_static_assets: true
        static_extensions: [".js", ".mjs", ".css"]
        min_file_size_bytes: 500
        max_file_size_mb: 50
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from bs4 import BeautifulSoup

from depnova.core.models import (
    ConfidenceLevel,
    Dependency,
    DependencyGraph,
    Ecosystem,
    SourceType,
)
from depnova.core.purl import generate_purl
from depnova.plugins.base import BasePlugin, PipelineContext
from depnova.utils.logger import get_logger

log = get_logger(__name__)


# ---------------------------------------------------------------------------
# CDN URL parsers — one function per CDN family
# ---------------------------------------------------------------------------

# General version regex: matches 1.2.3, 2.0.0-beta.1, etc.
_VERSION_RE = re.compile(r"(\d+\.\d+\.\d+(?:[-.][\w.]+)?)")


def _parse_jsdelivr_unpkg(url: str) -> Optional[tuple[str, str]]:
    """Parse jsDelivr or unpkg URLs.

    Formats:
        https://cdn.jsdelivr.net/npm/package@1.2.3/file.js
        https://cdn.jsdelivr.net/npm/@scope/package@1.2.3/file.js
        https://unpkg.com/package@1.2.3/file.js
        https://unpkg.com/@scope/package@1.2.3/file.js
    """
    parsed = urlparse(url)
    path = parsed.path

    # Remove /npm/ prefix (jsDelivr) or leading / (unpkg)
    if "/npm/" in path:
        path = path.split("/npm/", 1)[1]
    else:
        path = path.lstrip("/")

    # Handle scoped packages: @scope/name@version/...
    if path.startswith("@"):
        # @scope/name@version/rest
        match = re.match(r"(@[^/]+/[^@]+)@([^/]+)", path)
    else:
        # name@version/rest
        match = re.match(r"([^@]+)@([^/]+)", path)

    if match:
        name = match.group(1).strip()
        version = match.group(2).strip()
        return name, version

    return None


def _parse_cdnjs(url: str) -> Optional[tuple[str, str]]:
    """Parse cdnjs.cloudflare.com URLs.

    Format: https://cdnjs.cloudflare.com/ajax/libs/{name}/{version}/{file}
    """
    parsed = urlparse(url)
    path = parsed.path

    # Find /ajax/libs/ prefix
    if "/ajax/libs/" not in path:
        return None

    after_libs = path.split("/ajax/libs/", 1)[1]
    parts = after_libs.strip("/").split("/")

    if len(parts) >= 2:
        name = parts[0]
        version = parts[1]
        if _VERSION_RE.match(version):
            return name, version

    return None


def _parse_google_cdn(url: str) -> Optional[tuple[str, str]]:
    """Parse Google Hosted Libraries URLs.

    Format: https://ajax.googleapis.com/ajax/libs/{name}/{version}/{file}
    """
    parsed = urlparse(url)
    path = parsed.path

    if "/ajax/libs/" not in path:
        return None

    after_libs = path.split("/ajax/libs/", 1)[1]
    parts = after_libs.strip("/").split("/")

    if len(parts) >= 2:
        name = parts[0]
        version = parts[1]
        if _VERSION_RE.match(version):
            return name, version

    return None


def _parse_generic_cdn(url: str) -> Optional[tuple[str, str]]:
    """Fallback: try to extract library name and version from any URL.

    Looks for patterns like:
        /library-name/1.2.3/file.js
        /library-name@1.2.3/file.js
        /library-1.2.3.min.js
    """
    parsed = urlparse(url)
    path = parsed.path

    # Pattern 1: name@version in path
    match = re.search(r"/([^/@]+)@(\d+\.\d+\.\d+[^/]*)", path)
    if match:
        return match.group(1), match.group(2)

    # Pattern 2: name/version/ in path
    match = re.search(r"/([a-zA-Z][\w.-]+)/(\d+\.\d+\.\d+[^/]*)/", path)
    if match:
        return match.group(1), match.group(2)

    # Pattern 3: name-version.min.js in filename
    filename = path.split("/")[-1]
    match = re.match(r"([a-zA-Z][\w.-]*?)-(\d+\.\d+\.\d+[^.]*?)(?:\.min)?\.(?:js|css)$", filename)
    if match:
        return match.group(1), match.group(2)

    return None


# Map CDN hostnames to their parsers
_CDN_PARSERS: dict[str, callable] = {
    "cdn.jsdelivr.net": _parse_jsdelivr_unpkg,
    "unpkg.com": _parse_jsdelivr_unpkg,
    "cdnjs.cloudflare.com": _parse_cdnjs,
    "ajax.googleapis.com": _parse_google_cdn,
    "ajax.aspnetcdn.com": _parse_google_cdn,  # Same format as Google
    "code.jquery.com": _parse_generic_cdn,
    "stackpath.bootstrapcdn.com": _parse_generic_cdn,
    "maxcdn.bootstrapcdn.com": _parse_generic_cdn,
}


def parse_cdn_url(url: str) -> Optional[tuple[str, str, str]]:
    """Parse a CDN URL to extract library name, version, and CDN provider.

    Args:
        url: The full CDN URL

    Returns:
        Tuple of (name, version, cdn_provider) or None if not recognized
    """
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
    except Exception:
        return None

    # Try specific CDN parser first
    for cdn_host, parser in _CDN_PARSERS.items():
        if cdn_host in hostname:
            result = parser(url)
            if result:
                name, version = result
                return name, version, cdn_host

    # Fallback to generic parser for any URL with version-like patterns
    result = _parse_generic_cdn(url)
    if result:
        name, version = result
        return name, version, hostname

    return None


# ---------------------------------------------------------------------------
# Main plugin
# ---------------------------------------------------------------------------

class FrontendScanner(BasePlugin):
    """Scans HTML files for frontend dependencies loaded via CDN or local paths.

    Detection methods:
        1. Parse <script src="..."> tags for CDN URLs → extract name + version
        2. Parse <link href="..."> tags for CSS CDN URLs → extract name + version
        3. Collect local static asset paths → share with fingerprinter plugin
        4. Extract version from filename patterns (e.g. jquery-3.6.0.min.js)

    Config options:
        html_scan_paths:     List of directories to scan for HTML files
        detect_cdn:          Enable CDN URL detection (default: true)
        cdn_patterns:        List of CDN hostnames to recognize
        scan_static_assets:  Collect local .js/.css paths (default: true)
        static_extensions:   File extensions to collect [".js", ".mjs", ".css"]
        min_file_size_bytes: Minimum file size to consider (default: 500)
        max_file_size_mb:    Maximum file size to consider (default: 50)
    """

    def get_name(self) -> str:
        return "frontend_scanner"

    def get_phase(self) -> int:
        return 3

    def get_description(self) -> str:
        return "Scan HTML files for CDN-loaded scripts/styles and collect local static assets"

    def get_supported_ecosystems(self) -> list[str]:
        return ["cdn", "npm", "static"]

    def scan(self, context: PipelineContext) -> DependencyGraph:
        graph = DependencyGraph(source_plugin=self.get_name())
        root = Path(context.project_root)

        # Config
        html_scan_paths = self.config.get("html_scan_paths", [".", "./public", "./src", "./dist", "./templates"])
        detect_cdn = self.config.get("detect_cdn", True)
        scan_static = self.config.get("scan_static_assets", True)
        static_extensions = self.config.get("static_extensions", [".js", ".mjs", ".css"])
        min_size = self.config.get("min_file_size_bytes", 500)
        max_size_mb = self.config.get("max_file_size_mb", 50)
        max_size = max_size_mb * 1024 * 1024

        # Step 1: Find all HTML files
        html_files = self._find_html_files(root, html_scan_paths)
        log.info("html_files_found", count=len(html_files))

        if not html_files:
            graph.add_warning("No HTML files found in scan paths")
            return graph

        # Step 2: Parse each HTML file
        all_local_scripts: list[dict] = []  # Collected for fingerprinter
        seen_cdn_deps: set[str] = set()     # Deduplicate across HTML files

        for html_path in html_files:
            log.info("scanning_html", file=str(html_path))

            try:
                content = html_path.read_text(errors="ignore")
                soup = BeautifulSoup(content, "lxml")
            except Exception as e:
                graph.add_error(f"Failed to parse {html_path}: {e}")
                continue

            # Extract <script src="..."> tags
            for tag in soup.find_all("script", src=True):
                src = tag.get("src", "").strip()
                if not src:
                    continue

                result = self._process_script_src(src, html_path, detect_cdn, seen_cdn_deps)
                if result:
                    if result["type"] == "cdn_dep":
                        graph.add_dependency(result["dependency"])
                    elif result["type"] == "local_script":
                        all_local_scripts.append(result["info"])

            # Extract <link href="..."> tags (CSS)
            for tag in soup.find_all("link", href=True):
                rel = tag.get("rel", [])
                if isinstance(rel, list):
                    rel = " ".join(rel)
                if "stylesheet" not in rel.lower():
                    continue

                href = tag.get("href", "").strip()
                if not href:
                    continue

                result = self._process_link_href(href, html_path, detect_cdn, seen_cdn_deps)
                if result:
                    if result["type"] == "cdn_dep":
                        graph.add_dependency(result["dependency"])
                    elif result["type"] == "local_asset":
                        all_local_scripts.append(result["info"])

        # Step 3: Walk filesystem for static assets (if enabled)
        if scan_static:
            static_files = self._find_static_assets(root, html_scan_paths, static_extensions, min_size, max_size)

            for file_path in static_files:
                info = {
                    "path": str(file_path),
                    "filename": file_path.name,
                    "size": file_path.stat().st_size,
                    "extension": file_path.suffix,
                }
                all_local_scripts.append(info)

                # Try to extract version from filename
                dep = self._dep_from_filename(file_path)
                if dep:
                    key = dep.unique_key
                    if key not in seen_cdn_deps:
                        seen_cdn_deps.add(key)
                        graph.add_dependency(dep)

        # Step 4: Share local scripts with fingerprinter plugin (Phase 3B)
        # Deduplicate by path
        unique_scripts = {s["path"]: s for s in all_local_scripts}
        context.set_shared("local_scripts_for_fingerprinting", list(unique_scripts.values()))
        log.info("local_scripts_collected", count=len(unique_scripts),
                 hint="Shared with js_fingerprinter plugin for Phase 3B")

        log.info(
            "frontend_scan_complete",
            cdn_deps=graph.dependency_count,
            local_scripts=len(unique_scripts),
        )

        return graph

    # -------------------------------------------------------------------
    # HTML file discovery
    # -------------------------------------------------------------------

    def _find_html_files(self, root: Path, scan_paths: list[str]) -> list[Path]:
        """Find all HTML files in the configured scan paths."""
        html_files: list[Path] = []
        seen: set[str] = set()

        for sp in scan_paths:
            search_dir = root / sp
            if not search_dir.exists():
                continue

            if search_dir.is_file() and search_dir.suffix in (".html", ".htm"):
                resolved = str(search_dir.resolve())
                if resolved not in seen:
                    seen.add(resolved)
                    html_files.append(search_dir)
                continue

            # Recursively find HTML files
            for ext in ("*.html", "*.htm"):
                for f in search_dir.rglob(ext):
                    resolved = str(f.resolve())
                    if resolved not in seen:
                        seen.add(resolved)
                        html_files.append(f)

        return sorted(html_files)

    # -------------------------------------------------------------------
    # Script/link tag processing
    # -------------------------------------------------------------------

    def _process_script_src(
        self,
        src: str,
        html_path: Path,
        detect_cdn: bool,
        seen: set[str],
    ) -> Optional[dict]:
        """Process a <script src="..."> value.

        Returns:
            Dict with type="cdn_dep" and dependency, or
            type="local_script" and file info, or None
        """
        # Check if it's a CDN URL
        if detect_cdn and src.startswith(("http://", "https://", "//")):
            full_url = src if src.startswith("http") else f"https:{src}"
            result = parse_cdn_url(full_url)

            if result:
                name, version, cdn = result
                dep = self._create_cdn_dependency(name, version, cdn, full_url, str(html_path), "script")
                key = dep.unique_key
                if key not in seen:
                    seen.add(key)
                    return {"type": "cdn_dep", "dependency": dep}
                return None
            else:
                # External URL but couldn't parse — warn
                log.debug("cdn_url_unparseable", url=src)
                return None

        # Local script — collect for fingerprinting
        if not src.startswith(("http://", "https://", "//", "data:", "javascript:")):
            return {
                "type": "local_script",
                "info": {
                    "path": src,
                    "filename": src.split("/")[-1],
                    "html_source": str(html_path),
                    "tag_type": "script",
                },
            }

        return None

    def _process_link_href(
        self,
        href: str,
        html_path: Path,
        detect_cdn: bool,
        seen: set[str],
    ) -> Optional[dict]:
        """Process a <link href="..."> value (CSS stylesheets)."""
        if detect_cdn and href.startswith(("http://", "https://", "//")):
            full_url = href if href.startswith("http") else f"https:{href}"
            result = parse_cdn_url(full_url)

            if result:
                name, version, cdn = result
                dep = self._create_cdn_dependency(name, version, cdn, full_url, str(html_path), "link")
                key = dep.unique_key
                if key not in seen:
                    seen.add(key)
                    return {"type": "cdn_dep", "dependency": dep}
                return None

        # Local CSS asset
        if not href.startswith(("http://", "https://", "//", "data:")):
            return {
                "type": "local_asset",
                "info": {
                    "path": href,
                    "filename": href.split("/")[-1],
                    "html_source": str(html_path),
                    "tag_type": "link",
                },
            }

        return None

    # -------------------------------------------------------------------
    # Dependency creation
    # -------------------------------------------------------------------

    def _create_cdn_dependency(
        self,
        name: str,
        version: str,
        cdn: str,
        url: str,
        html_source: str,
        tag_type: str,
    ) -> Dependency:
        """Create a Dependency from a parsed CDN URL."""
        # Clean up name: remove trailing slashes, file extensions
        name = name.strip("/").strip()

        # Map common CDN names to their npm package names
        name = _CDN_NAME_ALIASES.get(name.lower(), name)

        return Dependency(
            name=name,
            version=version,
            ecosystem=Ecosystem.CDN,
            purl=generate_purl(name, version, Ecosystem.CDN),
            is_direct=True,
            is_dev=False,
            confidence=ConfidenceLevel.SCANNED,  # 0.85 — CDN version from URL
            sources=[SourceType.CDN_URL.value],
            location=html_source,
            metadata={
                "cdn_provider": cdn,
                "cdn_url": url,
                "html_tag": tag_type,
            },
        )

    def _dep_from_filename(self, file_path: Path) -> Optional[Dependency]:
        """Try to extract library name + version from a filename.

        Examples:
            jquery-3.6.0.min.js  → jquery @ 3.6.0
            underscore-1.13.6.js → underscore @ 1.13.6
            vue.global.min.js    → None (no version)
        """
        filename = file_path.name
        match = re.match(
            r"([a-zA-Z][\w.-]*?)[.-](\d+\.\d+\.\d+[^.]*?)(?:\.min)?\.(?:js|css|mjs)$",
            filename,
        )
        if not match:
            return None

        name = match.group(1)
        version = match.group(2)

        return Dependency(
            name=name,
            version=version,
            ecosystem=Ecosystem.STATIC,
            purl=generate_purl(name, version, Ecosystem.STATIC),
            is_direct=True,
            is_dev=False,
            confidence=ConfidenceLevel.FINGERPRINTED,  # 0.70 — filename only
            sources=[SourceType.FRONTEND_HTML.value],
            location=str(file_path),
            metadata={"detection_method": "filename_pattern"},
        )

    # -------------------------------------------------------------------
    # Static asset discovery
    # -------------------------------------------------------------------

    def _find_static_assets(
        self,
        root: Path,
        scan_paths: list[str],
        extensions: list[str],
        min_size: int,
        max_size: int,
    ) -> list[Path]:
        """Walk filesystem for static JS/CSS files."""
        files: list[Path] = []
        seen: set[str] = set()

        # Skip known non-relevant directories
        skip_dirs = {
            "node_modules", ".git", "__pycache__", ".venv", "venv",
            ".tox", ".pytest_cache", ".mypy_cache", "depnova-reports",
        }

        for sp in scan_paths:
            search_dir = root / sp
            if not search_dir.exists() or not search_dir.is_dir():
                continue

            for ext in extensions:
                for f in search_dir.rglob(f"*{ext}"):
                    # Skip excluded directories
                    if any(skip in f.parts for skip in skip_dirs):
                        continue

                    resolved = str(f.resolve())
                    if resolved in seen:
                        continue
                    seen.add(resolved)

                    # Check size bounds
                    try:
                        size = f.stat().st_size
                        if size < min_size or size > max_size:
                            continue
                    except OSError:
                        continue

                    files.append(f)

        log.debug("static_assets_found", count=len(files))
        return sorted(files)


# ---------------------------------------------------------------------------
# CDN name aliases — map CDN-specific names to npm package names
# ---------------------------------------------------------------------------

_CDN_NAME_ALIASES: dict[str, str] = {
    "jquery": "jquery",
    "moment.js": "moment",
    "moment": "moment",
    "chart.js": "chart.js",
    "font-awesome": "font-awesome",
    "lodash.js": "lodash",
    "lodash": "lodash",
    "d3": "d3",
    "vue": "vue",
    "react": "react",
    "react-dom": "react-dom",
    "angular.js": "angular",
    "backbone.js": "backbone",
    "ember.js": "ember-source",
    "underscore.js": "underscore",
    "underscore": "underscore",
    "sweetalert2": "sweetalert2",
    "axios": "axios",
    "bootstrap": "bootstrap",
    "popper.js": "@popperjs/core",
    "three.js": "three",
}
