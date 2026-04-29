"""Manifest scanner plugin — Phase 1.

Parses manifest files that may NOT have exact versions (unlike lock files).
These are lower-confidence sources but important for catching dependencies
that might not have lock files.

Supported manifests:
    - requirements.txt (pip)
    - setup.py / setup.cfg (setuptools)
    - pyproject.toml (PEP 621)
    - package.json (npm — direct deps only, NOT a lock file)
    - pom.xml (Maven)
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Optional

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


class ManifestScanner(BasePlugin):
    """Scans manifest files for declared dependencies.

    Config options:
        files:          list of manifest filenames to look for
        mark_unpinned:  bool — flag deps without exact versions as warnings
        scan_paths:     list of directories to scan
    """

    def get_name(self) -> str:
        return "manifest_scanner"

    def get_phase(self) -> int:
        return 1

    def get_description(self) -> str:
        return "Parse manifest files (requirements.txt, package.json, pom.xml) for declared dependencies"

    def get_supported_ecosystems(self) -> list[str]:
        return ["pypi", "npm", "maven"]

    def scan(self, context: PipelineContext) -> DependencyGraph:
        graph = DependencyGraph(source_plugin=self.get_name())
        root = Path(context.project_root)

        target_files = self.config.get("files", [
            "requirements.txt",
            "requirements-dev.txt",
            "requirements_dev.txt",
            "setup.py",
            "setup.cfg",
            "pyproject.toml",
            "package.json",
            "pom.xml",
        ])
        mark_unpinned = self.config.get("mark_unpinned", True)
        scan_paths = self.config.get("scan_paths", ["."])

        # Resolve scan paths
        dirs_to_scan: list[Path] = []
        for sp in scan_paths:
            resolved = root / sp
            if resolved.is_dir():
                dirs_to_scan.append(resolved)
            else:
                for match in root.glob(sp):
                    if match.is_dir():
                        dirs_to_scan.append(match)
        if not dirs_to_scan:
            dirs_to_scan = [root]

        # Map filenames to parsers
        parsers = {
            "requirements.txt": self._parse_requirements,
            "requirements-dev.txt": self._parse_requirements,
            "requirements_dev.txt": self._parse_requirements,
            "setup.cfg": self._parse_setup_cfg,
            "pyproject.toml": self._parse_pyproject_toml,
            "package.json": self._parse_package_json,
            "pom.xml": self._parse_pom_xml,
        }

        for scan_dir in dirs_to_scan:
            for filename in target_files:
                file_path = scan_dir / filename
                if not file_path.exists():
                    continue

                parser = parsers.get(filename)
                if not parser:
                    continue

                log.info("parsing_manifest", file=str(file_path))

                try:
                    deps = parser(file_path, mark_unpinned, graph)
                    for dep in deps:
                        graph.add_dependency(dep)
                    log.info("manifest_parsed", file=filename, dependencies=len(deps))
                except Exception as e:
                    msg = f"Failed to parse {file_path}: {e}"
                    log.error("manifest_parse_error", file=str(file_path), error=str(e))
                    graph.add_error(msg)

        return graph

    # -------------------------------------------------------------------
    # Parsers
    # -------------------------------------------------------------------

    def _parse_requirements(
        self, path: Path, mark_unpinned: bool, graph: DependencyGraph
    ) -> list[Dependency]:
        """Parse requirements.txt / requirements-dev.txt.

        Handles:
            - package==1.2.3 (pinned)
            - package>=1.2.0 (range — lower confidence)
            - package (no version — lowest confidence)
            - -r other-file.txt (recursive includes)
            - # comments
            - package[extra]==1.2.3 (extras)
        """
        deps: list[Dependency] = []
        is_dev = "dev" in path.name

        for line in path.read_text().splitlines():
            line = line.strip()

            # Skip empty lines, comments, and options
            if not line or line.startswith("#") or line.startswith("-"):
                continue

            # Handle -r includes (just note them, don't follow)
            if line.startswith("-r "):
                continue

            # Parse: name[extras]<operator>version
            match = re.match(
                r"^([A-Za-z0-9_][A-Za-z0-9._-]*)(?:\[.*?\])?\s*(==|>=|<=|~=|!=|>|<)?\s*([\d\w.*]+)?",
                line,
            )
            if not match:
                continue

            name = match.group(1)
            operator = match.group(2)
            version = match.group(3) or ""

            # Determine confidence based on version precision
            if operator == "==" and version:
                confidence = ConfidenceLevel.LOCKED  # Pinned exactly
            elif version:
                confidence = ConfidenceLevel.MANIFEST  # Has version but not pinned
                if mark_unpinned:
                    graph.add_warning(f"Unpinned dependency: {name}{operator}{version} in {path.name}")
            else:
                confidence = ConfidenceLevel.INFERRED
                if mark_unpinned:
                    graph.add_warning(f"Unversioned dependency: {name} in {path.name}")

            deps.append(Dependency(
                name=name,
                version=version,
                ecosystem=Ecosystem.PYPI,
                purl=generate_purl(name, version, Ecosystem.PYPI) if version else "",
                is_direct=True,
                is_dev=is_dev,
                confidence=confidence,
                sources=[SourceType.MANIFEST.value],
                location=str(path),
            ))

        return deps

    def _parse_setup_cfg(
        self, path: Path, mark_unpinned: bool, graph: DependencyGraph
    ) -> list[Dependency]:
        """Parse setup.cfg [options] install_requires."""
        import configparser

        config = configparser.ConfigParser()
        config.read(path)

        deps: list[Dependency] = []

        install_requires = config.get("options", "install_requires", fallback="")
        for line in install_requires.strip().splitlines():
            line = line.strip()
            if not line:
                continue

            match = re.match(r"^([A-Za-z0-9_][A-Za-z0-9._-]*)\s*(.*)", line)
            if match:
                name = match.group(1)
                version_spec = match.group(2).strip()
                version = re.search(r"[\d][.\d\w]*", version_spec)
                ver = version.group(0) if version else ""

                deps.append(Dependency(
                    name=name,
                    version=ver,
                    ecosystem=Ecosystem.PYPI,
                    purl=generate_purl(name, ver, Ecosystem.PYPI) if ver else "",
                    is_direct=True,
                    confidence=ConfidenceLevel.MANIFEST if ver else ConfidenceLevel.INFERRED,
                    sources=[SourceType.MANIFEST.value],
                    location=str(path),
                ))

        return deps

    def _parse_pyproject_toml(
        self, path: Path, mark_unpinned: bool, graph: DependencyGraph
    ) -> list[Dependency]:
        """Parse pyproject.toml [project] dependencies (PEP 621)."""
        try:
            import tomllib
        except ImportError:
            try:
                import tomli as tomllib  # type: ignore[no-redef]
            except ImportError:
                return []

        with open(path, "rb") as f:
            data = tomllib.load(f)

        deps: list[Dependency] = []

        # PEP 621 dependencies
        project_deps = data.get("project", {}).get("dependencies", [])
        for dep_str in project_deps:
            parsed = _parse_pep508(dep_str)
            if parsed:
                name, version = parsed
                deps.append(Dependency(
                    name=name,
                    version=version,
                    ecosystem=Ecosystem.PYPI,
                    purl=generate_purl(name, version, Ecosystem.PYPI) if version else "",
                    is_direct=True,
                    confidence=ConfidenceLevel.MANIFEST if version else ConfidenceLevel.INFERRED,
                    sources=[SourceType.MANIFEST.value],
                    location=str(path),
                ))

        return deps

    def _parse_package_json(
        self, path: Path, mark_unpinned: bool, graph: DependencyGraph
    ) -> list[Dependency]:
        """Parse package.json for declared dependencies (NOT a lock file).

        Extracts from 'dependencies' and 'devDependencies'.
        Version ranges (^, ~) get lower confidence.
        """
        with open(path) as f:
            data = json.load(f)

        deps: list[Dependency] = []

        for section, is_dev in [("dependencies", False), ("devDependencies", True)]:
            packages = data.get(section, {})
            for name, version_spec in packages.items():
                # Clean version spec
                version = version_spec.lstrip("^~>=<")
                is_exact = not any(c in version_spec for c in "^~>=<*")

                if is_exact and version:
                    confidence = ConfidenceLevel.MANIFEST
                elif version:
                    confidence = ConfidenceLevel.INFERRED
                    if mark_unpinned:
                        graph.add_warning(f"Range version: {name}@{version_spec} in package.json")
                else:
                    confidence = ConfidenceLevel.UNKNOWN
                    version = ""

                deps.append(Dependency(
                    name=name,
                    version=version,
                    ecosystem=Ecosystem.NPM,
                    purl=generate_purl(name, version, Ecosystem.NPM) if version else "",
                    is_direct=True,
                    is_dev=is_dev,
                    confidence=confidence,
                    sources=[SourceType.MANIFEST.value],
                    location=str(path),
                ))

        return deps

    def _parse_pom_xml(
        self, path: Path, mark_unpinned: bool, graph: DependencyGraph
    ) -> list[Dependency]:
        """Parse Maven pom.xml for declared dependencies.

        Note: This does NOT resolve effective POM — it reads declared
        dependencies only. Property references (${version.X}) are
        resolved if defined in the same file.
        """
        from lxml import etree

        tree = etree.parse(str(path))
        root = tree.getroot()

        # Handle Maven namespace
        ns = ""
        if root.tag.startswith("{"):
            ns = root.tag.split("}")[0] + "}"

        # Extract properties for variable resolution
        properties: dict[str, str] = {}
        props_el = root.find(f"{ns}properties")
        if props_el is not None:
            for prop in props_el:
                tag = prop.tag.replace(ns, "")
                properties[tag] = prop.text or ""

        deps: list[Dependency] = []

        for dep_el in root.iter(f"{ns}dependency"):
            group_id = _xml_text(dep_el, f"{ns}groupId") or ""
            artifact_id = _xml_text(dep_el, f"{ns}artifactId") or ""
            version = _xml_text(dep_el, f"{ns}version") or ""
            scope = _xml_text(dep_el, f"{ns}scope") or "compile"

            if not artifact_id:
                continue

            # Resolve property references
            version = _resolve_maven_props(version, properties)

            is_dev = scope in ("test", "provided")

            deps.append(Dependency(
                name=artifact_id,
                version=version,
                ecosystem=Ecosystem.MAVEN,
                purl=generate_purl(artifact_id, version, Ecosystem.MAVEN, namespace=group_id) if version else "",
                is_direct=True,
                is_dev=is_dev,
                confidence=ConfidenceLevel.MANIFEST if version else ConfidenceLevel.INFERRED,
                sources=[SourceType.MANIFEST.value],
                location=str(path),
                metadata={"groupId": group_id, "scope": scope},
            ))

        return deps


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_pep508(dep_string: str) -> Optional[tuple[str, str]]:
    """Parse a PEP 508 dependency string.

    Examples:
        "requests>=2.25.0" → ("requests", "2.25.0")
        "click" → ("click", "")
    """
    match = re.match(r"^([A-Za-z0-9_][A-Za-z0-9._-]*)(?:\[.*?\])?\s*(?:[><=!~]+\s*([\d\w.*]+))?", dep_string)
    if match:
        return match.group(1), match.group(2) or ""
    return None


def _xml_text(element, tag: str) -> Optional[str]:
    """Get text content of an XML child element."""
    child = element.find(tag)
    return child.text if child is not None else None


def _resolve_maven_props(value: str, properties: dict[str, str]) -> str:
    """Resolve Maven property references like ${spring.version}."""
    if not value:
        return value

    def replacer(match):
        prop_name = match.group(1)
        return properties.get(prop_name, match.group(0))

    return re.sub(r"\$\{([^}]+)\}", replacer, value)
