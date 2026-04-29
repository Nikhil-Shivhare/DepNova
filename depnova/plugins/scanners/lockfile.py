"""Lock file scanner plugin — Phase 1.

Parses lock files from multiple ecosystems to extract exact
dependency versions. Lock files are the most reliable source
of version data (confidence: 0.95).

Supported lock files:
    - package-lock.json (npm)
    - yarn.lock (yarn)
    - pnpm-lock.yaml (pnpm)
    - poetry.lock (poetry/python)
    - Pipfile.lock (pipenv/python)
    - gradle.lockfile (gradle/java)
    - Cargo.lock (rust)
    - go.sum (go)
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Optional

import yaml

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


class LockfileScanner(BasePlugin):
    """Scans lock files for exact dependency versions.

    Config options (in YAML):
        ecosystems:   dict of ecosystem_name → bool (enable/disable each)
        scan_paths:   list of directories to scan (default: ["."])
        include_dev_dependencies: bool (default: false)
    """

    def get_name(self) -> str:
        return "lockfile_scanner"

    def get_phase(self) -> int:
        return 1

    def get_description(self) -> str:
        return "Parse lock files for exact dependency versions (npm, yarn, pnpm, poetry, pipenv, gradle, cargo, go)"

    def get_supported_ecosystems(self) -> list[str]:
        return ["npm", "yarn", "pnpm", "pypi", "maven", "cargo", "golang"]

    def validate_config(self) -> list[str]:
        errors = []
        ecosystems = self.config.get("ecosystems", {})
        if ecosystems and not isinstance(ecosystems, dict):
            errors.append("'ecosystems' must be a dict of ecosystem_name → bool")
        return errors

    def scan(self, context: PipelineContext) -> DependencyGraph:
        graph = DependencyGraph(source_plugin=self.get_name())
        root = Path(context.project_root)

        ecosystems = self.config.get("ecosystems", {})
        scan_paths = self.config.get("scan_paths", ["."])
        include_dev = self.config.get("include_dev_dependencies", False)

        # Resolve scan paths relative to project root
        dirs_to_scan: list[Path] = []
        for sp in scan_paths:
            resolved = root / sp
            if resolved.is_dir():
                dirs_to_scan.append(resolved)
            else:
                # Handle glob patterns like "./services/*"
                for match in root.glob(sp):
                    if match.is_dir():
                        dirs_to_scan.append(match)

        if not dirs_to_scan:
            dirs_to_scan = [root]

        # Define lock file parsers mapped to ecosystem config keys
        lock_file_handlers = {
            "package-lock.json": ("npm", self._parse_npm_lock),
            "yarn.lock": ("yarn", self._parse_yarn_lock),
            "pnpm-lock.yaml": ("pnpm", self._parse_pnpm_lock),
            "poetry.lock": ("poetry", self._parse_poetry_lock),
            "Pipfile.lock": ("pipenv", self._parse_pipenv_lock),
            "gradle.lockfile": ("gradle", self._parse_gradle_lock),
            "Cargo.lock": ("cargo", self._parse_cargo_lock),
            "go.sum": ("go_mod", self._parse_go_sum),
        }

        for scan_dir in dirs_to_scan:
            for lock_filename, (eco_key, parser_fn) in lock_file_handlers.items():
                # Check if this ecosystem is enabled
                if ecosystems and not ecosystems.get(eco_key, True):
                    continue

                lock_path = scan_dir / lock_filename
                if not lock_path.exists():
                    continue

                log.info("parsing_lockfile", file=str(lock_path), ecosystem=eco_key)

                try:
                    deps = parser_fn(lock_path, include_dev)
                    for dep in deps:
                        graph.add_dependency(dep)
                    log.info("lockfile_parsed", file=lock_filename,
                             dependencies=len(deps), dir=str(scan_dir))
                except Exception as e:
                    msg = f"Failed to parse {lock_path}: {e}"
                    log.error("lockfile_parse_error", file=str(lock_path), error=str(e))
                    graph.add_error(msg)

        log.info("lockfile_scan_complete", total_deps=graph.dependency_count)
        return graph

    # -------------------------------------------------------------------
    # Lock file parsers
    # -------------------------------------------------------------------

    def _parse_npm_lock(self, path: Path, include_dev: bool) -> list[Dependency]:
        """Parse package-lock.json (v2/v3 format)."""
        with open(path) as f:
            data = json.load(f)

        deps: list[Dependency] = []
        lockfile_version = data.get("lockfileVersion", 1)

        if lockfile_version >= 2:
            # v2/v3: packages dict (preferred)
            packages = data.get("packages", {})
            for pkg_path, info in packages.items():
                if not pkg_path:  # Skip the root package
                    continue

                name = info.get("name") or pkg_path.split("node_modules/")[-1]
                version = info.get("version", "")
                is_dev = info.get("dev", False)

                if not include_dev and is_dev:
                    continue

                if not version:
                    continue

                dep = Dependency(
                    name=name,
                    version=version,
                    ecosystem=Ecosystem.NPM,
                    purl=generate_purl(name, version, Ecosystem.NPM),
                    is_direct="node_modules/" not in pkg_path.replace("node_modules/" + name, ""),
                    is_dev=is_dev,
                    confidence=ConfidenceLevel.LOCKED,
                    sources=[SourceType.LOCKFILE.value],
                    location=str(path),
                    hash_sha256=info.get("integrity", "").replace("sha512-", "").replace("sha256-", "") or None,
                )
                deps.append(dep)
        else:
            # v1: dependencies dict (legacy)
            dependencies = data.get("dependencies", {})
            deps.extend(self._parse_npm_v1_deps(dependencies, path, include_dev))

        return deps

    def _parse_npm_v1_deps(
        self, dependencies: dict, path: Path, include_dev: bool, is_transitive: bool = False
    ) -> list[Dependency]:
        """Recursively parse npm lockfile v1 dependencies."""
        deps = []
        for name, info in dependencies.items():
            version = info.get("version", "")
            is_dev = info.get("dev", False)

            if not include_dev and is_dev:
                continue

            if version:
                deps.append(Dependency(
                    name=name,
                    version=version,
                    ecosystem=Ecosystem.NPM,
                    purl=generate_purl(name, version, Ecosystem.NPM),
                    is_direct=not is_transitive,
                    is_dev=is_dev,
                    confidence=ConfidenceLevel.LOCKED,
                    sources=[SourceType.LOCKFILE.value],
                    location=str(path),
                ))

            # Recurse into nested dependencies
            nested = info.get("dependencies", {})
            if nested:
                deps.extend(self._parse_npm_v1_deps(nested, path, include_dev, is_transitive=True))

        return deps

    def _parse_yarn_lock(self, path: Path, include_dev: bool) -> list[Dependency]:
        """Parse yarn.lock (v1 text format).

        yarn.lock v1 format is NOT valid YAML — it's a custom text format:
            package-name@^version:
              version "1.2.3"
              resolved "https://..."
              integrity sha512-...
        """
        content = path.read_text()
        deps: list[Dependency] = []

        # Regex to match yarn.lock entries
        # Matches: "package@^version", "package@~version", etc.
        pattern = re.compile(
            r'^"?(@?[^@\n]+)@[^:\n]+"?:\s*\n'
            r'  version "([^"]+)"',
            re.MULTILINE,
        )

        for match in pattern.finditer(content):
            name = match.group(1).strip().strip('"')
            version = match.group(2)

            if not name or not version:
                continue

            # Determine namespace for scoped packages (@scope/name)
            namespace = None
            if name.startswith("@") and "/" in name:
                parts = name.split("/", 1)
                namespace = parts[0]

            deps.append(Dependency(
                name=name,
                version=version,
                ecosystem=Ecosystem.NPM,  # Yarn uses npm registry
                purl=generate_purl(name, version, Ecosystem.YARN, namespace=namespace),
                is_direct=False,  # yarn.lock doesn't distinguish
                is_dev=False,
                confidence=ConfidenceLevel.LOCKED,
                sources=[SourceType.LOCKFILE.value],
                location=str(path),
            ))

        return deps

    def _parse_pnpm_lock(self, path: Path, include_dev: bool) -> list[Dependency]:
        """Parse pnpm-lock.yaml."""
        with open(path) as f:
            data = yaml.safe_load(f)

        deps: list[Dependency] = []
        if not data:
            return deps

        # pnpm v6+ uses 'packages' key
        packages = data.get("packages", {})

        for pkg_spec, info in packages.items():
            if not isinstance(info, dict):
                continue

            # pkg_spec format: "/package-name@version" or "/@scope/name@version"
            match = re.match(r"/?(@?[^@]+)@(.+)", pkg_spec)
            if not match:
                continue

            name = match.group(1)
            version = match.group(2)
            is_dev = info.get("dev", False)

            if not include_dev and is_dev:
                continue

            deps.append(Dependency(
                name=name,
                version=version,
                ecosystem=Ecosystem.NPM,  # pnpm uses npm registry
                purl=generate_purl(name, version, Ecosystem.PNPM),
                is_direct=False,
                is_dev=is_dev,
                confidence=ConfidenceLevel.LOCKED,
                sources=[SourceType.LOCKFILE.value],
                location=str(path),
            ))

        return deps

    def _parse_poetry_lock(self, path: Path, include_dev: bool) -> list[Dependency]:
        """Parse poetry.lock (TOML format).

        Uses basic parsing since we want to avoid adding toml as a
        hard dependency — poetry.lock structure is simple enough.
        """
        try:
            import tomllib
        except ImportError:
            try:
                import tomli as tomllib  # type: ignore[no-redef]
            except ImportError:
                log.warning("toml_parser_missing",
                            hint="Install tomli for poetry.lock support (Python < 3.11)")
                return []

        with open(path, "rb") as f:
            data = tomllib.load(f)

        deps: list[Dependency] = []
        packages = data.get("package", [])

        for pkg in packages:
            name = pkg.get("name", "")
            version = pkg.get("version", "")
            category = pkg.get("category", "main")

            if not name or not version:
                continue

            is_dev = category != "main"
            if not include_dev and is_dev:
                continue

            deps.append(Dependency(
                name=name,
                version=version,
                ecosystem=Ecosystem.PYPI,
                purl=generate_purl(name, version, Ecosystem.PYPI),
                is_direct=True,  # poetry.lock includes all deps
                is_dev=is_dev,
                confidence=ConfidenceLevel.LOCKED,
                sources=[SourceType.LOCKFILE.value],
                location=str(path),
            ))

        return deps

    def _parse_pipenv_lock(self, path: Path, include_dev: bool) -> list[Dependency]:
        """Parse Pipfile.lock (JSON format)."""
        with open(path) as f:
            data = json.load(f)

        deps: list[Dependency] = []

        for section in ["default", "develop"]:
            if section == "develop" and not include_dev:
                continue

            packages = data.get(section, {})
            for name, info in packages.items():
                version = info.get("version", "").lstrip("=")

                if not version:
                    continue

                deps.append(Dependency(
                    name=name,
                    version=version,
                    ecosystem=Ecosystem.PYPI,
                    purl=generate_purl(name, version, Ecosystem.PYPI),
                    is_direct=True,
                    is_dev=(section == "develop"),
                    confidence=ConfidenceLevel.LOCKED,
                    sources=[SourceType.LOCKFILE.value],
                    location=str(path),
                    hash_sha256=_extract_hash(info.get("hashes", [])),
                ))

        return deps

    def _parse_gradle_lock(self, path: Path, include_dev: bool) -> list[Dependency]:
        """Parse gradle.lockfile.

        Format is simple text:
            group:artifact:version=configuration1,configuration2
        Lines starting with # are comments.
        """
        deps: list[Dependency] = []

        for line in path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("empty="):
                continue

            # Split off configurations
            parts = line.split("=")
            gav = parts[0].strip()

            # group:artifact:version
            gav_parts = gav.split(":")
            if len(gav_parts) != 3:
                continue

            group, artifact, version = gav_parts
            if not version:
                continue

            deps.append(Dependency(
                name=artifact,
                version=version,
                ecosystem=Ecosystem.MAVEN,
                purl=generate_purl(artifact, version, Ecosystem.GRADLE, namespace=group),
                is_direct=False,
                is_dev=False,
                confidence=ConfidenceLevel.LOCKED,
                sources=[SourceType.LOCKFILE.value],
                location=str(path),
                metadata={"groupId": group},
            ))

        return deps

    def _parse_cargo_lock(self, path: Path, include_dev: bool) -> list[Dependency]:
        """Parse Cargo.lock (TOML format)."""
        try:
            import tomllib
        except ImportError:
            try:
                import tomli as tomllib  # type: ignore[no-redef]
            except ImportError:
                log.warning("toml_parser_missing", hint="Install tomli for Cargo.lock support")
                return []

        with open(path, "rb") as f:
            data = tomllib.load(f)

        deps: list[Dependency] = []

        for pkg in data.get("package", []):
            name = pkg.get("name", "")
            version = pkg.get("version", "")

            if not name or not version:
                continue

            deps.append(Dependency(
                name=name,
                version=version,
                ecosystem=Ecosystem.CARGO,
                purl=generate_purl(name, version, Ecosystem.CARGO),
                is_direct=False,
                is_dev=False,
                confidence=ConfidenceLevel.LOCKED,
                sources=[SourceType.LOCKFILE.value],
                location=str(path),
                hash_sha256=pkg.get("checksum"),
            ))

        return deps

    def _parse_go_sum(self, path: Path, include_dev: bool) -> list[Dependency]:
        """Parse go.sum.

        Format:
            module version hash
            module version/go.mod hash
        """
        deps: list[Dependency] = []
        seen: set[str] = set()

        for line in path.read_text().splitlines():
            line = line.strip()
            if not line:
                continue

            parts = line.split()
            if len(parts) < 3:
                continue

            module = parts[0]
            version = parts[1].split("/")[0]  # Remove /go.mod suffix
            version = version.lstrip("v")

            key = f"{module}@{version}"
            if key in seen:
                continue
            seen.add(key)

            deps.append(Dependency(
                name=module,
                version=version,
                ecosystem=Ecosystem.GO,
                purl=generate_purl(module, version, Ecosystem.GO),
                is_direct=False,
                is_dev=False,
                confidence=ConfidenceLevel.LOCKED,
                sources=[SourceType.LOCKFILE.value],
                location=str(path),
            ))

        return deps


def _extract_hash(hashes: list[str]) -> Optional[str]:
    """Extract SHA-256 hash from a list of hash strings."""
    for h in hashes:
        if h.startswith("sha256:"):
            return h[7:]
    return None
