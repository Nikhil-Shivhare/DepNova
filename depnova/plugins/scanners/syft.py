"""Syft SBOM scanner plugin — Phase 2.

Wraps Anchore's Syft tool to generate a Software Bill of Materials
from Docker images or filesystem directories. Syft detects both
OS packages (dpkg, rpm, apk) AND application dependencies (pip,
npm, gem, etc.) in a single pass.

Syft must be installed on the system: https://github.com/anchore/syft

Usage in config:
    - plugin: "syft_scanner"
      enabled: true
      config:
        targets:
          - type: "image"         # "image" or "dir"
            value: "myapp:latest" # Docker image tag or directory path
          - type: "dir"
            value: "/app"
        scope: "all-layers"       # "all-layers" or "squashed"
        timeout_seconds: 300      # Max time for Syft to run
        catalogers: []            # Optional: specific catalogers to enable
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any, Optional

from depnova.core.models import (
    ConfidenceLevel,
    Dependency,
    DependencyGraph,
    Ecosystem,
    SourceType,
)
from depnova.core.purl import generate_purl, normalize_version
from depnova.plugins.base import BasePlugin, PipelineContext
from depnova.utils.logger import get_logger

log = get_logger(__name__)


# ---------------------------------------------------------------------------
# PURL type → Ecosystem mapping (Syft uses PURL types in its output)
# ---------------------------------------------------------------------------

_PURL_TYPE_TO_ECOSYSTEM: dict[str, Ecosystem] = {
    "npm": Ecosystem.NPM,
    "pypi": Ecosystem.PYPI,
    "maven": Ecosystem.MAVEN,
    "gem": Ecosystem.UNKNOWN,  # Ruby gems — can be extended
    "cargo": Ecosystem.CARGO,
    "golang": Ecosystem.GO,
    "nuget": Ecosystem.NUGET,
    "composer": Ecosystem.COMPOSER,
    "deb": Ecosystem.OS_DPKG,
    "rpm": Ecosystem.OS_RPM,
    "apk": Ecosystem.OS_APK,
    "generic": Ecosystem.UNKNOWN,
}


class SyftScanner(BasePlugin):
    """Generates SBOM using Anchore Syft and parses the output.

    Syft is run as a subprocess producing CycloneDX JSON output,
    which is then parsed into DepNova's DependencyGraph format.

    Config options:
        targets:          List of scan targets [{type, value}]
        scope:            "all-layers" or "squashed" (Docker images only)
        timeout_seconds:  Max seconds for Syft to run (default: 300)
        catalogers:       List of specific Syft catalogers to enable
        syft_path:        Custom path to syft binary (default: auto-detect)
        extra_args:       Additional CLI args to pass to Syft
        save_sbom:        If true, save raw SBOM to output_dir (default: true)
    """

    def get_name(self) -> str:
        return "syft_scanner"

    def get_phase(self) -> int:
        return 2

    def get_description(self) -> str:
        return "Generate SBOM using Anchore Syft (Docker images & filesystem directories)"

    def get_supported_ecosystems(self) -> list[str]:
        return ["npm", "pypi", "maven", "cargo", "golang", "deb", "rpm", "apk"]

    def validate_config(self) -> list[str]:
        """Validate plugin configuration."""
        errors = []
        targets = self.config.get("targets", [])

        if not targets:
            errors.append(
                "No scan targets specified. Add 'targets' list with "
                "{type: 'image'|'dir', value: '...'} entries."
            )

        for i, target in enumerate(targets):
            if not isinstance(target, dict):
                errors.append(f"Target {i} must be a dict with 'type' and 'value' keys")
                continue
            if target.get("type") not in ("image", "dir"):
                errors.append(f"Target {i}: 'type' must be 'image' or 'dir', got '{target.get('type')}'")
            if not target.get("value"):
                errors.append(f"Target {i}: 'value' is required")

        return errors

    def scan(self, context: PipelineContext) -> DependencyGraph:
        """Run Syft on each configured target and parse the results."""
        graph = DependencyGraph(source_plugin=self.get_name())

        # Check if Syft is available
        syft_bin = self._find_syft()
        if not syft_bin:
            msg = (
                "Syft is not installed or not found in PATH. "
                "Install from: https://github.com/anchore/syft#installation"
            )
            log.error("syft_not_found")
            graph.add_error(msg)
            return graph

        # Log Syft version
        syft_version = self._get_syft_version(syft_bin)
        log.info("syft_found", path=syft_bin, version=syft_version)

        targets = self.config.get("targets", [])
        save_sbom = self.config.get("save_sbom", True)

        for i, target in enumerate(targets):
            target_type = target["type"]
            target_value = target["value"]

            # Resolve directory paths relative to project root
            if target_type == "dir":
                resolved = Path(context.project_root) / target_value
                if not resolved.exists():
                    msg = f"Directory target does not exist: {resolved}"
                    log.warning("syft_target_missing", target=str(resolved))
                    graph.add_warning(msg)
                    continue
                target_value = str(resolved)

            log.info("syft_scanning", target_type=target_type, target=target_value)

            # Run Syft
            sbom_json = self._run_syft(syft_bin, target_type, target_value, context)

            if sbom_json is None:
                graph.add_error(f"Syft failed for target: {target_type}:{target_value}")
                continue

            # Optionally save raw SBOM to output directory
            if save_sbom:
                self._save_sbom(sbom_json, target_value, context.output_dir, i)

            # Parse SBOM into dependencies
            deps = self._parse_cyclonedx(sbom_json, target_value)
            for dep in deps:
                graph.add_dependency(dep)

            log.info(
                "syft_target_complete",
                target=target_value,
                dependencies=len(deps),
            )

        # Share the raw SBOM data for Phase 6 (vulnerability scanning)
        context.set_shared("syft_scan_complete", True)

        log.info("syft_scan_complete", total_deps=graph.dependency_count)
        return graph

    # -------------------------------------------------------------------
    # Syft execution
    # -------------------------------------------------------------------

    def _find_syft(self) -> Optional[str]:
        """Locate the Syft binary."""
        # Check custom path first
        custom = self.config.get("syft_path")
        if custom and Path(custom).exists():
            return custom

        # Search PATH
        return shutil.which("syft")

    def _get_syft_version(self, syft_bin: str) -> str:
        """Get the installed Syft version."""
        try:
            result = subprocess.run(
                [syft_bin, "version"],
                capture_output=True, text=True, timeout=10,
            )
            # Parse version from output
            for line in result.stdout.splitlines():
                if "version" in line.lower() or line.strip().startswith("0") or line.strip().startswith("1"):
                    return line.strip()
            return result.stdout.strip()[:50]
        except Exception:
            return "unknown"

    def _run_syft(
        self,
        syft_bin: str,
        target_type: str,
        target_value: str,
        context: PipelineContext,
    ) -> Optional[dict]:
        """Execute Syft and return parsed JSON output.

        Args:
            syft_bin:     Path to syft binary
            target_type:  "image" or "dir"
            target_value: Image tag or directory path
            context:      Pipeline context

        Returns:
            Parsed CycloneDX JSON dict, or None on failure
        """
        timeout = self.config.get("timeout_seconds", 300)
        scope = self.config.get("scope", "all-layers")
        catalogers = self.config.get("catalogers", [])
        extra_args = self.config.get("extra_args", [])

        # Build the Syft command
        cmd = [syft_bin]

        # Target specification
        if target_type == "image":
            cmd.append(f"{target_value}")
        elif target_type == "dir":
            cmd.append(f"dir:{target_value}")

        # Output format: CycloneDX JSON
        cmd.extend(["-o", "cyclonedx-json"])

        # Scope for Docker images
        if target_type == "image":
            cmd.extend(["--scope", scope])

        # Optional catalogers
        if catalogers:
            for cat in catalogers:
                cmd.extend(["--catalogers", cat])

        # Extra args from config
        cmd.extend(extra_args)

        log.debug("syft_command", cmd=" ".join(cmd))

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )

            if result.returncode != 0:
                log.error(
                    "syft_execution_failed",
                    returncode=result.returncode,
                    stderr=result.stderr[:500],
                )
                return None

            # Parse JSON output
            return json.loads(result.stdout)

        except subprocess.TimeoutExpired:
            log.error("syft_timeout", timeout=timeout, target=target_value)
            return None
        except json.JSONDecodeError as e:
            log.error("syft_json_parse_error", error=str(e))
            return None
        except Exception as e:
            log.error("syft_unexpected_error", error=str(e))
            return None

    # -------------------------------------------------------------------
    # CycloneDX SBOM parsing
    # -------------------------------------------------------------------

    def _parse_cyclonedx(self, sbom: dict, source_target: str) -> list[Dependency]:
        """Parse CycloneDX JSON SBOM into Dependency objects.

        CycloneDX structure:
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "components": [
                {
                    "type": "library",
                    "name": "package-name",
                    "version": "1.2.3",
                    "purl": "pkg:npm/package-name@1.2.3",
                    "licenses": [...],
                    "hashes": [...]
                }
            ]
        }
        """
        deps: list[Dependency] = []
        components = sbom.get("components", [])

        for comp in components:
            dep = self._component_to_dependency(comp, source_target)
            if dep:
                deps.append(dep)

        return deps

    def _component_to_dependency(
        self, component: dict, source_target: str
    ) -> Optional[Dependency]:
        """Convert a single CycloneDX component to a Dependency."""
        name = component.get("name", "")
        version = component.get("version", "")

        if not name:
            return None

        # Extract PURL (Syft provides this)
        purl = component.get("purl", "")

        # Determine ecosystem from PURL or component type
        ecosystem = self._detect_ecosystem(purl, component)

        # Extract license
        license_id = self._extract_license(component)

        # Extract hash
        hash_sha256 = self._extract_hash(component)

        # Extract CPE
        cpe = None
        cpes = component.get("cpe", component.get("cpes", []))
        if isinstance(cpes, list) and cpes:
            cpe = cpes[0]
        elif isinstance(cpes, str):
            cpe = cpes

        # Generate PURL if Syft didn't provide one
        if not purl and version:
            purl = generate_purl(name, version, ecosystem)

        return Dependency(
            name=name,
            version=normalize_version(version),
            ecosystem=ecosystem,
            purl=purl,
            is_direct=False,  # Syft can't determine direct vs transitive
            is_dev=False,
            confidence=ConfidenceLevel.SCANNED,
            sources=[SourceType.SYFT.value],
            license_id=license_id,
            hash_sha256=hash_sha256,
            cpe=cpe,
            location=source_target,
            metadata={
                "component_type": component.get("type", ""),
                "publisher": component.get("publisher", ""),
                "group": component.get("group", ""),
            },
        )

    def _detect_ecosystem(self, purl: str, component: dict) -> Ecosystem:
        """Detect the ecosystem from PURL or component metadata."""
        if purl:
            # Extract type from PURL: "pkg:TYPE/..." 
            try:
                purl_type = purl.split(":")[1].split("/")[0]
                return _PURL_TYPE_TO_ECOSYSTEM.get(purl_type, Ecosystem.UNKNOWN)
            except (IndexError, ValueError):
                pass

        # Fallback: guess from component type or properties
        comp_type = component.get("type", "")
        if comp_type == "operating-system":
            return Ecosystem.OS_DPKG  # Default OS type

        return Ecosystem.UNKNOWN

    def _extract_license(self, component: dict) -> Optional[str]:
        """Extract SPDX license ID from CycloneDX component."""
        licenses = component.get("licenses", [])
        if not licenses:
            return None

        for lic in licenses:
            if isinstance(lic, dict):
                # CycloneDX license object
                license_obj = lic.get("license", lic)
                spdx_id = license_obj.get("id")
                if spdx_id:
                    return spdx_id
                name = license_obj.get("name")
                if name:
                    return name

        return None

    def _extract_hash(self, component: dict) -> Optional[str]:
        """Extract SHA-256 hash from CycloneDX component."""
        hashes = component.get("hashes", [])
        for h in hashes:
            if isinstance(h, dict) and h.get("alg", "").upper() in ("SHA-256", "SHA256"):
                return h.get("content")
        return None

    # -------------------------------------------------------------------
    # SBOM file management
    # -------------------------------------------------------------------

    def _save_sbom(
        self,
        sbom: dict,
        target_value: str,
        output_dir: str,
        index: int,
    ) -> None:
        """Save raw SBOM JSON to the output directory."""
        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)

        # Create a safe filename from target value
        safe_name = (
            target_value
            .replace("/", "_")
            .replace(":", "_")
            .replace(" ", "_")
        )[:60]

        filename = f"syft_sbom_{index}_{safe_name}.json"
        filepath = out_path / filename

        with open(filepath, "w") as f:
            json.dump(sbom, f, indent=2)

        log.info("sbom_saved", path=str(filepath))
