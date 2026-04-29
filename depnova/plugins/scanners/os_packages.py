"""OS package scanner plugin — Phase 2.

Directly queries installed OS package managers (dpkg, rpm, apk)
to enumerate all system-level packages. This serves as:
  - A fallback when Syft is not available
  - A complement to Syft for bare-metal / VM environments
  - An independent validation source for container scans

Each package manager is queried via standard CLI commands:
  - dpkg:  `dpkg-query -W -f '${Package}\t${Version}\t${Architecture}\n'`
  - rpm:   `rpm -qa --queryformat '%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n'`
  - apk:   `apk list --installed`

Config example:
    - plugin: "os_package_scanner"
      enabled: true
      config:
        package_managers: ["dpkg", "rpm", "apk"]  # Which to query
        auto_detect: true                          # Auto-detect which are available
        include_architecture: true                 # Include arch in metadata
"""

from __future__ import annotations

import re
import shutil
import subprocess
from typing import Optional

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


class OSPackageScanner(BasePlugin):
    """Scans OS package managers for installed system packages.

    Queries dpkg, rpm, and/or apk directly via CLI commands.
    Useful for bare-metal servers, VMs, or as a Syft fallback.

    Config options:
        package_managers:     List of package managers to query
                              ["dpkg", "rpm", "apk"] (default: auto-detect)
        auto_detect:          If true, detect which PMs are available (default: true)
        include_architecture: Include package architecture in metadata (default: true)
        timeout_seconds:      Max time per PM query (default: 60)
    """

    def get_name(self) -> str:
        return "os_package_scanner"

    def get_phase(self) -> int:
        return 2

    def get_description(self) -> str:
        return "Query OS package managers (dpkg, rpm, apk) for installed system packages"

    def get_supported_ecosystems(self) -> list[str]:
        return ["deb", "rpm", "apk"]

    def scan(self, context: PipelineContext) -> DependencyGraph:
        """Query each configured/detected package manager."""
        graph = DependencyGraph(source_plugin=self.get_name())

        auto_detect = self.config.get("auto_detect", True)
        requested_pms = self.config.get("package_managers", [])
        timeout = self.config.get("timeout_seconds", 60)
        include_arch = self.config.get("include_architecture", True)

        # Determine which package managers to query
        if auto_detect and not requested_pms:
            pms_to_query = self._detect_package_managers()
        elif requested_pms:
            pms_to_query = [pm for pm in requested_pms if self._is_available(pm)]
            missing = set(requested_pms) - set(pms_to_query)
            for pm in missing:
                graph.add_warning(f"Requested package manager '{pm}' not found on this system")
        else:
            pms_to_query = self._detect_package_managers()

        if not pms_to_query:
            log.info("no_package_managers_found")
            graph.add_warning("No supported OS package managers detected on this system")
            return graph

        log.info("os_scan_starting", package_managers=pms_to_query)

        # Dispatch to specific parsers
        pm_handlers = {
            "dpkg": self._scan_dpkg,
            "rpm": self._scan_rpm,
            "apk": self._scan_apk,
        }

        for pm in pms_to_query:
            handler = pm_handlers.get(pm)
            if not handler:
                graph.add_warning(f"No handler for package manager: {pm}")
                continue

            log.info("scanning_pm", package_manager=pm)

            try:
                deps = handler(timeout, include_arch)
                for dep in deps:
                    graph.add_dependency(dep)
                log.info("pm_scan_complete", package_manager=pm, packages=len(deps))
            except Exception as e:
                msg = f"Failed to scan {pm}: {e}"
                log.error("pm_scan_failed", package_manager=pm, error=str(e))
                graph.add_error(msg)

        log.info("os_scan_complete", total_packages=graph.dependency_count)
        return graph

    # -------------------------------------------------------------------
    # Package manager detection
    # -------------------------------------------------------------------

    def _detect_package_managers(self) -> list[str]:
        """Auto-detect which package managers are available."""
        detected = []

        # dpkg (Debian/Ubuntu)
        if self._is_available("dpkg"):
            detected.append("dpkg")

        # rpm (RHEL/CentOS/Fedora)
        if self._is_available("rpm"):
            detected.append("rpm")

        # apk (Alpine)
        if self._is_available("apk"):
            detected.append("apk")

        log.debug("detected_package_managers", pms=detected)
        return detected

    def _is_available(self, pm: str) -> bool:
        """Check if a package manager command is available."""
        cmd_map = {
            "dpkg": "dpkg-query",
            "rpm": "rpm",
            "apk": "apk",
        }
        cmd = cmd_map.get(pm, pm)
        return shutil.which(cmd) is not None

    # -------------------------------------------------------------------
    # dpkg scanner (Debian/Ubuntu/Kali)
    # -------------------------------------------------------------------

    def _scan_dpkg(self, timeout: int, include_arch: bool) -> list[Dependency]:
        """Query dpkg for installed packages.

        Uses dpkg-query with a custom format for clean parsing.
        Output format: package\tversion\tarchitecture\tstatus
        """
        cmd = [
            "dpkg-query", "-W",
            "-f", "${Package}\t${Version}\t${Architecture}\t${db:Status-Abbrev}\n",
        ]

        output = self._run_command(cmd, timeout)
        if output is None:
            return []

        deps: list[Dependency] = []

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            parts = line.split("\t")
            if len(parts) < 2:
                continue

            name = parts[0].strip()
            version = parts[1].strip()
            arch = parts[2].strip() if len(parts) > 2 else ""
            status = parts[3].strip() if len(parts) > 3 else ""

            # Skip packages that aren't fully installed
            # Status "ii" = installed, "rc" = removed but config remains
            if status and not status.startswith("ii"):
                continue

            if not name or not version:
                continue

            # Build qualifiers for PURL
            qualifiers = {}
            if include_arch and arch:
                qualifiers["arch"] = arch

            # Debian packages may have epoch: "1:2.3.4-5"
            normalized_ver = normalize_version(version)

            purl = generate_purl(
                name, version, Ecosystem.OS_DPKG,
                qualifiers=qualifiers if qualifiers else None,
            )

            metadata = {"original_version": version}
            if include_arch and arch:
                metadata["architecture"] = arch

            deps.append(Dependency(
                name=name,
                version=normalized_ver,
                ecosystem=Ecosystem.OS_DPKG,
                purl=purl,
                is_direct=True,  # All OS packages are "direct" in this context
                is_dev=False,
                confidence=ConfidenceLevel.SCANNED,
                sources=[SourceType.OS_QUERY.value],
                location="dpkg",
                metadata=metadata,
            ))

        return deps

    # -------------------------------------------------------------------
    # rpm scanner (RHEL/CentOS/Fedora)
    # -------------------------------------------------------------------

    def _scan_rpm(self, timeout: int, include_arch: bool) -> list[Dependency]:
        """Query rpm for installed packages.

        Uses rpm -qa with queryformat for structured output.
        """
        cmd = [
            "rpm", "-qa",
            "--queryformat", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n",
        ]

        output = self._run_command(cmd, timeout)
        if output is None:
            return []

        deps: list[Dependency] = []

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            parts = line.split("\t")
            if len(parts) < 2:
                continue

            name = parts[0].strip()
            version = parts[1].strip()
            arch = parts[2].strip() if len(parts) > 2 else ""

            if not name or not version:
                continue

            # Build qualifiers
            qualifiers = {}
            if include_arch and arch:
                qualifiers["arch"] = arch

            purl = generate_purl(
                name, version, Ecosystem.OS_RPM,
                qualifiers=qualifiers if qualifiers else None,
            )

            metadata = {}
            if include_arch and arch:
                metadata["architecture"] = arch

            deps.append(Dependency(
                name=name,
                version=normalize_version(version),
                ecosystem=Ecosystem.OS_RPM,
                purl=purl,
                is_direct=True,
                is_dev=False,
                confidence=ConfidenceLevel.SCANNED,
                sources=[SourceType.OS_QUERY.value],
                location="rpm",
                metadata=metadata,
            ))

        return deps

    # -------------------------------------------------------------------
    # apk scanner (Alpine Linux)
    # -------------------------------------------------------------------

    def _scan_apk(self, timeout: int, include_arch: bool) -> list[Dependency]:
        """Query apk for installed packages.

        Uses 'apk list --installed' which outputs:
            package-name-1.2.3-r0 x86_64 {origin} (license) [installed]
        """
        cmd = ["apk", "list", "--installed"]

        output = self._run_command(cmd, timeout)
        if output is None:
            return []

        deps: list[Dependency] = []

        # Pattern: name-version arch {origin} (license) [status]
        # Example: curl-8.1.2-r0 x86_64 {curl} (MIT) [installed]
        pattern = re.compile(
            r"^(.+?)-(\d[\d.]*(?:-r\d+)?)\s+(\S+)\s+"
            r"\{([^}]*)\}\s+\(([^)]*)\)\s+\[(\w+)\]"
        )

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            match = pattern.match(line)
            if not match:
                # Simpler fallback: name-version arch
                simple = re.match(r"^(.+?)-(\d[\d.]*\S*)\s+(\S+)", line)
                if simple:
                    name = simple.group(1)
                    version = simple.group(2)
                    arch = simple.group(3)
                else:
                    continue
            else:
                name = match.group(1)
                version = match.group(2)
                arch = match.group(3)

            if not name or not version:
                continue

            qualifiers = {}
            if include_arch and arch:
                qualifiers["arch"] = arch

            purl = generate_purl(
                name, version, Ecosystem.OS_APK,
                qualifiers=qualifiers if qualifiers else None,
            )

            metadata = {}
            if include_arch and arch:
                metadata["architecture"] = arch
            if match:
                metadata["origin"] = match.group(4)
                metadata["license"] = match.group(5)

            deps.append(Dependency(
                name=name,
                version=normalize_version(version),
                ecosystem=Ecosystem.OS_APK,
                purl=purl,
                is_direct=True,
                is_dev=False,
                confidence=ConfidenceLevel.SCANNED,
                sources=[SourceType.OS_QUERY.value],
                location="apk",
                metadata=metadata,
            ))

        return deps

    # -------------------------------------------------------------------
    # Command execution helper
    # -------------------------------------------------------------------

    def _run_command(self, cmd: list[str], timeout: int) -> Optional[str]:
        """Run a shell command and return stdout.

        Args:
            cmd:     Command and arguments
            timeout: Max seconds

        Returns:
            stdout string, or None on failure
        """
        log.debug("running_command", cmd=" ".join(cmd))

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )

            if result.returncode != 0:
                log.warning(
                    "command_failed",
                    cmd=cmd[0],
                    returncode=result.returncode,
                    stderr=result.stderr[:300],
                )
                return None

            return result.stdout

        except subprocess.TimeoutExpired:
            log.error("command_timeout", cmd=cmd[0], timeout=timeout)
            return None
        except FileNotFoundError:
            log.error("command_not_found", cmd=cmd[0])
            return None
        except Exception as e:
            log.error("command_error", cmd=cmd[0], error=str(e))
            return None
