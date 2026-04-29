"""Dependency Merger plugin — Phase 5.

Deduplicates and merges dependencies from all prior phases into a
single, clean "golden SBOM". When the same library is found by
multiple scanners, the merger applies conflict resolution rules
to produce one authoritative record.

Resolution hierarchy (highest wins):
    1. Runtime-validated (pip freeze, npm list)  → confidence 0.99
    2. Lock file (package-lock.json, poetry.lock) → confidence 0.95
    3. System scanner (Syft, dpkg)                → confidence 0.85
    4. CDN URL / Fingerprint                      → confidence 0.70-0.85
    5. Manifest (package.json ranges)             → confidence 0.50
    6. Source map / Inferred                       → confidence 0.30

Merge rules:
    - Group by normalized PURL or name+ecosystem key
    - Pick the version with highest confidence
    - Merge all sources (provenance chain)
    - Keep metadata from all scanners
    - Deduplicate vulnerabilities by CVE ID

Config example:
    - plugin: "dependency_merger"
      enabled: true
      config:
        normalize_names: true       # lodash.js → lodash
        merge_cdn_and_npm: true     # Treat CDN lodash same as npm lodash
        drop_no_version: false      # Keep deps with no version?
        prefer_locked: true         # Always prefer lock file version
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Optional

from depnova.core.models import (
    ConfidenceLevel,
    Dependency,
    DependencyGraph,
    Ecosystem,
    Vulnerability,
)
from depnova.plugins.base import BasePlugin, PipelineContext
from depnova.utils.logger import get_logger

log = get_logger(__name__)

# Ecosystems that represent the same "npm" package universe
_NPM_FAMILY = {Ecosystem.NPM, Ecosystem.CDN, Ecosystem.STATIC, Ecosystem.YARN, Ecosystem.PNPM}


class DependencyMerger(BasePlugin):
    """Merges and deduplicates dependencies from all prior pipeline phases.

    This plugin runs AFTER all scanners/fingerprinters. It reads the
    accumulated results from the pipeline context and produces a
    single, deduplicated DependencyGraph.

    Config options:
        normalize_names:    Normalize package names (default: true)
        merge_cdn_and_npm:  Treat CDN + NPM + static as same ecosystem (default: true)
        drop_no_version:    Remove deps with no version info (default: false)
        prefer_locked:      Always prefer lock file version over others (default: true)
    """

    def get_name(self) -> str:
        return "dependency_merger"

    def get_phase(self) -> int:
        return 5

    def get_description(self) -> str:
        return "Merge and deduplicate dependencies from all scanners using conflict resolution"

    def get_supported_ecosystems(self) -> list[str]:
        return ["all"]

    def scan(self, context: PipelineContext) -> DependencyGraph:
        """Merge all prior results into one deduplicated graph."""
        graph = DependencyGraph(source_plugin=self.get_name())

        normalize = self.config.get("normalize_names", True)
        merge_npm = self.config.get("merge_cdn_and_npm", True)
        drop_empty = self.config.get("drop_no_version", False)
        prefer_locked = self.config.get("prefer_locked", True)

        # Step 1: Collect ALL dependencies from prior plugins
        all_deps: list[Dependency] = []
        all_vulns: list[Vulnerability] = []

        for plugin_name, result_graph in context.plugin_results.items():
            if plugin_name == self.get_name():
                continue  # Don't merge our own results
            if isinstance(result_graph, DependencyGraph):
                all_deps.extend(result_graph.dependencies)
                all_vulns.extend(result_graph.vulnerabilities)
                log.debug(
                    "merger_source",
                    plugin=plugin_name,
                    deps=result_graph.dependency_count,
                    vulns=len(result_graph.vulnerabilities),
                )

        log.info("merger_input", total_deps=len(all_deps), total_vulns=len(all_vulns))

        if not all_deps:
            graph.add_warning("No dependencies to merge — were any scanners enabled?")
            return graph

        # Step 2: Group dependencies by merge key
        groups: dict[str, list[Dependency]] = defaultdict(list)

        for dep in all_deps:
            key = self._merge_key(dep, normalize, merge_npm)
            groups[key].append(dep)

        log.info("merger_groups", unique_keys=len(groups), total_deps=len(all_deps))

        # Step 3: Resolve each group into one dependency
        for key, deps_in_group in groups.items():
            merged = self._resolve_group(deps_in_group, prefer_locked)

            # Optionally drop deps with no version
            if drop_empty and not merged.version:
                continue

            graph.add_dependency(merged)

        # Step 4: Deduplicate vulnerabilities by CVE ID
        seen_vulns: set[str] = set()
        for vuln in all_vulns:
            if vuln.vuln_id not in seen_vulns:
                seen_vulns.add(vuln.vuln_id)
                graph.vulnerabilities.append(vuln)

        # Step 5: Generate merge statistics
        stats = self._compute_stats(all_deps, graph)
        graph.metadata["merge_stats"] = stats
        context.set_shared("merged_sbom", graph)

        log.info(
            "merger_complete",
            input_deps=len(all_deps),
            output_deps=graph.dependency_count,
            duplicates_removed=len(all_deps) - graph.dependency_count,
            vulns=len(graph.vulnerabilities),
        )

        return graph

    # -------------------------------------------------------------------
    # Merge key generation
    # -------------------------------------------------------------------

    def _merge_key(self, dep: Dependency, normalize: bool, merge_npm: bool) -> str:
        """Generate a merge key for grouping duplicates.

        Two dependencies with the same merge key will be merged into one.

        Strategy:
            - Normalize the name (lowercase, strip .js suffix)
            - Group npm/cdn/static/yarn/pnpm as same family
            - Use name + normalized ecosystem as key
        """
        name = dep.name

        if normalize:
            name = self._normalize_name(name)

        # Map ecosystem family
        eco = dep.ecosystem
        if merge_npm and eco in _NPM_FAMILY:
            eco_key = "js"  # All JavaScript ecosystems merge together
        else:
            eco_key = eco.value

        return f"{eco_key}:{name}"

    def _normalize_name(self, name: str) -> str:
        """Normalize a package name for deduplication.

        Examples:
            "Lodash" → "lodash"
            "moment.js" → "moment"
            "jQuery" → "jquery"
            "@sentry/browser" → "@sentry/browser"  (keep scoped names)
        """
        # Lowercase
        normalized = name.lower().strip()

        # Remove common suffixes
        for suffix in (".js", ".css", ".min"):
            if normalized.endswith(suffix) and not normalized.startswith("@"):
                normalized = normalized[: -len(suffix)]

        # Handle known aliases
        normalized = _NAME_ALIASES.get(normalized, normalized)

        return normalized

    # -------------------------------------------------------------------
    # Group resolution
    # -------------------------------------------------------------------

    def _resolve_group(self, deps: list[Dependency], prefer_locked: bool) -> Dependency:
        """Resolve a group of duplicate deps into one winner.

        Rules:
            1. If prefer_locked and any dep is from a lock file → use that version
            2. Otherwise pick the dep with highest confidence
            3. Merge all sources into the winner
            4. Keep the highest confidence score
            5. Merge metadata from all entries
        """
        if len(deps) == 1:
            return deps[0]

        # Sort by confidence (descending), then by version presence
        sorted_deps = sorted(
            deps,
            key=lambda d: (
                # Lock file gets priority if prefer_locked is on
                1 if prefer_locked and "lockfile" in d.sources else 0,
                # Higher confidence wins
                d.confidence,
                # Prefer entries WITH a version over those without
                1 if d.version else 0,
            ),
            reverse=True,
        )

        # The winner is the highest-ranked dep
        winner = sorted_deps[0]

        # Create a merged copy
        merged = Dependency(
            name=winner.name,
            version=winner.version,
            ecosystem=winner.ecosystem,
            purl=winner.purl,
            is_direct=any(d.is_direct for d in deps),
            is_dev=all(d.is_dev for d in deps),  # Only dev if ALL are dev
            confidence=max(d.confidence for d in deps),
            sources=list(winner.sources),
            license_id=winner.license_id,
            hash_sha256=winner.hash_sha256,
            cpe=winner.cpe,
            location=winner.location,
            metadata=dict(winner.metadata),
        )

        # Merge in data from other entries
        for dep in sorted_deps[1:]:
            # Merge sources
            for src in dep.sources:
                if src not in merged.sources:
                    merged.sources.append(src)

            # Fill in missing fields from lower-priority entries
            if not merged.version and dep.version:
                merged.version = dep.version
                merged.purl = dep.purl

            if not merged.license_id and dep.license_id:
                merged.license_id = dep.license_id

            if not merged.hash_sha256 and dep.hash_sha256:
                merged.hash_sha256 = dep.hash_sha256

            if not merged.cpe and dep.cpe:
                merged.cpe = dep.cpe

            # Merge metadata (without overwriting)
            for k, v in dep.metadata.items():
                if k not in merged.metadata:
                    merged.metadata[k] = v

        # Record merge info
        merged.metadata["merged_from"] = len(deps)
        merged.metadata["all_sources"] = merged.sources.copy()
        merged.metadata["merge_details"] = [
            {
                "source": d.sources[0] if d.sources else "unknown",
                "version": d.version,
                "confidence": d.confidence,
                "location": d.location,
            }
            for d in sorted_deps
        ]

        return merged

    # -------------------------------------------------------------------
    # Statistics
    # -------------------------------------------------------------------

    def _compute_stats(
        self,
        input_deps: list[Dependency],
        output_graph: DependencyGraph,
    ) -> dict:
        """Compute merge statistics for reporting."""
        # Count by ecosystem
        eco_before: dict[str, int] = defaultdict(int)
        eco_after: dict[str, int] = defaultdict(int)

        for d in input_deps:
            eco_before[d.ecosystem.value] += 1
        for d in output_graph.dependencies:
            eco_after[d.ecosystem.value] += 1

        # Count multi-source deps (found by >1 scanner)
        multi_source = sum(
            1 for d in output_graph.dependencies
            if len(d.sources) > 1
        )

        # Count version upgrades (version filled from a higher-confidence source)
        versioned = sum(1 for d in output_graph.dependencies if d.version)

        return {
            "input_total": len(input_deps),
            "output_total": output_graph.dependency_count,
            "duplicates_removed": len(input_deps) - output_graph.dependency_count,
            "multi_source_deps": multi_source,
            "versioned_deps": versioned,
            "unversioned_deps": output_graph.dependency_count - versioned,
            "ecosystems_before": dict(eco_before),
            "ecosystems_after": dict(eco_after),
        }


# ---------------------------------------------------------------------------
# Name aliases for deduplication
# ---------------------------------------------------------------------------

_NAME_ALIASES: dict[str, str] = {
    "jquery": "jquery",
    "moment": "moment",
    "lodash": "lodash",
    "underscore": "underscore",
    "backbone": "backbone",
    "ember-source": "ember-source",
    "chart": "chart.js",
    "chartjs": "chart.js",
    "d3js": "d3",
    "vuejs": "vue",
    "reactjs": "react",
    "angular": "angular",
    "angularjs": "angular",
    "font-awesome": "font-awesome",
    "fontawesome": "font-awesome",
}
