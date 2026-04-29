"""Report generator plugin — Phase 6.

Generates output reports from the merged dependency graph:
    - CycloneDX JSON SBOM (industry standard, machine-readable)
    - HTML report (human-readable, for management/auditors)
    - CSV export (spreadsheet-friendly)
    - Console summary (terminal output)

Config example:
    - plugin: "report_generator"
      enabled: true
      config:
        formats: ["cyclonedx-json", "html", "csv"]
        output_dir: "./depnova-reports"
        include_vulnerabilities: true
        include_metadata: true
"""

from __future__ import annotations

import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from depnova.core.models import (
    Dependency,
    DependencyGraph,
    Vulnerability,
)
from depnova.plugins.base import BasePlugin, PipelineContext
from depnova.utils.logger import get_logger

log = get_logger(__name__)


class ReportGenerator(BasePlugin):
    """Generates SBOM and vulnerability reports in multiple formats.

    Config options:
        formats:                List of output formats to generate
        output_dir:             Override output directory (default: from project config)
        include_vulnerabilities: Include vulnerability data (default: true)
        include_metadata:       Include plugin metadata (default: true)
        project_name:           Override project name for reports
    """

    def get_name(self) -> str:
        return "report_generator"

    def get_phase(self) -> int:
        return 6

    def get_description(self) -> str:
        return "Generate SBOM reports (CycloneDX JSON, HTML, CSV)"

    def get_supported_ecosystems(self) -> list[str]:
        return ["all"]

    def scan(self, context: PipelineContext) -> DependencyGraph:
        """Generate reports from the pipeline results."""
        graph = DependencyGraph(source_plugin=self.get_name())

        formats = self.config.get("formats", ["cyclonedx-json", "html", "csv"])
        output_dir = Path(self.config.get("output_dir", context.output_dir))
        output_dir.mkdir(parents=True, exist_ok=True)

        include_vulns = self.config.get("include_vulnerabilities", True)
        include_meta = self.config.get("include_metadata", True)

        # Collect ALL deps and vulns from prior plugins
        all_deps: list[Dependency] = []
        all_vulns: list[Vulnerability] = []
        for name, result in context.plugin_results.items():
            if name == self.get_name():
                continue
            if isinstance(result, DependencyGraph):
                all_deps.extend(result.dependencies)
                all_vulns.extend(result.vulnerabilities)

        # If merger ran, prefer its output (deduplicated)
        merged = context.get_shared("merged_sbom")
        if merged and isinstance(merged, DependencyGraph):
            all_deps = merged.dependencies
            all_vulns = merged.vulnerabilities
            log.info("using_merged_sbom", deps=len(all_deps))

        project_name = self.config.get(
            "project_name",
            context.global_config.get("project", {}).get("name", "depnova-project"),
        )

        # Generate each requested format
        generated_files = []

        if "cyclonedx-json" in formats:
            path = self._generate_cyclonedx(
                all_deps, all_vulns, output_dir, project_name, include_meta
            )
            generated_files.append(("CycloneDX JSON", str(path)))

        if "html" in formats:
            path = self._generate_html(
                all_deps, all_vulns, output_dir, project_name
            )
            generated_files.append(("HTML Report", str(path)))

        if "csv" in formats:
            path = self._generate_csv(all_deps, output_dir)
            generated_files.append(("CSV Export", str(path)))

        # Log generated files
        for fmt, fpath in generated_files:
            log.info("report_generated", format=fmt, path=fpath)

        graph.metadata["generated_reports"] = generated_files
        return graph

    # -------------------------------------------------------------------
    # CycloneDX JSON SBOM
    # -------------------------------------------------------------------

    def _generate_cyclonedx(
        self,
        deps: list[Dependency],
        vulns: list[Vulnerability],
        output_dir: Path,
        project_name: str,
        include_meta: bool,
    ) -> Path:
        """Generate a CycloneDX 1.4 JSON SBOM."""
        now = datetime.now(timezone.utc).isoformat()

        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "metadata": {
                "timestamp": now,
                "tools": [
                    {
                        "vendor": "DepNova",
                        "name": "depnova",
                        "version": "0.1.0",
                    }
                ],
                "component": {
                    "type": "application",
                    "name": project_name,
                },
            },
            "components": [],
            "vulnerabilities": [],
        }

        # Add components
        for dep in deps:
            component = {
                "type": "library",
                "name": dep.name,
                "version": dep.version or "",
            }

            if dep.purl:
                component["purl"] = dep.purl

            if dep.license_id:
                component["licenses"] = [{"license": {"id": dep.license_id}}]

            if dep.hash_sha256:
                component["hashes"] = [{"alg": "SHA-256", "content": dep.hash_sha256}]

            if dep.cpe:
                component["cpe"] = dep.cpe

            if include_meta:
                props = []
                props.append({"name": "depnova:ecosystem", "value": dep.ecosystem.value})
                props.append({"name": "depnova:confidence", "value": str(dep.confidence)})
                props.append({"name": "depnova:sources", "value": ",".join(dep.sources)})
                if dep.is_dev:
                    props.append({"name": "depnova:is_dev", "value": "true"})
                if dep.is_direct:
                    props.append({"name": "depnova:is_direct", "value": "true"})
                component["properties"] = props

            sbom["components"].append(component)

        # Add vulnerabilities
        for vuln in vulns:
            vuln_entry = {
                "id": vuln.vuln_id,
                "source": {"name": vuln.source or "retirejs"},
                "ratings": [
                    {
                        "severity": vuln.severity.value,
                        "score": vuln.score,
                    }
                ],
                "description": vuln.title or vuln.description,
            }

            if vuln.url:
                vuln_entry["advisories"] = [{"url": vuln.url}]

            if vuln.dependency_purl:
                vuln_entry["affects"] = [{"ref": vuln.dependency_purl}]

            sbom["vulnerabilities"].append(vuln_entry)

        filepath = output_dir / "sbom.cdx.json"
        with open(filepath, "w") as f:
            json.dump(sbom, f, indent=2)

        return filepath

    # -------------------------------------------------------------------
    # HTML Report
    # -------------------------------------------------------------------

    def _generate_html(
        self,
        deps: list[Dependency],
        vulns: list[Vulnerability],
        output_dir: Path,
        project_name: str,
    ) -> Path:
        """Generate a standalone HTML report."""
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        # Count by ecosystem
        eco_counts: dict[str, int] = {}
        for d in deps:
            eco = d.ecosystem.value
            eco_counts[eco] = eco_counts.get(eco, 0) + 1

        # Severity counts
        sev_counts: dict[str, int] = {}
        for v in vulns:
            s = v.severity.value
            sev_counts[s] = sev_counts.get(s, 0) + 1

        # Build dependency table rows
        dep_rows = ""
        for dep in sorted(deps, key=lambda d: (d.ecosystem.value, d.name)):
            conf_pct = f"{dep.confidence:.0%}"
            conf_class = "high" if dep.confidence >= 0.85 else "med" if dep.confidence >= 0.50 else "low"
            sources = ", ".join(dep.sources)
            dep_rows += f"""
            <tr>
                <td>{dep.name}</td>
                <td>{dep.version or '<span class="no-ver">unknown</span>'}</td>
                <td><span class="badge eco-{dep.ecosystem.value}">{dep.ecosystem.value}</span></td>
                <td><span class="conf conf-{conf_class}">{conf_pct}</span></td>
                <td class="sources">{sources}</td>
                <td class="purl">{dep.purl or '—'}</td>
            </tr>"""

        # Build vulnerability rows
        vuln_rows = ""
        for v in sorted(vulns, key=lambda x: x.severity.value):
            sev_class = v.severity.value
            vuln_rows += f"""
            <tr class="vuln-{sev_class}">
                <td><a href="{v.url}" target="_blank">{v.vuln_id}</a></td>
                <td><span class="badge sev-{sev_class}">{v.severity.value.upper()}</span></td>
                <td>{v.dependency_purl}</td>
                <td>{v.title[:120]}</td>
            </tr>"""

        # Ecosystem chart data
        eco_labels = list(eco_counts.keys())
        eco_values = list(eco_counts.values())

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DepNova Report — {project_name}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Inter', -apple-system, sans-serif; background: #0f172a; color: #e2e8f0; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        h1 {{ font-size: 1.8rem; margin-bottom: 5px; color: #f8fafc; }}
        .subtitle {{ color: #94a3b8; margin-bottom: 25px; }}
        .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 25px; }}
        .card {{ background: #1e293b; border-radius: 12px; padding: 20px; border: 1px solid #334155; }}
        .card .value {{ font-size: 2rem; font-weight: 700; color: #38bdf8; }}
        .card .label {{ font-size: 0.85rem; color: #94a3b8; margin-top: 4px; }}
        .card.danger .value {{ color: #f87171; }}
        .card.warning .value {{ color: #fbbf24; }}
        .card.success .value {{ color: #4ade80; }}
        table {{ width: 100%; border-collapse: collapse; background: #1e293b; border-radius: 12px; overflow: hidden; margin-bottom: 25px; }}
        th {{ background: #334155; padding: 12px 15px; text-align: left; font-size: 0.85rem; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.05em; }}
        td {{ padding: 10px 15px; border-top: 1px solid #334155; font-size: 0.9rem; }}
        tr:hover {{ background: #273548; }}
        .badge {{ padding: 3px 8px; border-radius: 6px; font-size: 0.75rem; font-weight: 600; }}
        .sev-critical {{ background: #991b1b; color: #fecaca; }}
        .sev-high {{ background: #92400e; color: #fde68a; }}
        .sev-medium {{ background: #854d0e; color: #fef08a; }}
        .sev-low {{ background: #1e3a5f; color: #93c5fd; }}
        .eco-npm, .eco-cdn, .eco-static {{ background: #164e63; color: #67e8f9; }}
        .eco-pypi {{ background: #1e3a5f; color: #93c5fd; }}
        .eco-maven {{ background: #3b0764; color: #d8b4fe; }}
        .eco-deb {{ background: #14532d; color: #86efac; }}
        .conf {{ padding: 2px 6px; border-radius: 4px; font-size: 0.8rem; font-weight: 600; }}
        .conf-high {{ color: #4ade80; }}
        .conf-med {{ color: #fbbf24; }}
        .conf-low {{ color: #f87171; }}
        .no-ver {{ color: #f87171; font-style: italic; }}
        .sources {{ font-size: 0.8rem; color: #94a3b8; }}
        .purl {{ font-size: 0.75rem; color: #64748b; font-family: monospace; }}
        h2 {{ margin: 20px 0 15px; color: #f8fafc; }}
        .section {{ margin-bottom: 30px; }}
        .vuln-critical td {{ border-left: 3px solid #ef4444; }}
        .vuln-high td {{ border-left: 3px solid #f59e0b; }}
        .vuln-medium td {{ border-left: 3px solid #eab308; }}
        a {{ color: #38bdf8; text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
        .footer {{ text-align: center; padding: 20px; color: #64748b; font-size: 0.8rem; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ DepNova Security Report</h1>
        <p class="subtitle">{project_name} — Generated {now}</p>

        <div class="cards">
            <div class="card">
                <div class="value">{len(deps)}</div>
                <div class="label">Total Dependencies</div>
            </div>
            <div class="card">
                <div class="value">{len(eco_counts)}</div>
                <div class="label">Ecosystems</div>
            </div>
            <div class="card {'danger' if len(vulns) > 0 else 'success'}">
                <div class="value">{len(vulns)}</div>
                <div class="label">Vulnerabilities</div>
            </div>
            <div class="card {'danger' if sev_counts.get('critical', 0) + sev_counts.get('high', 0) > 0 else 'success'}">
                <div class="value">{sev_counts.get('critical', 0) + sev_counts.get('high', 0)}</div>
                <div class="label">Critical + High</div>
            </div>
        </div>

        {"<div class='section'><h2>🚨 Vulnerabilities</h2><table><thead><tr><th>CVE ID</th><th>Severity</th><th>Package</th><th>Summary</th></tr></thead><tbody>" + vuln_rows + "</tbody></table></div>" if vulns else ""}

        <div class="section">
            <h2>📦 Dependencies ({len(deps)})</h2>
            <table>
                <thead>
                    <tr>
                        <th>Name</th>
                        <th>Version</th>
                        <th>Ecosystem</th>
                        <th>Confidence</th>
                        <th>Sources</th>
                        <th>PURL</th>
                    </tr>
                </thead>
                <tbody>{dep_rows}</tbody>
            </table>
        </div>

        <div class="footer">
            Generated by DepNova v0.1.0 • {now}
        </div>
    </div>
</body>
</html>"""

        filepath = output_dir / "report.html"
        with open(filepath, "w") as f:
            f.write(html)

        return filepath

    # -------------------------------------------------------------------
    # CSV Export
    # -------------------------------------------------------------------

    def _generate_csv(self, deps: list[Dependency], output_dir: Path) -> Path:
        """Generate a CSV file with all dependencies."""
        filepath = output_dir / "dependencies.csv"

        with open(filepath, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                "Name", "Version", "Ecosystem", "PURL", "Confidence",
                "Sources", "Direct", "Dev", "License", "Location",
            ])

            for dep in sorted(deps, key=lambda d: (d.ecosystem.value, d.name)):
                writer.writerow([
                    dep.name,
                    dep.version,
                    dep.ecosystem.value,
                    dep.purl,
                    f"{dep.confidence:.0%}",
                    " | ".join(dep.sources),
                    "Yes" if dep.is_direct else "No",
                    "Yes" if dep.is_dev else "No",
                    dep.license_id or "",
                    dep.location or "",
                ])

        return filepath
