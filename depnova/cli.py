"""DepNova CLI — command-line interface.

Built with Click for professional CLI with help text,
autocompletion, and subcommands.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from depnova import __version__
from depnova.core.config import load_config, write_default_config
from depnova.core.engine import Engine
from depnova.core.plugin_loader import discover_plugins, list_plugins
from depnova.utils.logger import setup_logging, get_logger


@click.group()
@click.version_option(version=__version__, prog_name="depnova")
def main():
    """DepNova — Comprehensive dependency inventory & CVE scanning.

    Scans backend, frontend, and OS dependencies from multiple sources
    and produces a unified, accurate SBOM.
    """
    pass


@main.command()
@click.option("--config", "-c", "config_path", default=None, help="Path to YAML config file")
@click.option("--phases", "-p", default=None, help="Comma-separated phase numbers to run (e.g. 1,2,3)")
@click.option("--dry-run", is_flag=True, help="Show execution plan without running")
@click.option("--log-level", "-l", default=None, help="Override log level (DEBUG/INFO/WARNING/ERROR)")
@click.option("--output-dir", "-o", default=None, help="Override output directory")
@click.option("--fail-on-error", is_flag=True, default=None, help="Abort pipeline on any plugin failure")
@click.option("--ci", is_flag=True, help="CI mode — exit code 1 if vulnerabilities found")
def scan(config_path, phases, dry_run, log_level, output_dir, fail_on_error, ci):
    """Run the dependency scanning pipeline.

    Examples:

        depnova scan

        depnova scan --config custom.yaml

        depnova scan --phases 1,2,3

        depnova scan --dry-run

        depnova scan --ci --fail-on-error
    """
    # Load config
    try:
        config = load_config(config_path)
    except (FileNotFoundError, ValueError) as e:
        click.secho(f"Config error: {e}", fg="red", err=True)
        sys.exit(1)

    # Apply CLI overrides
    if log_level:
        config.settings.log_level = log_level.upper()
    if output_dir:
        config.project.output_dir = output_dir
    if fail_on_error is not None:
        config.settings.fail_on_error = fail_on_error

    # Setup logging
    setup_logging(config.settings.log_level)
    log = get_logger("cli")

    # Parse phase filter
    phase_filter = None
    if phases:
        try:
            phase_filter = [int(p.strip()) for p in phases.split(",")]
        except ValueError:
            click.secho(f"Invalid phases: '{phases}'. Use comma-separated numbers.", fg="red", err=True)
            sys.exit(1)

    # Run the engine
    engine = Engine(config)
    result = engine.run(phases=phase_filter, dry_run=dry_run)

    # Print summary
    summary = result.summary()
    click.echo()
    click.secho("═" * 50, fg="cyan")
    click.secho("  DepNova Scan Summary", fg="cyan", bold=True)
    click.secho("═" * 50, fg="cyan")
    click.echo(f"  Dependencies found:  {summary['total_dependencies']}")
    click.echo(f"  Ecosystems:          {summary['ecosystems']}")
    click.echo(f"  Vulnerabilities:     {summary['vulnerabilities']}")
    click.echo(f"  Errors:              {summary['errors']}")
    click.echo(f"  Warnings:            {summary['warnings']}")
    click.secho("═" * 50, fg="cyan")

    # CI mode exit code
    if ci and summary["vulnerabilities"] > 0:
        click.secho(f"\nCI check FAILED: {summary['vulnerabilities']} vulnerabilities found", fg="red")
        sys.exit(1)

    if result.has_errors and fail_on_error:
        sys.exit(1)


@main.command()
@click.option("--output", "-o", default="depnova.yaml", help="Output config file path")
def init(output):
    """Generate a default config file for customization.

    Creates a depnova.yaml with all plugins and default settings.
    Edit this file to customize your scanning pipeline.
    """
    path = Path(output)
    if path.exists():
        if not click.confirm(f"{path} already exists. Overwrite?"):
            click.echo("Aborted.")
            return

    written = write_default_config(output)
    click.secho(f"✓ Default config written to: {written}", fg="green")
    click.echo("  Edit this file to customize your pipeline.")


@main.command(name="plugins")
def list_plugins_cmd():
    """List all available plugins."""
    setup_logging("WARNING")  # Suppress discovery logs
    discover_plugins()
    plugins = list_plugins()

    if not plugins:
        click.echo("No plugins found.")
        return

    click.secho("\nAvailable Plugins:", fg="cyan", bold=True)
    click.secho("-" * 70, fg="cyan")

    for p in sorted(plugins, key=lambda x: x.get("phase", 0)):
        phase = p.get("phase", "?")
        name = p.get("name", "unknown")
        desc = p.get("description", "")
        ecosystems = ", ".join(p.get("ecosystems", [])) or "all"

        click.echo(f"  Phase {phase} │ {name:<25} │ {ecosystems}")
        click.echo(f"         │ {desc}")
        click.echo()


@main.command()
@click.option("--config", "-c", "config_path", default=None, help="Config file to validate")
def validate(config_path):
    """Validate a config file without running the pipeline."""
    try:
        config = load_config(config_path)
        click.secho("✓ Config is valid", fg="green")
        click.echo(f"  Project:  {config.project.name}")
        click.echo(f"  Pipeline: {len(config.pipeline)} plugins configured")

        for entry in config.pipeline:
            status = "✓" if entry.enabled else "○"
            color = "green" if entry.enabled else "yellow"
            click.secho(f"    {status} {entry.plugin}", fg=color)

    except Exception as e:
        click.secho(f"✗ Config invalid: {e}", fg="red")
        sys.exit(1)


if __name__ == "__main__":
    main()
