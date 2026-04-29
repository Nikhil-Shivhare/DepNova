"""Configuration loading and validation for DepNova.

Loads YAML config files, merges with defaults, and validates
using Pydantic models. The config drives the entire pipeline.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Optional

import yaml
from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Pydantic config models — these define & validate the YAML structure
# ---------------------------------------------------------------------------

class ProjectConfig(BaseModel):
    """Project-level configuration."""

    name: str = "unnamed-project"
    root_path: str = "."
    output_dir: str = "./depnova-reports"


class SettingsConfig(BaseModel):
    """Global settings."""

    log_level: str = "INFO"
    cache_enabled: bool = True
    cache_ttl_hours: int = 24
    fail_on_error: bool = False
    parallel_execution: bool = False

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        valid = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        upper = v.upper()
        if upper not in valid:
            raise ValueError(f"log_level must be one of {valid}, got '{v}'")
        return upper


class OutputConfig(BaseModel):
    """Output configuration."""

    format: str = "cyclonedx-json"
    include_provenance: bool = True
    include_confidence: bool = True


class PluginEntry(BaseModel):
    """A single plugin definition in the pipeline."""

    plugin: str                     # Plugin name (must match get_name())
    enabled: bool = True
    config: dict[str, Any] = Field(default_factory=dict)


class DepNovaConfig(BaseModel):
    """Root configuration model for DepNova.

    This is the full parsed + validated representation of the YAML config.
    """

    project: ProjectConfig = Field(default_factory=ProjectConfig)
    settings: SettingsConfig = Field(default_factory=SettingsConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)
    pipeline: list[PluginEntry] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Config loading functions
# ---------------------------------------------------------------------------

def load_config(config_path: Optional[str | Path] = None) -> DepNovaConfig:
    """Load and validate a DepNova configuration file.

    If no path is provided, looks for config in this order:
        1. ./depnova.yaml
        2. ./depnova.yml
        3. ./.depnova.yaml
        4. Falls back to default config

    Args:
        config_path: Optional explicit path to config file

    Returns:
        Validated DepNovaConfig object

    Raises:
        FileNotFoundError: If explicit config_path doesn't exist
        ValueError: If config file is invalid YAML or fails validation
    """
    if config_path:
        path = Path(config_path)
        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {path}")
        return _parse_config_file(path)

    # Auto-discover config
    search_paths = [
        Path("depnova.yaml"),
        Path("depnova.yml"),
        Path(".depnova.yaml"),
    ]

    for path in search_paths:
        if path.exists():
            return _parse_config_file(path)

    # No config found — use defaults
    return _get_default_config()


def _parse_config_file(path: Path) -> DepNovaConfig:
    """Parse a YAML config file and validate it.

    Args:
        path: Path to the YAML config file

    Returns:
        Validated DepNovaConfig
    """
    with open(path, "r") as f:
        raw = yaml.safe_load(f)

    if raw is None:
        raw = {}

    if not isinstance(raw, dict):
        raise ValueError(f"Config file {path} must contain a YAML mapping (dict), got {type(raw)}")

    return DepNovaConfig(**raw)


def _get_default_config() -> DepNovaConfig:
    """Return a default configuration with all phases enabled.

    This runs when no config file is found — provides sensible defaults
    so the tool works out of the box with zero configuration.
    """
    return DepNovaConfig(
        project=ProjectConfig(),
        settings=SettingsConfig(),
        output=OutputConfig(),
        pipeline=[
            PluginEntry(plugin="lockfile_scanner", enabled=True, config={
                "ecosystems": {
                    "npm": True, "yarn": True, "pnpm": True,
                    "poetry": True, "pipenv": True,
                    "gradle": True, "maven": True,
                    "cargo": True, "go_mod": True,
                },
                "include_dev_dependencies": False,
            }),
            PluginEntry(plugin="manifest_scanner", enabled=True, config={
                "files": ["requirements.txt", "setup.py", "setup.cfg", "pyproject.toml"],
                "mark_unpinned": True,
            }),
            PluginEntry(plugin="frontend_scanner", enabled=True, config={
                "html_scan_paths": [".", "./public", "./src", "./dist"],
                "detect_cdn": True,
                "scan_static_assets": True,
            }),
            PluginEntry(plugin="dependency_merger", enabled=True, config={
                "dedup_key": "purl",
                "normalize_versions": True,
                "tag_provenance": True,
            }),
            PluginEntry(plugin="report_generator", enabled=True, config={
                "formats": ["cyclonedx-json"],
            }),
        ],
    )


def write_default_config(output_path: str | Path = "depnova.yaml") -> Path:
    """Write a default config file to disk for user customization.

    Useful for `depnova init` CLI command.

    Args:
        output_path: Where to write the config

    Returns:
        Path to the written config file
    """
    path = Path(output_path)
    config = _get_default_config()

    # Convert to dict and write as YAML
    config_dict = config.model_dump()
    with open(path, "w") as f:
        yaml.dump(config_dict, f, default_flow_style=False, sort_keys=False, indent=2)

    return path
