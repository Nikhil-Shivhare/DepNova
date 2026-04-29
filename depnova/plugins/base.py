"""Abstract base class for all DepNova plugins.

Every scanner, validator, fingerprinter, and reporter must inherit from
BasePlugin and implement the required interface methods.  The engine
discovers plugins automatically and calls them in pipeline order.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from depnova.core.models import DependencyGraph


class BasePlugin(ABC):
    """Base class that all DepNova plugins must inherit from.

    Lifecycle:
        1. Engine loads plugin and calls __init__ with plugin config
        2. Engine calls validate_config() to check config is valid
        3. Engine calls scan() with the pipeline context
        4. If scan() raises, engine calls on_error() then continues
           (unless fail_on_error is set in global config)

    Subclasses MUST implement:
        - get_name()
        - get_phase()
        - scan()

    Subclasses MAY override:
        - validate_config()
        - on_error()
        - get_description()
        - get_supported_ecosystems()
    """

    def __init__(self, plugin_config: dict | None = None):
        """Initialize plugin with its config section from YAML.

        Args:
            plugin_config: The 'config' dict for this plugin from the YAML
                           pipeline definition. None if no config provided.
        """
        self.config = plugin_config or {}

    # -------------------------------------------------------------------
    # Required interface
    # -------------------------------------------------------------------

    @abstractmethod
    def get_name(self) -> str:
        """Return the unique plugin identifier.

        Must match the 'plugin' key in the YAML config.
        Example: "lockfile_scanner", "syft_scanner"
        """

    @abstractmethod
    def get_phase(self) -> int:
        """Return the phase number (1-6) this plugin belongs to.

        Used for ordering when the pipeline doesn't specify explicit order.
        Phase 1: Lock file / manifest extraction
        Phase 2: Container & OS inventory
        Phase 3: Frontend discovery
        Phase 4: Runtime validation
        Phase 5: Merge & deduplication
        Phase 6: CVE scanning & reporting
        """

    @abstractmethod
    def scan(self, context: PipelineContext) -> DependencyGraph:
        """Execute the plugin's core logic.

        This is the main entry point called by the engine.

        Args:
            context: Shared pipeline context containing project root,
                     results from previous plugins, and global settings.

        Returns:
            A DependencyGraph containing discovered dependencies,
            any errors, and warnings.
        """

    # -------------------------------------------------------------------
    # Optional overrides
    # -------------------------------------------------------------------

    def validate_config(self) -> list[str]:
        """Validate this plugin's configuration.

        Returns:
            List of validation error messages. Empty list = valid.
        """
        return []

    def on_error(self, error: Exception) -> None:
        """Called when scan() raises an exception.

        Override to implement custom error handling (e.g., cleanup,
        partial result saving). By default, does nothing.
        """
        pass

    def get_description(self) -> str:
        """Human-readable description of what this plugin does."""
        return f"Plugin: {self.get_name()} (Phase {self.get_phase()})"

    def get_supported_ecosystems(self) -> list[str]:
        """Return list of ecosystems this plugin can scan.

        Used by the engine for filtering and reporting.
        Override in subclasses to declare supported ecosystems.
        """
        return []

    # -------------------------------------------------------------------
    # Utility helpers available to all plugins
    # -------------------------------------------------------------------

    def _get_config_value(self, key: str, default: Any = None) -> Any:
        """Safely get a value from plugin config with a default."""
        return self.config.get(key, default)

    def _require_config_value(self, key: str) -> Any:
        """Get a required config value, raising if missing."""
        if key not in self.config:
            raise ValueError(
                f"Plugin '{self.get_name()}' requires config key '{key}' "
                f"but it was not provided."
            )
        return self.config[key]

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} name={self.get_name()} phase={self.get_phase()}>"


class PipelineContext:
    """Shared context passed to every plugin during pipeline execution.

    Contains project info, global settings, and results accumulated
    from plugins that have already executed.

    Attributes:
        project_root:     Absolute path to the project being scanned
        output_dir:       Where to write output files
        global_config:    The full parsed YAML config
        plugin_results:   Dict mapping plugin_name → DependencyGraph
        shared_data:      Arbitrary data plugins can share with later plugins
    """

    def __init__(
        self,
        project_root: str,
        output_dir: str,
        global_config: dict | None = None,
    ):
        self.project_root = project_root
        self.output_dir = output_dir
        self.global_config = global_config or {}
        self.plugin_results: dict[str, DependencyGraph] = {}
        self.shared_data: dict[str, Any] = {}

    def get_results(self, plugin_name: str) -> DependencyGraph | None:
        """Get the results from a previously executed plugin."""
        return self.plugin_results.get(plugin_name)

    def store_results(self, plugin_name: str, graph: DependencyGraph) -> None:
        """Store results from a plugin execution."""
        self.plugin_results[plugin_name] = graph

    def get_all_dependencies(self) -> list:
        """Get all dependencies discovered so far across all plugins."""
        all_deps = []
        for graph in self.plugin_results.values():
            all_deps.extend(graph.dependencies)
        return all_deps

    def set_shared(self, key: str, value: Any) -> None:
        """Store data for later plugins to consume."""
        self.shared_data[key] = value

    def get_shared(self, key: str, default: Any = None) -> Any:
        """Retrieve shared data from earlier plugins."""
        return self.shared_data.get(key, default)
