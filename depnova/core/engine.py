"""Pipeline engine — the core orchestrator for DepNova.

Loads config, discovers plugins, builds the pipeline from YAML,
and executes plugins in order. Handles errors gracefully per
the fail_on_error setting.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Optional

from depnova.core.config import DepNovaConfig, PluginEntry
from depnova.core.models import DependencyGraph
from depnova.core.plugin_loader import discover_plugins, get_plugin_class
from depnova.plugins.base import BasePlugin, PipelineContext
from depnova.utils.logger import get_logger

log = get_logger(__name__)


class Engine:
    """The DepNova pipeline engine.

    Responsibilities:
        1. Load and validate config
        2. Discover available plugins
        3. Build the execution pipeline from config
        4. Execute plugins in order, passing context
        5. Collect and return results

    Usage:
        engine = Engine(config)
        results = engine.run()
    """

    def __init__(self, config: DepNovaConfig):
        self.config = config
        self.context: Optional[PipelineContext] = None
        self._pipeline: list[tuple[PluginEntry, BasePlugin]] = []

    def run(
        self,
        phases: Optional[list[int]] = None,
        dry_run: bool = False,
    ) -> DependencyGraph:
        """Execute the full pipeline.

        Args:
            phases:  Optional list of phase numbers to run (e.g. [1, 2, 3]).
                     If None, runs all enabled plugins.
            dry_run: If True, show what would execute without running.

        Returns:
            Merged DependencyGraph with all results.
        """
        log.info("engine_starting", project=self.config.project.name)
        start_time = time.time()

        # Step 1: Discover all available plugins
        registry = discover_plugins()
        if not registry:
            log.error("no_plugins_found")
            graph = DependencyGraph(source_plugin="engine")
            graph.add_error("No plugins found. Check your installation.")
            return graph

        # Step 2: Build the pipeline from config
        self._build_pipeline(registry, phases)

        if not self._pipeline:
            log.warning("empty_pipeline", hint="No plugins matched the config or phase filter")
            graph = DependencyGraph(source_plugin="engine")
            graph.add_warning("No plugins to execute. Check your config.")
            return graph

        # Step 3: Dry run — just show the plan
        if dry_run:
            return self._dry_run()

        # Step 4: Create pipeline context
        project_root = str(Path(self.config.project.root_path).resolve())
        output_dir = str(Path(self.config.project.output_dir).resolve())
        Path(output_dir).mkdir(parents=True, exist_ok=True)

        self.context = PipelineContext(
            project_root=project_root,
            output_dir=output_dir,
            global_config=self.config.model_dump(),
        )

        # Step 5: Execute each plugin
        merged = DependencyGraph(source_plugin="engine")

        for entry, plugin in self._pipeline:
            result = self._execute_plugin(entry, plugin)
            if result:
                self.context.store_results(plugin.get_name(), result)
                merged.merge_from(result)

        # Step 6: Summary
        elapsed = time.time() - start_time
        log.info(
            "engine_complete",
            elapsed_seconds=round(elapsed, 2),
            **merged.summary(),
        )

        return merged

    def _build_pipeline(
        self,
        registry: dict[str, type[BasePlugin]],
        phases: Optional[list[int]] = None,
    ) -> None:
        """Build the ordered list of plugins to execute.

        Matches YAML pipeline entries to discovered plugin classes.
        Filters by enabled flag and optional phase filter.
        """
        self._pipeline = []

        for entry in self.config.pipeline:
            # Skip disabled plugins
            if not entry.enabled:
                log.debug("plugin_skipped_disabled", plugin=entry.plugin)
                continue

            # Find the plugin class
            plugin_class = registry.get(entry.plugin)
            if plugin_class is None:
                msg = f"Plugin '{entry.plugin}' not found in registry. Available: {list(registry.keys())}"
                log.warning("plugin_not_found", plugin=entry.plugin)
                if self.config.settings.fail_on_error:
                    raise ValueError(msg)
                continue

            # Create instance with config
            plugin = plugin_class(plugin_config=entry.config)

            # Filter by phase if specified
            if phases and plugin.get_phase() not in phases:
                log.debug("plugin_skipped_phase", plugin=entry.plugin,
                          phase=plugin.get_phase(), requested=phases)
                continue

            # Validate plugin config
            errors = plugin.validate_config()
            if errors:
                log.warning("plugin_config_invalid", plugin=entry.plugin, errors=errors)
                if self.config.settings.fail_on_error:
                    raise ValueError(f"Plugin '{entry.plugin}' config invalid: {errors}")
                continue

            self._pipeline.append((entry, plugin))

        log.info(
            "pipeline_built",
            plugin_count=len(self._pipeline),
            plugins=[p.get_name() for _, p in self._pipeline],
        )

    def _execute_plugin(
        self,
        entry: PluginEntry,
        plugin: BasePlugin,
    ) -> Optional[DependencyGraph]:
        """Execute a single plugin with error handling.

        Returns:
            DependencyGraph from the plugin, or None on failure.
        """
        name = plugin.get_name()
        phase = plugin.get_phase()

        log.info("plugin_executing", plugin=name, phase=phase)
        start = time.time()

        try:
            result = plugin.scan(self.context)
            elapsed = round(time.time() - start, 2)

            result.source_plugin = name
            log.info(
                "plugin_complete",
                plugin=name,
                elapsed_seconds=elapsed,
                dependencies_found=result.dependency_count,
                errors=len(result.errors),
                warnings=len(result.warnings),
            )
            return result

        except Exception as e:
            elapsed = round(time.time() - start, 2)
            log.error(
                "plugin_failed",
                plugin=name,
                phase=phase,
                error=str(e),
                elapsed_seconds=elapsed,
            )

            # Let the plugin handle its own error
            try:
                plugin.on_error(e)
            except Exception:
                pass

            if self.config.settings.fail_on_error:
                raise

            # Return a graph with just the error recorded
            error_graph = DependencyGraph(source_plugin=name)
            error_graph.add_error(f"Plugin '{name}' failed: {e}")
            return error_graph

    def _dry_run(self) -> DependencyGraph:
        """Show what the pipeline would execute without running anything."""
        log.info("dry_run_mode")

        graph = DependencyGraph(source_plugin="engine-dry-run")

        for i, (entry, plugin) in enumerate(self._pipeline, 1):
            log.info(
                "dry_run_step",
                step=i,
                plugin=plugin.get_name(),
                phase=plugin.get_phase(),
                description=plugin.get_description(),
                ecosystems=plugin.get_supported_ecosystems(),
                config_keys=list(entry.config.keys()),
            )

        graph.metadata["dry_run"] = True
        graph.metadata["planned_plugins"] = [p.get_name() for _, p in self._pipeline]
        return graph
