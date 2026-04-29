"""Dynamic plugin discovery and loading for DepNova.

Scans the plugins/ directory tree, imports all modules that contain
BasePlugin subclasses, and builds a registry mapping plugin names
to their classes. The engine uses this registry to instantiate plugins
based on the YAML pipeline config.
"""

from __future__ import annotations

import importlib
import pkgutil
from pathlib import Path
from typing import Type

from depnova.plugins.base import BasePlugin
from depnova.utils.logger import get_logger

log = get_logger(__name__)


# ---------------------------------------------------------------------------
# Plugin registry
# ---------------------------------------------------------------------------

# Global registry: plugin_name → plugin_class
_plugin_registry: dict[str, Type[BasePlugin]] = {}


def discover_plugins() -> dict[str, Type[BasePlugin]]:
    """Discover and register all available plugins.

    Scans the depnova.plugins package tree for classes that
    inherit from BasePlugin. Each plugin is instantiated briefly
    to get its name, then the class is stored in the registry.

    Returns:
        Dict mapping plugin_name → plugin_class
    """
    import depnova.plugins as plugins_pkg

    _scan_package(plugins_pkg)

    log.info("plugin_discovery_complete", count=len(_plugin_registry),
             plugins=list(_plugin_registry.keys()))
    return _plugin_registry.copy()


def _scan_package(package) -> None:
    """Recursively scan a package for BasePlugin subclasses."""
    package_path = package.__path__
    package_name = package.__name__

    for importer, module_name, is_pkg in pkgutil.walk_packages(
        package_path, prefix=f"{package_name}."
    ):
        try:
            module = importlib.import_module(module_name)
        except Exception as e:
            log.warning("plugin_import_failed", module=module_name, error=str(e))
            continue

        # Find all BasePlugin subclasses in this module
        for attr_name in dir(module):
            attr = getattr(module, attr_name)

            if (
                isinstance(attr, type)
                and issubclass(attr, BasePlugin)
                and attr is not BasePlugin
                and not getattr(attr, "__abstractmethods__", None)
            ):
                _register_plugin_class(attr)


def _register_plugin_class(plugin_class: Type[BasePlugin]) -> None:
    """Register a plugin class in the global registry.

    Instantiates the class with empty config to get its name.
    """
    try:
        # Create a temporary instance to get the plugin name
        instance = plugin_class(plugin_config={})
        name = instance.get_name()

        if name in _plugin_registry:
            existing = _plugin_registry[name].__name__
            log.warning(
                "plugin_name_conflict",
                name=name,
                existing_class=existing,
                new_class=plugin_class.__name__,
            )
        else:
            _plugin_registry[name] = plugin_class
            log.debug("plugin_registered", name=name, cls=plugin_class.__name__)

    except Exception as e:
        log.warning(
            "plugin_registration_failed",
            cls=plugin_class.__name__,
            error=str(e),
        )


def get_plugin_class(name: str) -> Type[BasePlugin] | None:
    """Get a registered plugin class by name.

    Args:
        name: Plugin name (as returned by get_name())

    Returns:
        Plugin class, or None if not found
    """
    return _plugin_registry.get(name)


def list_plugins() -> list[dict[str, str]]:
    """List all registered plugins with metadata.

    Returns:
        List of dicts with name, class, phase, description
    """
    result = []
    for name, cls in sorted(_plugin_registry.items()):
        try:
            instance = cls(plugin_config={})
            result.append({
                "name": name,
                "class": cls.__name__,
                "phase": instance.get_phase(),
                "description": instance.get_description(),
                "ecosystems": instance.get_supported_ecosystems(),
            })
        except Exception:
            result.append({
                "name": name,
                "class": cls.__name__,
                "phase": -1,
                "description": "Error loading plugin",
                "ecosystems": [],
            })
    return result


def clear_registry() -> None:
    """Clear the plugin registry. Mainly for testing."""
    _plugin_registry.clear()
