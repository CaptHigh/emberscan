"""
EmberScan Plugin System.

Plugins extend EmberScan functionality with:
- Custom scanners
- New device support
- Integration with external tools
- Custom report formats

Plugin Structure:
    plugins/
        my_plugin/
            __init__.py  # Must export 'register' function
            scanner.py   # Optional custom scanner
            config.yaml  # Plugin configuration
"""

import os
import sys
import importlib
import importlib.util
from pathlib import Path
from typing import Dict, List, Optional, Type, Any

from ..core.logger import get_logger
from ..core.config import Config
from ..core.exceptions import PluginLoadError, PluginExecutionError

logger = get_logger(__name__)


class PluginManager:
    """Manages loading and execution of EmberScan plugins."""

    def __init__(self, config: Config):
        self.config = config
        self.plugins_dir = Path(config.plugins_dir)
        self.loaded_plugins: Dict[str, Any] = {}

    def discover_plugins(self) -> List[str]:
        """Discover available plugins in plugins directory."""
        plugins = []

        if not self.plugins_dir.exists():
            logger.debug(f"Plugins directory not found: {self.plugins_dir}")
            return plugins

        for item in self.plugins_dir.iterdir():
            if item.is_dir() and (item / "__init__.py").exists():
                plugins.append(item.name)
            elif item.suffix == ".py" and item.name != "__init__.py":
                plugins.append(item.stem)

        logger.info(f"Discovered {len(plugins)} plugins: {plugins}")
        return plugins

    def load_plugin(self, plugin_name: str) -> bool:
        """Load a specific plugin."""
        if plugin_name in self.loaded_plugins:
            logger.debug(f"Plugin already loaded: {plugin_name}")
            return True

        plugin_path = self.plugins_dir / plugin_name

        # Check if it's a package or module
        if plugin_path.is_dir():
            init_file = plugin_path / "__init__.py"
            if not init_file.exists():
                raise PluginLoadError(f"Plugin missing __init__.py: {plugin_name}")
            module_path = str(init_file)
        elif (plugin_path.with_suffix(".py")).exists():
            module_path = str(plugin_path.with_suffix(".py"))
        else:
            raise PluginLoadError(f"Plugin not found: {plugin_name}")

        try:
            spec = importlib.util.spec_from_file_location(
                f"emberscan.plugins.{plugin_name}", module_path
            )
            module = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = module
            spec.loader.exec_module(module)

            # Check for register function
            if hasattr(module, "register"):
                module.register(self)

            self.loaded_plugins[plugin_name] = module
            logger.info(f"Loaded plugin: {plugin_name}")
            return True

        except Exception as e:
            raise PluginLoadError(f"Failed to load plugin {plugin_name}: {e}")

    def load_all_plugins(self):
        """Load all discovered plugins."""
        enabled = self.config.enabled_plugins or self.discover_plugins()

        for plugin_name in enabled:
            try:
                self.load_plugin(plugin_name)
            except PluginLoadError as e:
                logger.error(str(e))

    def get_plugin(self, plugin_name: str) -> Optional[Any]:
        """Get a loaded plugin by name."""
        return self.loaded_plugins.get(plugin_name)

    def execute_hook(self, hook_name: str, *args, **kwargs) -> Dict[str, Any]:
        """Execute a hook across all loaded plugins."""
        results = {}

        for name, plugin in self.loaded_plugins.items():
            if hasattr(plugin, hook_name):
                try:
                    hook = getattr(plugin, hook_name)
                    result = hook(*args, **kwargs)
                    results[name] = result
                except Exception as e:
                    logger.error(f"Plugin {name} hook {hook_name} failed: {e}")
                    results[name] = {"error": str(e)}

        return results


# Plugin registration decorators
def scanner_plugin(scanner_class: Type):
    """Decorator to register a scanner plugin."""
    from ..scanners.base import ScannerRegistry

    name = getattr(scanner_class, "name", scanner_class.__name__.lower())
    ScannerRegistry.register(name)(scanner_class)

    return scanner_class


def reporter_plugin(reporter_class: Type):
    """Decorator to register a reporter plugin."""
    # Would register with reporter registry
    return reporter_class


# Export plugin manager
__all__ = ["PluginManager", "scanner_plugin", "reporter_plugin"]
