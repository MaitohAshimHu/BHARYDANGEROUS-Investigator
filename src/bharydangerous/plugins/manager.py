"""Plugin discovery and registration manager."""
import importlib.util
from pathlib import Path
from typing import Dict, List
from bharydangerous.core.config import get_config_dir
from bharydangerous.plugins.base_plugin import BaseForensicPlugin

class PluginManager:
    """Manages discovery and lifecycle of forensic plugins."""

    def __init__(self, plugin_dir: Path | None = None):
        self.plugin_dir = plugin_dir or (get_config_dir() / "plugins")
        self.plugins: Dict[str, BaseForensicPlugin] = {}
        self._discover_plugins()

    def _discover_plugins(self) -> None:
        """Scan plugin directory for Python files implementing BaseForensicPlugin."""
        if not self.plugin_dir.is_dir():
            return

        for pfile in self.plugin_dir.glob("*.py"):
            if pfile.name.startswith("__"):
                continue
            try:
                spec = importlib.util.spec_from_file_location(pfile.stem, pfile)
                if spec and spec.loader:
                    mod = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(mod)
                    for attr_name in dir(mod):
                        attr = getattr(mod, attr_name)
                        if (
                            isinstance(attr, type)
                            and issubclass(attr, BaseForensicPlugin)
                            and attr is not BaseForensicPlugin
                        ):
                            instance = attr()
                            self.plugins[instance.name] = instance
            except Exception:
                continue

    def list_plugins(self) -> List[Dict[str, str]]:
        """Return metadata list of loaded plugins."""
        return [
            {
                "name": p.name,
                "version": p.version,
                "author": p.author,
                "description": p.description,
            }
            for p in self.plugins.values()
        ]
