from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

@dataclass
class PluginContext:
    """Context passed to plugins during execution."""
    target_url: Optional[str]
    source_path: Optional[str]
    output_dir: str
    auth_cookie: Optional[str]

@dataclass
class PluginResult:
    """Standard output format for all plugins."""
    plugin_name: str
    success: bool
    findings: List[Dict[str, Any]]
    logs: str

class BaseScannerPlugin(ABC):
    """
    The Abstract Base Class that all custom plugins must inherit from.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the scanner plugin (e.g., 'Custom SQL Checker')."""
        pass

    @property
    @abstractmethod
    def version(self) -> str:
        """Version of the plugin (e.g., '1.0.0')."""
        pass

    @property
    @abstractmethod
    def profile(self) -> str:
        """Which profile runs this? 'web', 'developer', or 'all'."""
        pass

    @abstractmethod
    def run(self, context: PluginContext) -> PluginResult:
        """
        The main execution logic.
        Must return a PluginResult object.
        """
        pass