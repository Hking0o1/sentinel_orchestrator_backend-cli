import importlib
import pkgutil
import logging
from typing import List
from scanner.plugins.base import BaseScannerPlugin

logger = logging.getLogger("scanner.plugins")

def load_plugins(plugin_package: str = "scanner.plugins.custom") -> List[BaseScannerPlugin]:
    """
    Dynamically discovers and instantiates scanner plugins.
    1. Looks in the 'custom' folder.
    2. Imports every module found.
    3. Scans for classes inheriting from BaseScannerPlugin.
    4. Returns a list of INSTANTIATED plugins ready to run.
    """
    found_plugins = []

    # Get the physical path of the package
    try:
        package_module = importlib.import_module(plugin_package)
        path = getattr(package_module, "__path__", [])
    except ImportError:
        logger.warning(f"Plugin package '{plugin_package}' not found. No custom plugins loaded.")
        return []

    # Iterate over all modules in the package directory
    for _, name, _ in pkgutil.iter_modules(path):
        full_name = f"{plugin_package}.{name}"
        try:
            imported_module = importlib.import_module(full_name)

            # Inspect module members
            for attribute_name in dir(imported_module):
                attribute = getattr(imported_module, attribute_name)

                # Check if it's a class, inherits from Base, and IS NOT Base itself
                if (isinstance(attribute, type) and 
                    issubclass(attribute, BaseScannerPlugin) and 
                    attribute is not BaseScannerPlugin):
                    
                    # Instantiate and add
                    try:
                        plugin_instance = attribute()
                        found_plugins.append(plugin_instance)
                        logger.info(f"Loaded Plugin: {plugin_instance.name} v{plugin_instance.version}")
                    except Exception as e:
                        logger.error(f"Failed to instantiate plugin {attribute_name}: {e}")

        except Exception as e:
            logger.error(f"Failed to import plugin module {full_name}: {e}")

    return found_plugins