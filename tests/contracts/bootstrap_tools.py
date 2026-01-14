import pkgutil
import importlib
import scanner.tools


def bootstrap_tool_registry() -> None:
    for _, module_name, _ in pkgutil.iter_modules(scanner.tools.__path__):
        if module_name.startswith("_"):
            continue
        if module_name in ("utils", "registry"):
            continue

        importlib.import_module(f"scanner.tools.{module_name}")
