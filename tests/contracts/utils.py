import pkgutil
import scanner.tools


def discover_tools():
    for _, module_name, _ in pkgutil.iter_modules(scanner.tools.__path__):
        if module_name.startswith("_"):
            continue
        yield module_name
