import os
import sys

# Ensure project root is on sys.path so top-level packages (e.g., engine, scanner) are importable
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

def pytest_sessionstart(session):
    os.environ["SENTINEL_TEST_MODE"] = "1"