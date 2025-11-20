import subprocess
import os
import shutil
import logging
import colorlog # <-- NEW IMPORT
from typing import List, Tuple, Optional

# -------------------------
# Centralized Logging (Prettified)
# -------------------------
logger = logging.getLogger("project_sentinel")
logger.setLevel(os.getenv("LOG_LEVEL", "INFO"))

# Create a colored formatter
handler = logging.StreamHandler()
handler.setFormatter(colorlog.ColoredFormatter(
    "%(log_color)s[%(asctime)s] [%(levelname)-8s] %(message)s",
    datefmt="%H:%M:%S",
    reset=True,
    log_colors={
        'DEBUG':    'cyan',
        'INFO':     'green',
        'WARNING':  'yellow',
        'ERROR':    'red',
        'CRITICAL': 'red,bg_white',
    },
    secondary_log_colors={},
    style='%'
))

if not logger.handlers:
    logger.addHandler(handler)


# -------------------------
# Global Configuration
# -------------------------
SCAN_EXCLUDE_DIRS = [
    "node_modules", ".git", ".venv", "venv", "env", ".next", "dist", "build", "__pycache__",
]

# Timeouts (seconds)
DEFAULT_CMD_TIMEOUT = 60 * 20 
SHORT_CMD_TIMEOUT = 60 * 3   

SEVERITY_MAP = {
    "CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM",
    "LOW": "LOW", "INFO": "INFO", "ERROR": "CRITICAL", "WARNING": "HIGH", None: "INFO"
}

# -------------------------
# Helper Functions
# -------------------------

def get_logger(name: str):
    """Returns a child logger for a specific tool."""
    return logger.getChild(name)

def is_tool_installed(name: str) -> bool:
    return shutil.which(name) is not None

def normalize_severity(raw: Optional[str]) -> str:
    if not raw: return "INFO"
    return SEVERITY_MAP.get(raw.upper(), "INFO")

def run_subprocess(cmd: List[str], cwd: Optional[str] = None, timeout: int = DEFAULT_CMD_TIMEOUT) -> Tuple[bool, str]:
    """
    Securely runs a subprocess without shell=True.
    Logs the command and captures output.
    """
    tool_name = os.path.basename(cmd[0])
    log = get_logger(f"subprocess.{tool_name}")
    
    # Just log the binary name to reduce noise, or full cmd for debug
    log.debug(f"Exec: {cmd[0]}...")

    try:
        proc = subprocess.run(
            cmd, 
            cwd=cwd, 
            capture_output=True, 
            text=True, 
            timeout=timeout,
            check=False 
        )
        
        output = (proc.stdout or "") + (proc.stderr or "")
        
        if proc.returncode != 0:
            log.warning(f"{cmd[0]} exited with code {proc.returncode}")
            return False, output
            
        return True, output

    except subprocess.TimeoutExpired:
        log.error(f"Command timed out after {timeout}s")
        return False, "TIMEOUT"
    except FileNotFoundError:
        log.error(f"Binary not found: {cmd[0]}")
        return False, "NOT_FOUND"
    except Exception as e:
        log.exception(f"Unexpected execution error: {e}")
        return False, str(e)

def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)