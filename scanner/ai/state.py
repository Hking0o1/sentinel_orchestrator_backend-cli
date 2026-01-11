import json
import os
from pathlib import Path
from typing import Dict


def load_progress(path: str) -> int:
    """
    Load last completed chunk index.
    """
    p = Path(path)
    if not p.exists():
        return 0

    with p.open("r", encoding="utf-8") as f:
        data = json.load(f)

    return int(data.get("last_chunk", 0))


def save_progress(path: str, chunk_index: int) -> None:
    """
    Atomically persist progress.
    """
    tmp_path = f"{path}.tmp"

    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump({"last_chunk": chunk_index}, f)

    os.replace(tmp_path, path)
