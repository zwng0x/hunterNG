# hunterNG/utls/file_utils.py

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

def save_json(data: Dict[Any, Any] | List[Any], file_path: Path) -> None:
    file_path.parent.mkdir(parents=True, exist_ok=True)
    with file_path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def load_json(file_path: Path) -> Optional[Dict[str, Any]]:
    with open(file_path, 'r', encoding='utf-8') as f:
        return json.load(f)
    
def save_text(data: str, file_path: Path) -> None:
    file_path.parent.mkdir(parents=True, exist_ok=True)
    with file_path.open("w", encoding="utf-8") as f:
        f.write(data)

def load_text(file_path: Path) -> Optional[str]:
    with file_path.open("r", encoding="utf-8") as f:
        return f.read()