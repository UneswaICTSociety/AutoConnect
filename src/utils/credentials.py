# saves student id and birthday so user doesnt have to type again

import json
from pathlib import Path

from src.utils.system_utils import PathManager


CREDENTIALS_FILE = "credentials.json"


def _get_credentials_path():
    cfg = PathManager.get_config_dir()
    cfg.mkdir(parents=True, exist_ok=True)
    return cfg / CREDENTIALS_FILE


def save_credentials(student_id, birthday):
    try:
        path = _get_credentials_path()
        payload = {"student_id": student_id or "", "birthday": birthday or ""}
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        return True
    except Exception:
        return False


def load_credentials():
    # returns student_id, birthday or None, None
    try:
        path = _get_credentials_path()
        if not path.exists():
            return None, None
        data = json.loads(path.read_text(encoding="utf-8"))
        return data.get("student_id") or None, data.get("birthday") or None
    except Exception:
        return None, None


def remove_credentials():
    try:
        path = _get_credentials_path()
        if path.exists():
            path.unlink()
        return True
    except Exception:
        return False

