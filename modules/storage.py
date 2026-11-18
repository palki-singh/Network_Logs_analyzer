"""
Thread-safe, atomic JSON storage utilities for SecureChat.
Prevents JSON file corruption during concurrent operations or server crashes.
Hardened for Windows filesystem semantics.
"""

import json
import os
import threading
import tempfile
import time

_file_lock = threading.RLock()

def load_json(file_path, default=None):
    """
    Safely load data from a JSON file.
    If the file does not exist or is empty/corrupt, returns default and initializes it.
    """
    if default is None:
        default = []

    with _file_lock:
        if not os.path.exists(file_path):
            save_json(file_path, default)
            return default

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read().strip()
                if not content:
                    return default
                return json.loads(content)
        except (json.JSONDecodeError, OSError):
            return default

def save_json(file_path, data):
    """
    Atomically writes data to a JSON file using a temporary file and rename.
    Includes Windows-specific retry handling to prevent WinError 5 during rapid updates.
    """
    with _file_lock:
        dirname = os.path.dirname(file_path)
        if dirname and not os.path.exists(dirname):
            os.makedirs(dirname, exist_ok=True)

        temp_fd, temp_path = tempfile.mkstemp(dir=dirname, prefix="tmp_", suffix=".json")
        try:
            with os.fdopen(temp_fd, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4, ensure_ascii=False)
                f.flush()

            # Atomic replace with retry for Windows file system locking
            replaced = False
            for attempt in range(5):
                try:
                    os.replace(temp_path, file_path)
                    replaced = True
                    break
                except OSError:
                    time.sleep(0.05)

            if not replaced:
                # Direct write fallback under lock
                with open(file_path, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=4, ensure_ascii=False)
                    f.flush()

        finally:
            if os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except OSError:
                    pass

def append_json_item(file_path, item):
    """
    Safely appends an item to a JSON list.
    """
    with _file_lock:
        data = load_json(file_path, default=[])
        if not isinstance(data, list):
            data = []
        data.append(item)
        save_json(file_path, data)
        return item
