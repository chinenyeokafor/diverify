import os
import time
import logging
import json
from datetime import datetime, timezone
from pathlib import Path
from functools import wraps

# Logger setup
logger = logging.getLogger("perf")
if not logger.hasHandlers():
    logging.basicConfig(level=logging.INFO)

PERF_MODE = os.getenv("PERF_MODE", "false").lower() == "true"
LOG_FILE = os.getenv("PERF_LOG", "perf_log.jsonl")
_log_path = Path(LOG_FILE)

TEST_MODE = "unknown"
LEVEL = "unknown"
ITERATION = 0
_measurements = {}  # {func_name: duration_ms}


def set_test_mode(mode, level, iteration=0):
    global TEST_MODE, LEVEL, ITERATION, _measurements
    TEST_MODE = mode
    LEVEL = level
    ITERATION = iteration
    _measurements = {}


def _func_key(func):
    return f"{func.__module__}.{func.__qualname__}"


def measure_latency(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not PERF_MODE:
            return func(*args, **kwargs)

        start = time.perf_counter()
        try:
            return func(*args, **kwargs)
        finally:
            duration = (time.perf_counter() - start) * 1000
            key = _func_key(func)
            _measurements[key] = round(duration, 2)

    return wrapper


def flush_perf():
    """Write one JSON object per iteration."""
    if not PERF_MODE or not _measurements:
        return

    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "iteration": ITERATION,
        "level": LEVEL,
        "mode": TEST_MODE,
        **_measurements,
    }

    with _log_path.open("a") as f:
        json.dump(record, f)
        f.write("\n")