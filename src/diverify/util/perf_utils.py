import os
import time
import logging
import csv
from datetime import datetime
from pathlib import Path

# Set up logger
logger = logging.getLogger("perf")
if not logger.hasHandlers():
    logging.basicConfig(level=logging.INFO)

PERF_MODE = os.getenv("PERF_MODE", "false").lower() == "true"

LOG_FILE = os.getenv("PERF_LOG", "perf_log.csv")
_log_path = Path(LOG_FILE)

TEST_MODE = "unknown"
LEVEL = "unknown"

def set_test_mode(mode, level):
    global TEST_MODE
    global LEVEL
    TEST_MODE = mode
    LEVEL = level

if PERF_MODE and not _log_path.exists():
    with _log_path.open("w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["level", "mode", "function", "duration_ms"])

def measure_latency(func):
    def wrapper(*args, **kwargs):
        if PERF_MODE:
            start = time.perf_counter()
            result = func(*args, **kwargs)
            duration = (time.perf_counter() - start) * 1000

            with _log_path.open("a", newline="") as f:
                writer = csv.writer(f)
                writer.writerow([LEVEL, TEST_MODE, func.__name__, f"{duration:.2f}"])
            return result
        else:
            return func(*args, **kwargs)
    return wrapper
