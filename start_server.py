"""
Launcher used by the scheduled task.
Runs server.py in a restart loop so the monitor recovers from crashes.
"""
import subprocess
import sys
import os
import time

APP_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(APP_DIR, "logs")
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "service.log")

def ts():
    return time.strftime("%Y-%m-%d %H:%M:%S")

with open(LOG_FILE, "a", encoding="utf-8") as log:
    while True:
        log.write(f"[{ts()}] Starting server.py\n")
        log.flush()
        try:
            proc = subprocess.run(
                [sys.executable, os.path.join(APP_DIR, "server.py")],
                cwd=APP_DIR,
                stdout=log,
                stderr=log,
            )
            log.write(f"[{ts()}] server.py exited (code {proc.returncode}), restarting in 10s\n")
        except Exception as e:
            log.write(f"[{ts()}] ERROR launching server.py: {e}\n")
        log.flush()
        time.sleep(10)
