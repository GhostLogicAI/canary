"""
CANARY WATCHDOG

Separate process that monitors canary components.
Detects if components die and can restart them.
Provides tamper detection for baseline files.
"""

import subprocess
import time
import sys
import os
import hashlib
import json
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict
import argparse

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent))

from config import get_config
from signals import Signal, SignalTypes, Severity, Category, get_signals_db

CANARY_DIR = Path(__file__).parent
HEARTBEAT_FILE = CANARY_DIR / ".watchdog_heartbeat"
COMPONENT_STATUS_FILE = CANARY_DIR / ".component_status.json"


def is_process_running(name: str) -> bool:
    """Check if a process by name is running."""
    try:
        result = subprocess.run(
            ["tasklist", "/FI", f"IMAGENAME eq {name}", "/FO", "CSV", "/NH"],
            capture_output=True, text=True, timeout=10
        )
        return name.lower() in result.stdout.lower()
    except Exception:
        return False


def is_python_script_running(script_name: str) -> bool:
    """Check if a Python script is running."""
    try:
        result = subprocess.run(
            ["powershell", "-Command",
             f"Get-Process python* -ErrorAction SilentlyContinue | Where-Object {{ $_.CommandLine -like '*{script_name}*' }}"],
            capture_output=True, text=True, timeout=10
        )
        return script_name.lower() in result.stdout.lower()
    except Exception:
        return False


def start_component(script_name: str) -> bool:
    """Start a canary component script."""
    script_path = CANARY_DIR / script_name
    if not script_path.exists():
        return False

    try:
        # Start in background
        subprocess.Popen(
            ["python", str(script_path)],
            cwd=str(CANARY_DIR),
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
        )
        return True
    except Exception as e:
        print(f"[!] Failed to start {script_name}: {e}")
        return False


def get_file_hash(path: Path) -> str:
    """Get SHA256 hash of a file."""
    if not path.exists():
        return ""
    try:
        with open(path, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception:
        return ""


class Watchdog:
    """Monitors canary components and handles resilience."""

    COMPONENTS = {
        "edge_parser.py": "EdgeParser",
        "canary_ui.py": "CanaryUI",
    }

    def __init__(self):
        self.config = get_config().watchdog
        self.signals_db = get_signals_db()
        self.running = False

        # Track baseline file hashes for tamper detection
        self.baseline_hashes = {}
        self._snapshot_baselines()

        # Track component restarts
        self.restart_counts: Dict[str, int] = {}
        self.last_restart_time: Dict[str, float] = {}

    def _snapshot_baselines(self):
        """Take snapshot of baseline files for tamper detection."""
        files_to_watch = [
            CANARY_DIR / "baseline.db",
            CANARY_DIR / "signals.db",
            CANARY_DIR / "config.yaml",
        ]
        for f in files_to_watch:
            self.baseline_hashes[str(f)] = get_file_hash(f)

    def check_tamper(self) -> bool:
        """Check if baseline files were tampered with."""
        tampered = False
        for path_str, original_hash in self.baseline_hashes.items():
            path = Path(path_str)
            current_hash = get_file_hash(path)

            # Only check if file existed before and hash changed
            if original_hash and current_hash and original_hash != current_hash:
                print(f"[!] TAMPER DETECTED: {path.name}")
                self._emit_alert(
                    SignalTypes.BASELINE_TAMPERED,
                    f"File tampered: {path.name}",
                    {"file": path.name, "original_hash": original_hash[:16], "new_hash": current_hash[:16]}
                )
                tampered = True

            # Update hash for next check
            self.baseline_hashes[path_str] = current_hash

        return tampered

    def check_components(self) -> Dict[str, bool]:
        """Check if all components are running."""
        status = {}

        for script, name in self.COMPONENTS.items():
            is_running = is_python_script_running(script)
            status[script] = is_running

            if not is_running:
                print(f"[!] Component DOWN: {name}")

        return status

    def restart_component(self, script_name: str) -> bool:
        """Restart a dead component."""
        name = self.COMPONENTS.get(script_name, script_name)
        now = time.time()

        # Rate limit restarts (max 3 per 5 minutes)
        if script_name in self.last_restart_time:
            elapsed = now - self.last_restart_time[script_name]
            if elapsed < 300:  # 5 minutes
                restarts = self.restart_counts.get(script_name, 0)
                if restarts >= 3:
                    print(f"[!] Too many restarts for {name}, giving up")
                    return False
        else:
            self.restart_counts[script_name] = 0

        print(f"[*] Restarting {name}...")
        success = start_component(script_name)

        if success:
            self.restart_counts[script_name] = self.restart_counts.get(script_name, 0) + 1
            self.last_restart_time[script_name] = now

            self._emit_alert(
                SignalTypes.WATCHDOG_ALERT,
                f"Restarted {name}",
                {"component": name, "restart_count": self.restart_counts[script_name]}
            )

        return success

    def _emit_alert(self, signal_type: str, message: str, artifacts: dict):
        """Emit an alert signal."""
        sig = Signal.create(
            signal_type=signal_type,
            source_surface="Watchdog",
            trigger_reason=message,
            artifacts=artifacts,
            severity=Severity.CRITICAL,
            category=Category.META
        )
        self.signals_db.store(sig)
        print(f"[SIGNAL] {signal_type}: {message}")

    def write_heartbeat(self):
        """Write heartbeat timestamp to file."""
        try:
            with open(HEARTBEAT_FILE, 'w') as f:
                f.write(str(time.time()))
        except Exception:
            pass

    def write_status(self, status: Dict[str, bool]):
        """Write component status to file."""
        try:
            data = {
                "timestamp": time.time(),
                "components": status,
                "watchdog_pid": os.getpid(),
            }
            with open(COMPONENT_STATUS_FILE, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception:
            pass

    def run(self):
        """Main watchdog loop."""
        print("=" * 50)
        print("CANARY WATCHDOG")
        print("=" * 50)
        print(f"Check interval: {self.config.check_interval_seconds}s")
        print(f"Restart on failure: {self.config.restart_on_failure}")
        print("=" * 50)

        self.running = True

        try:
            while self.running:
                # Write heartbeat
                self.write_heartbeat()

                # Check for tampered files
                self.check_tamper()

                # Check component status
                status = self.check_components()
                self.write_status(status)

                # Restart dead components if enabled
                if self.config.restart_on_failure:
                    for script, is_running in status.items():
                        if not is_running:
                            self.restart_component(script)

                # Sleep until next check
                time.sleep(self.config.check_interval_seconds)

        except KeyboardInterrupt:
            print("\n[*] Watchdog stopped")
        finally:
            self.running = False


def get_watchdog_status() -> Optional[Dict]:
    """Get current watchdog status from file."""
    if not COMPONENT_STATUS_FILE.exists():
        return None
    try:
        with open(COMPONENT_STATUS_FILE, 'r') as f:
            return json.load(f)
    except Exception:
        return None


def is_watchdog_alive() -> bool:
    """Check if watchdog is alive (heartbeat within last 60s)."""
    if not HEARTBEAT_FILE.exists():
        return False
    try:
        with open(HEARTBEAT_FILE, 'r') as f:
            ts = float(f.read().strip())
            return (time.time() - ts) < 60
    except Exception:
        return False


def main():
    parser = argparse.ArgumentParser(description="Canary Watchdog")
    parser.add_argument("command", nargs="?", default="run",
                       choices=["run", "status", "check"],
                       help="Command to run")
    args = parser.parse_args()

    if args.command == "status":
        status = get_watchdog_status()
        alive = is_watchdog_alive()
        print(f"Watchdog: {'ALIVE' if alive else 'DEAD'}")
        if status:
            print(f"Last check: {datetime.fromtimestamp(status['timestamp']).strftime('%H:%M:%S')}")
            print("Components:")
            for comp, running in status.get('components', {}).items():
                status_str = '✓ UP' if running else '✗ DOWN'
                print(f"  {comp}: {status_str}")
        return

    if args.command == "check":
        # One-time check
        wd = Watchdog()
        status = wd.check_components()
        for comp, running in status.items():
            name = wd.COMPONENTS.get(comp, comp)
            status_str = '✓ UP' if running else '✗ DOWN'
            print(f"{name}: {status_str}")
        return

    # Run watchdog
    wd = Watchdog()
    wd.run()


if __name__ == "__main__":
    main()
