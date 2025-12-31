"""
Shared definitions for edge parser and canary UI.
Signal queue implementation using simple JSON files.
"""

import json
import os
import time
import uuid
from dataclasses import dataclass, asdict
from typing import Optional, List
from pathlib import Path
import threading
import filelock

# Paths
CANARY_DIR = Path(__file__).parent
SIGNALS_FILE = CANARY_DIR / "signals.json"
BASELINE_FILE = CANARY_DIR / "baseline.json"
LOCK_FILE = CANARY_DIR / ".signals.lock"
SIGNAL_LOG_FILE = CANARY_DIR / "canary_log.txt"

@dataclass
class Signal:
    """A mechanical signal emitted by the edge parser."""
    signal_id: str
    signal_type: str
    timestamp: float
    source_surface: str
    trigger_reason: str
    artifacts: dict

    @classmethod
    def create(cls, signal_type: str, source_surface: str,
               trigger_reason: str, artifacts: dict = None):
        return cls(
            signal_id=str(uuid.uuid4())[:8],
            signal_type=signal_type,
            timestamp=time.time(),
            source_surface=source_surface,
            trigger_reason=trigger_reason,
            artifacts=artifacts or {}
        )

    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_dict(cls, d):
        return cls(**d)


class SignalQueue:
    """
    File-based signal queue.
    Parser writes signals. Canary reads and clears them.
    Uses file locking to prevent corruption.
    """

    def __init__(self):
        self.lock = filelock.FileLock(str(LOCK_FILE), timeout=5)

    def push(self, signal: Signal):
        """Add a signal to the queue."""
        with self.lock:
            signals = self._read_raw()
            signals.append(signal.to_dict())
            self._write_raw(signals)

    def pop_all(self) -> List[Signal]:
        """Read and clear all signals from the queue."""
        with self.lock:
            signals = self._read_raw()
            if signals:
                self._write_raw([])
            return [Signal.from_dict(s) for s in signals]

    def peek(self) -> List[Signal]:
        """Read signals without clearing."""
        with self.lock:
            return [Signal.from_dict(s) for s in self._read_raw()]

    def _read_raw(self) -> list:
        if not SIGNALS_FILE.exists():
            return []
        try:
            with open(SIGNALS_FILE, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return []

    def _write_raw(self, signals: list):
        with open(SIGNALS_FILE, 'w') as f:
            json.dump(signals, f, indent=2)


class Baseline:
    """
    Simple baseline storage.
    Stores first-seen items, counts, hashes, timestamps.
    No models. No ML. No history compression.
    """

    def __init__(self):
        self.lock = threading.Lock()
        self._load()

    def _load(self):
        if BASELINE_FILE.exists():
            try:
                with open(BASELINE_FILE, 'r') as f:
                    self.data = json.load(f)
            except (json.JSONDecodeError, IOError):
                self.data = self._empty()
        else:
            self.data = self._empty()

    def _empty(self):
        return {
            "created_at": time.time(),
            "surfaces": {
                "drivers": {"items": [], "first_seen": {}},
                "services": {"items": [], "first_seen": {}},
                "processes": {"items": [], "first_seen": {}},
                "connections": {"items": [], "first_seen": {}},
                "autoruns": {"items": [], "first_seen": {}},
                "scheduled_tasks": {"items": [], "first_seen": {}},
            }
        }

    def save(self):
        with self.lock:
            with open(BASELINE_FILE, 'w') as f:
                json.dump(self.data, f, indent=2)

    def get_surface(self, name: str) -> dict:
        return self.data["surfaces"].get(name, {"items": [], "first_seen": {}})

    def update_surface(self, name: str, items: list):
        """Update a surface baseline. Returns (new_items, missing_items)."""
        with self.lock:
            surface = self.data["surfaces"].setdefault(
                name, {"items": [], "first_seen": {}}
            )
            old_set = set(surface["items"])
            new_set = set(items)

            # Find differences
            appeared = new_set - old_set
            disappeared = old_set - new_set

            # Update first-seen timestamps for new items
            now = time.time()
            for item in appeared:
                if item not in surface["first_seen"]:
                    surface["first_seen"][item] = now

            # Update current items
            surface["items"] = list(new_set)

            return list(appeared), list(disappeared)

    def is_first_run(self) -> bool:
        """Check if this is the first run (empty baseline)."""
        for surface in self.data["surfaces"].values():
            if surface["items"]:
                return False
        return True


# Signal type constants
class SignalTypes:
    # Kernel/Driver signals
    NEW_KERNEL_DRIVER = "new_kernel_driver_loaded"
    DRIVER_DISAPPEARED = "baseline_driver_missing"

    # Service signals
    NEW_SERVICE = "new_service_appeared"
    SERVICE_DISAPPEARED = "baseline_service_missing"
    SERVICE_STATE_CHANGED = "service_state_changed"

    # Process signals
    NEW_PROCESS_NAME = "new_process_name_observed"
    UNUSUAL_PARENT = "unusual_parent_child_relationship"
    UNSIGNED_BINARY = "unsigned_binary_executed"

    # Network signals
    NEW_OUTBOUND_DEST = "new_outbound_destination"
    NEW_LISTENING_PORT = "new_listening_port"
    CONNECTION_SPIKE = "connection_count_spike"

    # Autorun signals
    NEW_AUTORUN = "new_autorun_entry"
    AUTORUN_DISAPPEARED = "autorun_entry_removed"

    # Scheduled task signals
    NEW_SCHEDULED_TASK = "new_scheduled_task"
    TASK_DISAPPEARED = "scheduled_task_removed"

    # Log signals
    LOG_GAP = "log_gap_detected"
    LOG_CLEARED = "log_cleared"

    # Meta signals
    CANARY_SILENCED = "canary_silenced"
    PARSER_STARTED = "parser_started"
    BASELINE_INITIALIZED = "baseline_initialized"


# Signals that should trigger RED alert bubbles (paranoid mode - really bad)
ALERT_SIGNALS = {
    # Network anomalies
    SignalTypes.CONNECTION_SPIKE,

    # Kernel / driver anomalies
    SignalTypes.NEW_KERNEL_DRIVER,
    SignalTypes.DRIVER_DISAPPEARED,

    # Security events
    SignalTypes.LOG_CLEARED,
    SignalTypes.UNSIGNED_BINARY,

    # Meta
    SignalTypes.CANARY_SILENCED,
}

# Human-readable translations for canary UI
SIGNAL_TRANSLATIONS = {
    SignalTypes.NEW_KERNEL_DRIVER: "A new kernel driver just showed up. That wasn't here before.",
    SignalTypes.DRIVER_DISAPPEARED: "A kernel driver that was here before is gone now. Huh.",
    SignalTypes.NEW_SERVICE: "New service appeared. Someone installed something.",
    SignalTypes.SERVICE_DISAPPEARED: "A service that used to exist just... doesn't anymore.",
    SignalTypes.SERVICE_STATE_CHANGED: "A service changed its running state.",
    SignalTypes.NEW_PROCESS_NAME: "I'm seeing a process name I haven't seen before.",
    SignalTypes.UNUSUAL_PARENT: "That's a weird parent process for this child. Just saying.",
    SignalTypes.UNSIGNED_BINARY: "An unsigned executable just ran. Could be fine. Could be not.",
    SignalTypes.NEW_OUTBOUND_DEST: "This machine just talked to a new place on the internet.",
    SignalTypes.NEW_LISTENING_PORT: "Something new is listening on the network. Wasn't before.",
    SignalTypes.CONNECTION_SPIKE: "Yo. Not. Normal. At. All. Huge connection spike.",
    SignalTypes.NEW_AUTORUN: "Something new will run at startup now. FYI.",
    SignalTypes.AUTORUN_DISAPPEARED: "An autorun entry got removed. Maybe intentional.",
    SignalTypes.NEW_SCHEDULED_TASK: "New scheduled task appeared. Something wants to run later.",
    SignalTypes.TASK_DISAPPEARED: "A scheduled task vanished. Interesting.",
    SignalTypes.LOG_GAP: "I stopped hearing logs for a bit. That's unusual.",
    SignalTypes.LOG_CLEARED: "Someone cleared the logs. That's... a choice.",
    SignalTypes.CANARY_SILENCED: "Tell the Ghost I was right.",
    SignalTypes.PARSER_STARTED: "Edge parser woke up. Watching.",
    SignalTypes.BASELINE_INITIALIZED: "First run. Learning what 'normal' looks like here.",
}


def translate_signal(signal: Signal) -> tuple:
    """
    Convert a signal to human-readable text.
    Returns (message, is_alert) tuple.
    is_alert=True means RED bubble (really bad).
    """
    base = SIGNAL_TRANSLATIONS.get(
        signal.signal_type,
        f"Something happened: {signal.signal_type}"
    )

    # Check if this is an alert-level signal
    is_alert = signal.signal_type in ALERT_SIGNALS

    # Also check artifacts for explicit alert flag
    if signal.artifacts.get("alert"):
        is_alert = True

    # Add specific details if available
    details = []
    if "name" in signal.artifacts:
        details.append(signal.artifacts["name"])
    if "path" in signal.artifacts:
        details.append(signal.artifacts["path"])
    if "address" in signal.artifacts:
        details.append(signal.artifacts["address"])
    if "port" in signal.artifacts:
        details.append(f"port {signal.artifacts['port']}")
    if "count" in signal.artifacts:
        details.append(f"{signal.artifacts['count']} connections")
    if "baseline" in signal.artifacts:
        details.append(f"normally {signal.artifacts['baseline']}")

    if details:
        message = f"{base}\n({', '.join(details[:3])})"
    else:
        message = base

    return message, is_alert


def log_signal(signal: Signal, message: str, is_alert: bool):
    """Append signal to the persistent log file."""
    from datetime import datetime

    ts = datetime.fromtimestamp(signal.timestamp).strftime('%Y-%m-%d %H:%M:%S')
    alert_marker = " [ALERT]" if is_alert else ""

    log_line = f"[{ts}]{alert_marker} {signal.signal_type}\n"
    log_line += f"    {message.replace(chr(10), ' ')}\n"
    log_line += f"    Source: {signal.source_surface}\n"
    log_line += "\n"

    try:
        with open(SIGNAL_LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(log_line)
    except Exception:
        pass


def read_log(max_lines: int = 100) -> str:
    """Read the last N lines from the signal log."""
    if not SIGNAL_LOG_FILE.exists():
        return "No signals logged yet."

    try:
        with open(SIGNAL_LOG_FILE, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        # Return last max_lines
        if len(lines) > max_lines:
            lines = lines[-max_lines:]

        return ''.join(lines)
    except Exception as e:
        return f"Error reading log: {e}"


def clear_log():
    """Clear the signal log file."""
    try:
        with open(SIGNAL_LOG_FILE, 'w', encoding='utf-8') as f:
            f.write("")
    except Exception:
        pass
