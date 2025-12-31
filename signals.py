"""
CANARY SIGNALS SYSTEM v2

Enhanced signal system with:
- Severity levels (INFO, WARN, ALERT, CRITICAL)
- Categories for filtering
- SQLite storage for notification center
- Snooze support
"""

import sqlite3
import json
import time
import uuid
import winsound
from enum import Enum
from pathlib import Path
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, asdict, field
from contextlib import contextmanager

from config import get_config

CANARY_DIR = Path(__file__).parent
SIGNALS_DB = CANARY_DIR / "signals.db"


class Severity(Enum):
    """Signal severity levels."""
    INFO = "info"
    WARN = "warn"
    ALERT = "alert"
    CRITICAL = "critical"


class Category(Enum):
    """Signal categories for filtering."""
    NETWORK = "network"
    PROCESS = "process"
    KERNEL = "kernel"
    PERSISTENCE = "persistence"
    FORENSICS = "forensics"
    FILESYSTEM = "filesystem"
    META = "meta"


@dataclass
class Signal:
    """Enhanced signal with severity and category."""
    signal_id: str
    signal_type: str
    timestamp: float
    source_surface: str
    trigger_reason: str
    artifacts: dict
    severity: str = Severity.INFO.value
    category: str = Category.META.value
    message: str = ""
    snoozed_until: Optional[float] = None
    repeat_count: int = 1

    @classmethod
    def create(cls, signal_type: str, source_surface: str,
               trigger_reason: str = "", artifacts: dict = None,
               severity: Severity = Severity.INFO,
               category: Category = Category.META,
               message: str = None):
        """Create a new signal.

        Args:
            message: Optional custom message. If provided, overrides auto-generated message.
        """
        sig = cls(
            signal_id=str(uuid.uuid4())[:8],
            signal_type=signal_type,
            timestamp=time.time(),
            source_surface=source_surface,
            trigger_reason=trigger_reason or message or "",
            artifacts=artifacts or {},
            severity=severity.value if isinstance(severity, Severity) else severity,
            category=category.value if isinstance(category, Category) else category,
        )
        # Use provided message or generate from trigger_reason
        sig.message = message if message else translate_signal(sig)
        return sig

    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_dict(cls, d):
        return cls(**d)

    def is_snoozed(self) -> bool:
        """Check if this signal type is currently snoozed."""
        if self.snoozed_until is None:
            return False
        return time.time() < self.snoozed_until


class SignalTypes:
    """All signal type constants."""

    # Kernel/Driver signals
    NEW_KERNEL_DRIVER = "new_kernel_driver_loaded"
    DRIVER_DISAPPEARED = "baseline_driver_missing"

    # Service signals
    NEW_SERVICE = "new_service_appeared"
    SERVICE_DISAPPEARED = "baseline_service_missing"
    SERVICE_STATE_CHANGED = "service_state_changed"

    # Process signals
    NEW_PROCESS_NAME = "new_process_name_observed"
    UNUSUAL_PARENT_CHILD = "unusual_parent_child_relationship"
    SUSPICIOUS_COMMAND_LINE = "suspicious_command_line"
    UNSIGNED_BINARY = "unsigned_binary_executed"

    # Network signals
    NEW_OUTBOUND_DEST = "new_outbound_destination"
    NEW_LISTENING_PORT = "new_listening_port"
    CONNECTION_SPIKE = "connection_count_spike"
    BEACONING_DETECTED = "beaconing_detected"

    # DNS signals
    NEW_DNS_RESOLUTION = "new_dns_resolution"
    SUSPICIOUS_DOMAIN = "suspicious_domain"

    # Autorun signals
    NEW_AUTORUN = "new_autorun_entry"
    AUTORUN_DISAPPEARED = "autorun_entry_removed"

    # Scheduled task signals
    NEW_SCHEDULED_TASK = "new_scheduled_task"
    TASK_DISAPPEARED = "scheduled_task_removed"

    # File system signals
    NEW_EXECUTABLE_DROPPED = "new_executable_dropped"
    STARTUP_FOLDER_MODIFIED = "startup_folder_modified"
    SYSTEM32_MODIFIED = "system32_modified"

    # DLL signals
    UNUSUAL_DLL_LOADED = "unusual_dll_loaded"
    UNSIGNED_DLL_IN_SIGNED = "unsigned_dll_in_signed_process"

    # Named pipe signals
    NEW_NAMED_PIPE = "new_named_pipe"

    # WMI signals
    NEW_WMI_SUBSCRIPTION = "new_wmi_subscription"

    # COM signals
    COM_HIJACK_DETECTED = "com_hijack_detected"

    # Log signals
    LOG_GAP = "log_gap_detected"
    LOG_CLEARED = "log_cleared"

    # Security signals
    BASELINE_TAMPERED = "baseline_tampered"

    # Meta signals
    CANARY_SILENCED = "canary_silenced"
    PARSER_STARTED = "parser_started"
    BASELINE_INITIALIZED = "baseline_initialized"
    WATCHDOG_ALERT = "watchdog_alert"


# Signal metadata: severity and category for each type
SIGNAL_METADATA = {
    # Kernel - CRITICAL (system-level compromise)
    SignalTypes.NEW_KERNEL_DRIVER: (Severity.CRITICAL, Category.KERNEL),
    SignalTypes.DRIVER_DISAPPEARED: (Severity.ALERT, Category.KERNEL),

    # Services - WARN to ALERT
    SignalTypes.NEW_SERVICE: (Severity.WARN, Category.PERSISTENCE),
    SignalTypes.SERVICE_DISAPPEARED: (Severity.INFO, Category.PERSISTENCE),
    SignalTypes.SERVICE_STATE_CHANGED: (Severity.INFO, Category.PERSISTENCE),

    # Processes - WARN to CRITICAL
    SignalTypes.NEW_PROCESS_NAME: (Severity.INFO, Category.PROCESS),
    SignalTypes.UNUSUAL_PARENT_CHILD: (Severity.CRITICAL, Category.PROCESS),
    SignalTypes.SUSPICIOUS_COMMAND_LINE: (Severity.CRITICAL, Category.PROCESS),
    SignalTypes.UNSIGNED_BINARY: (Severity.ALERT, Category.PROCESS),

    # Network - WARN to CRITICAL
    SignalTypes.NEW_OUTBOUND_DEST: (Severity.INFO, Category.NETWORK),
    SignalTypes.NEW_LISTENING_PORT: (Severity.WARN, Category.NETWORK),
    SignalTypes.CONNECTION_SPIKE: (Severity.CRITICAL, Category.NETWORK),
    SignalTypes.BEACONING_DETECTED: (Severity.CRITICAL, Category.NETWORK),

    # DNS - INFO to ALERT
    SignalTypes.NEW_DNS_RESOLUTION: (Severity.INFO, Category.NETWORK),
    SignalTypes.SUSPICIOUS_DOMAIN: (Severity.ALERT, Category.NETWORK),

    # Autoruns - WARN
    SignalTypes.NEW_AUTORUN: (Severity.WARN, Category.PERSISTENCE),
    SignalTypes.AUTORUN_DISAPPEARED: (Severity.INFO, Category.PERSISTENCE),

    # Tasks - WARN
    SignalTypes.NEW_SCHEDULED_TASK: (Severity.WARN, Category.PERSISTENCE),
    SignalTypes.TASK_DISAPPEARED: (Severity.INFO, Category.PERSISTENCE),

    # File system - ALERT to CRITICAL
    SignalTypes.NEW_EXECUTABLE_DROPPED: (Severity.ALERT, Category.FILESYSTEM),
    SignalTypes.STARTUP_FOLDER_MODIFIED: (Severity.CRITICAL, Category.FILESYSTEM),
    SignalTypes.SYSTEM32_MODIFIED: (Severity.CRITICAL, Category.FILESYSTEM),

    # DLLs - ALERT to CRITICAL
    SignalTypes.UNUSUAL_DLL_LOADED: (Severity.ALERT, Category.PROCESS),
    SignalTypes.UNSIGNED_DLL_IN_SIGNED: (Severity.CRITICAL, Category.PROCESS),

    # Named pipes - WARN
    SignalTypes.NEW_NAMED_PIPE: (Severity.WARN, Category.NETWORK),

    # WMI - CRITICAL (common persistence)
    SignalTypes.NEW_WMI_SUBSCRIPTION: (Severity.CRITICAL, Category.PERSISTENCE),

    # COM - CRITICAL (hijack = compromise)
    SignalTypes.COM_HIJACK_DETECTED: (Severity.CRITICAL, Category.PERSISTENCE),

    # Logs - ALERT to CRITICAL
    SignalTypes.LOG_GAP: (Severity.WARN, Category.FORENSICS),
    SignalTypes.LOG_CLEARED: (Severity.CRITICAL, Category.FORENSICS),

    # Security - CRITICAL
    SignalTypes.BASELINE_TAMPERED: (Severity.CRITICAL, Category.META),

    # Meta - INFO
    SignalTypes.CANARY_SILENCED: (Severity.CRITICAL, Category.META),
    SignalTypes.PARSER_STARTED: (Severity.INFO, Category.META),
    SignalTypes.BASELINE_INITIALIZED: (Severity.INFO, Category.META),
    SignalTypes.WATCHDOG_ALERT: (Severity.CRITICAL, Category.META),
}


# Human-readable translations
SIGNAL_TRANSLATIONS = {
    SignalTypes.NEW_KERNEL_DRIVER: "A new kernel driver just showed up. That wasn't here before.",
    SignalTypes.DRIVER_DISAPPEARED: "A kernel driver that was here before is gone now. Huh.",
    SignalTypes.NEW_SERVICE: "New service appeared. Someone installed something.",
    SignalTypes.SERVICE_DISAPPEARED: "A service that used to exist just... doesn't anymore.",
    SignalTypes.SERVICE_STATE_CHANGED: "A service changed its running state.",
    SignalTypes.NEW_PROCESS_NAME: "I'm seeing a process name I haven't seen before.",
    SignalTypes.UNUSUAL_PARENT_CHILD: "That's a WEIRD parent process for this child. Red flag.",
    SignalTypes.SUSPICIOUS_COMMAND_LINE: "Suspicious command line detected. Encoded? Download cradle?",
    SignalTypes.UNSIGNED_BINARY: "An unsigned executable just ran. Could be fine. Could be not.",
    SignalTypes.NEW_OUTBOUND_DEST: "This machine just talked to a new place on the internet.",
    SignalTypes.NEW_LISTENING_PORT: "Something new is listening on the network. Wasn't before.",
    SignalTypes.CONNECTION_SPIKE: "Yo. Not. Normal. At. All. Huge connection spike.",
    SignalTypes.BEACONING_DETECTED: "Regular interval connections detected. Looks like a heartbeat. C2?",
    SignalTypes.NEW_DNS_RESOLUTION: "New domain resolved. First time seeing this one.",
    SignalTypes.SUSPICIOUS_DOMAIN: "Sketchy domain detected. Weird TLD or looks auto-generated.",
    SignalTypes.NEW_AUTORUN: "Something new will run at startup now. FYI.",
    SignalTypes.AUTORUN_DISAPPEARED: "An autorun entry got removed. Maybe intentional.",
    SignalTypes.NEW_SCHEDULED_TASK: "New scheduled task appeared. Something wants to run later.",
    SignalTypes.TASK_DISAPPEARED: "A scheduled task vanished. Interesting.",
    SignalTypes.NEW_EXECUTABLE_DROPPED: "New executable dropped in a monitored folder.",
    SignalTypes.STARTUP_FOLDER_MODIFIED: "Startup folder was modified. Persistence attempt?",
    SignalTypes.SYSTEM32_MODIFIED: "System32 was modified. That's... concerning.",
    SignalTypes.UNUSUAL_DLL_LOADED: "Unusual DLL loaded from a sketchy location.",
    SignalTypes.UNSIGNED_DLL_IN_SIGNED: "Unsigned DLL in a signed process. Side-loading?",
    SignalTypes.NEW_NAMED_PIPE: "New named pipe appeared. Common C2 channel.",
    SignalTypes.NEW_WMI_SUBSCRIPTION: "WMI event subscription detected. Sneaky persistence.",
    SignalTypes.COM_HIJACK_DETECTED: "COM object hijack detected. Bad.",
    SignalTypes.LOG_GAP: "I stopped hearing logs for a bit. That's unusual.",
    SignalTypes.LOG_CLEARED: "Someone cleared the logs. That's... a choice.",
    SignalTypes.BASELINE_TAMPERED: "Baseline file was tampered with. Someone's messing with me.",
    SignalTypes.CANARY_SILENCED: "Tell the Ghost I was right.",
    SignalTypes.PARSER_STARTED: "Edge parser woke up. Watching.",
    SignalTypes.BASELINE_INITIALIZED: "First run. Learning what 'normal' looks like here.",
    SignalTypes.WATCHDOG_ALERT: "Watchdog detected a problem with canary components.",
}


def get_signal_metadata(signal_type: str) -> Tuple[Severity, Category]:
    """Get severity and category for a signal type."""
    return SIGNAL_METADATA.get(signal_type, (Severity.INFO, Category.META))


def translate_signal(signal: Signal) -> str:
    """Convert signal to human-readable message."""
    base = SIGNAL_TRANSLATIONS.get(
        signal.signal_type,
        f"Something happened: {signal.signal_type}"
    )

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
    if "domain" in signal.artifacts:
        details.append(signal.artifacts["domain"])
    if "parent" in signal.artifacts:
        details.append(f"parent: {signal.artifacts['parent']}")
    if "child" in signal.artifacts:
        details.append(f"child: {signal.artifacts['child']}")
    if "command" in signal.artifacts:
        cmd = signal.artifacts["command"][:50]
        details.append(f"cmd: {cmd}...")

    if details:
        return f"{base}\n({', '.join(details[:3])})"
    return base


class SignalsDB:
    """SQLite storage for signals (notification center backend)."""

    def __init__(self, db_path: Path = None):
        self.db_path = db_path or SIGNALS_DB
        self._init_db()
        # Track recent signals for dedup/counting
        self._recent_signals: Dict[str, int] = {}  # key -> count
        self._recent_window = 60  # seconds

    def _init_db(self):
        """Initialize database schema."""
        with self._get_conn() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS signals (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    signal_id TEXT UNIQUE NOT NULL,
                    signal_type TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    source_surface TEXT NOT NULL,
                    trigger_reason TEXT,
                    artifacts TEXT,
                    severity TEXT NOT NULL,
                    category TEXT NOT NULL,
                    message TEXT,
                    snoozed_until REAL,
                    read INTEGER DEFAULT 0,
                    repeat_count INTEGER DEFAULT 1
                );

                CREATE INDEX IF NOT EXISTS idx_timestamp ON signals(timestamp);
                CREATE INDEX IF NOT EXISTS idx_severity ON signals(severity);
                CREATE INDEX IF NOT EXISTS idx_category ON signals(category);
                CREATE INDEX IF NOT EXISTS idx_signal_type ON signals(signal_type);

                CREATE TABLE IF NOT EXISTS snooze_rules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    signal_type TEXT UNIQUE NOT NULL,
                    snoozed_until REAL NOT NULL
                );
            """)
            # Add repeat_count column if upgrading
            try:
                conn.execute("ALTER TABLE signals ADD COLUMN repeat_count INTEGER DEFAULT 1")
            except Exception:
                pass  # Column already exists

    @contextmanager
    def _get_conn(self):
        """Get database connection."""
        conn = sqlite3.connect(str(self.db_path), timeout=10)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _get_dedup_key(self, signal: Signal) -> str:
        """Generate dedup key for a signal."""
        # Key by type + main artifact (name, domain, path, etc.)
        key_parts = [signal.signal_type]
        for field in ['name', 'domain', 'path', 'address', 'pipe_name', 'parent', 'child']:
            if field in signal.artifacts:
                key_parts.append(str(signal.artifacts[field]))
                break
        return "|".join(key_parts)

    def store(self, signal: Signal, dedup_window: int = 300):
        """
        Store a signal with deduplication.

        If same signal_type + key artifact seen in last N seconds,
        increment repeat_count instead of creating new entry.
        """
        dedup_key = self._get_dedup_key(signal)
        now = time.time()
        cutoff = now - dedup_window

        with self._get_conn() as conn:
            # Check for recent duplicate
            cursor = conn.execute("""
                SELECT id, repeat_count FROM signals
                WHERE signal_type = ? AND timestamp > ?
                ORDER BY timestamp DESC LIMIT 1
            """, (signal.signal_type, cutoff))
            row = cursor.fetchone()

            # Check if this is a true duplicate (same key)
            if row:
                existing_id = row['id']
                existing_count = row['repeat_count'] or 1

                # Get existing signal to compare
                cursor = conn.execute("SELECT artifacts FROM signals WHERE id = ?", (existing_id,))
                existing = cursor.fetchone()
                if existing:
                    existing_key = self._get_dedup_key_from_row(signal.signal_type, existing['artifacts'])
                    if existing_key == dedup_key:
                        # Increment count on existing
                        conn.execute("""
                            UPDATE signals SET repeat_count = ?, timestamp = ?
                            WHERE id = ?
                        """, (existing_count + 1, now, existing_id))
                        return

            # New signal
            conn.execute("""
                INSERT OR REPLACE INTO signals
                (signal_id, signal_type, timestamp, source_surface, trigger_reason,
                 artifacts, severity, category, message, snoozed_until, repeat_count)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
            """, (
                signal.signal_id,
                signal.signal_type,
                signal.timestamp,
                signal.source_surface,
                signal.trigger_reason,
                json.dumps(signal.artifacts),
                signal.severity,
                signal.category,
                signal.message,
                signal.snoozed_until,
            ))

    def _get_dedup_key_from_row(self, signal_type: str, artifacts_json: str) -> str:
        """Generate dedup key from DB row."""
        key_parts = [signal_type]
        try:
            artifacts = json.loads(artifacts_json) if artifacts_json else {}
            for field in ['name', 'domain', 'path', 'address', 'pipe_name', 'parent', 'child']:
                if field in artifacts:
                    key_parts.append(str(artifacts[field]))
                    break
        except Exception:
            pass
        return "|".join(key_parts)

    def get_signals(
        self,
        category: Optional[str] = None,
        severity: Optional[str] = None,
        since: Optional[float] = None,
        search: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Signal]:
        """Query signals with filters."""
        query = "SELECT * FROM signals WHERE 1=1"
        params = []

        if category:
            query += " AND category = ?"
            params.append(category)

        if severity:
            query += " AND severity = ?"
            params.append(severity)

        if since:
            query += " AND timestamp > ?"
            params.append(since)

        if search:
            query += " AND (message LIKE ? OR trigger_reason LIKE ?)"
            params.extend([f"%{search}%", f"%{search}%"])

        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        with self._get_conn() as conn:
            cursor = conn.execute(query, params)
            signals = []
            for row in cursor:
                sig = Signal(
                    signal_id=row['signal_id'],
                    signal_type=row['signal_type'],
                    timestamp=row['timestamp'],
                    source_surface=row['source_surface'],
                    trigger_reason=row['trigger_reason'],
                    artifacts=json.loads(row['artifacts']) if row['artifacts'] else {},
                    severity=row['severity'],
                    category=row['category'],
                    message=row['message'],
                    snoozed_until=row['snoozed_until'],
                    repeat_count=row['repeat_count'] if 'repeat_count' in row.keys() else 1,
                )
                signals.append(sig)
            return signals

    def get_count(
        self,
        category: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> int:
        """Get count of signals matching filters."""
        query = "SELECT COUNT(*) FROM signals WHERE 1=1"
        params = []

        if category:
            query += " AND category = ?"
            params.append(category)

        if severity:
            query += " AND severity = ?"
            params.append(severity)

        with self._get_conn() as conn:
            cursor = conn.execute(query, params)
            return cursor.fetchone()[0]

    def snooze_type(self, signal_type: str, hours: int = 24):
        """Snooze all signals of a type for N hours."""
        until = time.time() + (hours * 3600)
        with self._get_conn() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO snooze_rules (signal_type, snoozed_until)
                VALUES (?, ?)
            """, (signal_type, until))

    def is_snoozed(self, signal_type: str) -> bool:
        """Check if a signal type is snoozed."""
        with self._get_conn() as conn:
            cursor = conn.execute(
                "SELECT snoozed_until FROM snooze_rules WHERE signal_type = ?",
                (signal_type,)
            )
            row = cursor.fetchone()
            if row and row['snoozed_until'] > time.time():
                return True
            return False

    def clear_snooze(self, signal_type: str):
        """Clear snooze for a signal type."""
        with self._get_conn() as conn:
            conn.execute(
                "DELETE FROM snooze_rules WHERE signal_type = ?",
                (signal_type,)
            )

    def cleanup_old(self, days: int = 30):
        """Remove signals older than N days."""
        cutoff = time.time() - (days * 86400)
        with self._get_conn() as conn:
            conn.execute("DELETE FROM signals WHERE timestamp < ?", (cutoff,))

    def clear_all(self):
        """Clear all signals."""
        with self._get_conn() as conn:
            conn.execute("DELETE FROM signals")
            conn.execute("DELETE FROM snooze_rules")


def play_alert_sound(severity: Severity):
    """Play alert sound based on severity."""
    config = get_config().alert

    if not config.sound_enabled:
        return

    if severity in (Severity.ALERT, Severity.CRITICAL):
        try:
            if config.sound_file:
                winsound.PlaySound(config.sound_file, winsound.SND_FILENAME | winsound.SND_ASYNC)
            else:
                # System beep - different patterns for severity
                if severity == Severity.CRITICAL:
                    winsound.Beep(1000, 200)  # High pitch
                    winsound.Beep(1000, 200)
                else:
                    winsound.Beep(800, 300)   # Medium pitch
        except Exception:
            pass  # Ignore sound errors


# Global instances
_signals_db: Optional[SignalsDB] = None


def get_signals_db() -> SignalsDB:
    """Get global signals database."""
    global _signals_db
    if _signals_db is None:
        _signals_db = SignalsDB()
    return _signals_db
