"""
EDGE PARSER - Local, aggressive, expendable system surface monitor.

Monitors:
- Kernel drivers
- Services
- Processes
- Network connections
- Autoruns (registry run keys)
- Scheduled tasks
- Event log gaps

Emits mechanical signals. No inference. No correlation. No judgment.
"""

import subprocess
import time
import sys
import json
import hashlib
import traceback
import re
import math
import os
from datetime import datetime
from typing import List, Set, Tuple, Optional, Dict
from pathlib import Path
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from shared import (
    SignalQueue, Baseline, Signal, SignalTypes,
    CANARY_DIR
)
from config import get_config
from signals import Signal as SignalV2, SignalTypes as SignalTypesV2, Severity, Category, get_signals_db
from platform_utils import (
    get_drivers_impl, get_services_impl, get_processes_impl,
    get_network_impl, get_persistence_impl, get_dns_impl,
    get_filesystem_impl, IS_WINDOWS, IS_LINUX, IS_MACOS,
    get_platform_name
)

# Try to import psutil, fall back to WMI/subprocess if not available
try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False
    print("[!] psutil not found. Using fallback methods (slower).")


class SurfaceMonitor:
    """Base class for surface monitors."""

    # Class-level first-run tracking (set by EdgeParser)
    _first_run_mode = False
    _first_run_counts: Dict[str, int] = {}
    _first_run_batch_enabled = True
    _signals_db = None  # Shared signals DB for emit_v2

    def __init__(self, queue: SignalQueue, baseline: Baseline):
        self.queue = queue
        self.baseline = baseline
        # Initialize shared signals DB on first use
        if SurfaceMonitor._signals_db is None:
            SurfaceMonitor._signals_db = get_signals_db()

    def emit(self, signal_type: str, trigger_reason: str, artifacts: dict = None):
        """Emit a signal to the queue (batched on first run)."""
        # On first run, just count signals instead of emitting each one
        if SurfaceMonitor._first_run_mode and SurfaceMonitor._first_run_batch_enabled:
            key = f"{self.__class__.__name__}:{signal_type}"
            SurfaceMonitor._first_run_counts[key] = SurfaceMonitor._first_run_counts.get(key, 0) + 1
            # Only print progress every 100 signals
            count = SurfaceMonitor._first_run_counts[key]
            if count == 1 or count % 100 == 0:
                print(f"[FIRST RUN] {signal_type}: {count} items...")
            return

        signal = Signal.create(
            signal_type=signal_type,
            source_surface=self.__class__.__name__,
            trigger_reason=trigger_reason,
            artifacts=artifacts or {}
        )
        self.queue.push(signal)
        print(f"[SIGNAL] {signal_type}: {trigger_reason}")

    def emit_v2(self, signal_type: str, source: str, message: str,
                artifacts: dict, severity, category):
        """Emit to both old queue and new signals DB (batched on first run)."""
        # On first run, just count signals instead of emitting
        if SurfaceMonitor._first_run_mode and SurfaceMonitor._first_run_batch_enabled:
            key = f"{self.__class__.__name__}:{signal_type}"
            SurfaceMonitor._first_run_counts[key] = SurfaceMonitor._first_run_counts.get(key, 0) + 1
            count = SurfaceMonitor._first_run_counts[key]
            if count == 1 or count % 100 == 0:
                print(f"[FIRST RUN] {signal_type}: {count} items...")
            return

        # Old system
        self.emit(signal_type, message, artifacts)

        # New system
        sig = SignalV2.create(
            signal_type=signal_type,
            source_surface=source,
            message=message,
            artifacts=artifacts,
            severity=severity,
            category=category
        )
        SurfaceMonitor._signals_db.store(sig)

    def scan(self):
        """Override in subclasses."""
        raise NotImplementedError


class DriverMonitor(SurfaceMonitor):
    """Monitor kernel drivers/modules (cross-platform)."""

    def __init__(self, queue: SignalQueue, baseline: Baseline):
        super().__init__(queue, baseline)
        self._platform = get_drivers_impl()

    def get_drivers(self) -> List[str]:
        """Get list of loaded drivers/modules."""
        try:
            return self._platform.get_loaded_drivers()
        except Exception as e:
            print(f"[!] Driver scan failed: {e}")
            return []

    def scan(self):
        drivers = self.get_drivers()
        if not drivers:
            return

        appeared, disappeared = self.baseline.update_surface("drivers", drivers)

        for driver in appeared:
            self.emit(
                SignalTypes.NEW_KERNEL_DRIVER,
                f"New driver loaded: {driver}",
                {"name": driver}
            )

        for driver in disappeared:
            self.emit(
                SignalTypes.DRIVER_DISAPPEARED,
                f"Driver no longer present: {driver}",
                {"name": driver}
            )


class ServiceMonitor(SurfaceMonitor):
    """Monitor services/daemons (cross-platform)."""

    def __init__(self, queue: SignalQueue, baseline: Baseline):
        super().__init__(queue, baseline)
        self._platform = get_services_impl()

    def get_services(self) -> List[str]:
        """Get list of services with their states."""
        try:
            return self._platform.get_running_services()
        except Exception as e:
            print(f"[!] Service scan failed: {e}")
            return []

    def scan(self):
        services = self.get_services()
        if not services:
            return

        # Extract just service names for baseline comparison
        service_names = [s.split(':')[0] for s in services]
        appeared, disappeared = self.baseline.update_surface("services", service_names)

        for svc in appeared:
            self.emit(
                SignalTypes.NEW_SERVICE,
                f"New service appeared: {svc}",
                {"name": svc}
            )

        for svc in disappeared:
            self.emit(
                SignalTypes.SERVICE_DISAPPEARED,
                f"Service no longer exists: {svc}",
                {"name": svc}
            )


class ProcessMonitor(SurfaceMonitor):
    """Monitor running processes (cross-platform)."""

    def __init__(self, queue: SignalQueue, baseline: Baseline):
        super().__init__(queue, baseline)
        self._platform = get_processes_impl()

    def get_processes(self) -> List[str]:
        """Get list of unique process names."""
        try:
            return self._platform.get_running_processes()
        except Exception as e:
            print(f"[!] Process scan failed: {e}")
            return []

    def scan(self):
        processes = self.get_processes()
        if not processes:
            return

        appeared, disappeared = self.baseline.update_surface("processes", processes)

        # Only signal new process names (not every process start)
        for proc in appeared:
            self.emit(
                SignalTypes.NEW_PROCESS_NAME,
                f"New process name observed: {proc}",
                {"name": proc}
            )


class NetworkMonitor(SurfaceMonitor):
    """
    Monitor network connections with frequency tracking and spike detection (cross-platform).

    Tracks:
    - Known destinations (baseline)
    - Connection counts over time (rolling window)
    - Detects spikes when current count >> average (REALLY BAD = red bubble)
    """

    # Spike detection settings (high threshold = only really bad stuff)
    SPIKE_MULTIPLIER = 4.0      # Current must be 4x the average to trigger
    MIN_BASELINE_SAMPLES = 5    # Need at least 5 samples before detecting spikes
    HISTORY_SIZE = 20           # Keep last 20 connection counts

    def __init__(self, queue, baseline):
        super().__init__(queue, baseline)
        self._platform = get_network_impl()
        # Rolling history of connection counts
        self.connection_history = []
        # Track frequency per destination
        self.dest_frequency = {}

    def get_connections(self) -> Tuple[List[str], List[str], int]:
        """Get outbound destinations, listening ports, and total connection count."""
        try:
            return self._platform.get_connections()
        except Exception as e:
            print(f"[!] Network scan failed: {e}")
            return [], [], 0

    def check_for_spike(self, current_count: int) -> bool:
        """
        Check if current connection count is a spike.
        Returns True if this is REALLY BAD (way above normal).
        """
        # Add to history
        self.connection_history.append(current_count)

        # Keep history bounded
        if len(self.connection_history) > self.HISTORY_SIZE:
            self.connection_history.pop(0)

        # Need enough samples to establish baseline
        if len(self.connection_history) < self.MIN_BASELINE_SAMPLES:
            return False

        # Calculate average (excluding current)
        history = self.connection_history[:-1]
        avg = sum(history) / len(history)

        # Avoid division issues with very low averages
        if avg < 5:
            avg = 5

        # Check if current is way above average
        if current_count > avg * self.SPIKE_MULTIPLIER:
            return True

        return False

    def update_frequency(self, destinations: List[str]):
        """Track how often we see each destination."""
        for dest in destinations:
            if dest not in self.dest_frequency:
                self.dest_frequency[dest] = {"count": 0, "first_seen": time.time()}
            self.dest_frequency[dest]["count"] += 1
            self.dest_frequency[dest]["last_seen"] = time.time()

    def scan(self):
        outbound, listening, total_count = self.get_connections()

        # Update destination frequency
        self.update_frequency(outbound)

        # Check for connection spike (REALLY BAD)
        if self.check_for_spike(total_count):
            avg = sum(self.connection_history[:-1]) / len(self.connection_history[:-1])
            self.emit(
                SignalTypes.CONNECTION_SPIKE,
                f"Connection spike: {total_count} (normally ~{int(avg)})",
                {
                    "count": total_count,
                    "baseline": int(avg),
                    "alert": True  # Triggers red bubble
                }
            )

        # Check outbound destinations
        if outbound:
            appeared, _ = self.baseline.update_surface("connections", outbound)
            for dest in appeared:
                self.emit(
                    SignalTypes.NEW_OUTBOUND_DEST,
                    f"New outbound connection: {dest}",
                    {"address": dest}
                )

        # Check listening ports (separate surface)
        if listening:
            surface_name = "listening_ports"
            self.baseline.data["surfaces"].setdefault(
                surface_name, {"items": [], "first_seen": {}}
            )
            appeared, disappeared = self.baseline.update_surface(surface_name, listening)
            for port in appeared:
                self.emit(
                    SignalTypes.NEW_LISTENING_PORT,
                    f"New listening port: {port}",
                    {"port": port}
                )


class AutorunMonitor(SurfaceMonitor):
    """Monitor autorun/startup locations (cross-platform)."""

    def __init__(self, queue: SignalQueue, baseline: Baseline):
        super().__init__(queue, baseline)
        self._platform = get_persistence_impl()

    def get_autoruns(self) -> List[str]:
        """Get autorun entries."""
        try:
            return self._platform.get_autorun_entries()
        except Exception as e:
            print(f"[!] Autorun scan failed: {e}")
            return []

    def scan(self):
        autoruns = self.get_autoruns()

        appeared, disappeared = self.baseline.update_surface("autoruns", autoruns)

        for entry in appeared:
            self.emit(
                SignalTypes.NEW_AUTORUN,
                f"New autorun entry: {entry[:60]}",
                {"path": entry}
            )

        for entry in disappeared:
            self.emit(
                SignalTypes.AUTORUN_DISAPPEARED,
                f"Autorun entry removed: {entry[:60]}",
                {"path": entry}
            )


class ScheduledTaskMonitor(SurfaceMonitor):
    """Monitor scheduled tasks/cron jobs (cross-platform)."""

    def __init__(self, queue: SignalQueue, baseline: Baseline):
        super().__init__(queue, baseline)
        self._platform = get_persistence_impl()

    def get_tasks(self) -> List[str]:
        """Get list of scheduled tasks."""
        try:
            return self._platform.get_scheduled_tasks()
        except Exception as e:
            print(f"[!] Scheduled task scan failed: {e}")
            return []

    def scan(self):
        tasks = self.get_tasks()
        if not tasks:
            return

        appeared, disappeared = self.baseline.update_surface("scheduled_tasks", tasks)

        for task in appeared:
            self.emit(
                SignalTypes.NEW_SCHEDULED_TASK,
                f"New scheduled task: {task}",
                {"name": task}
            )

        for task in disappeared:
            self.emit(
                SignalTypes.TASK_DISAPPEARED,
                f"Scheduled task removed: {task}",
                {"name": task}
            )


class LogMonitor(SurfaceMonitor):
    """
    Monitor Windows Event Logs for gaps, clears, and suspicious events.

    LOGS MONITORED:
    ===============

    SECURITY LOGS:
    --------------
    - Security                    : Main security audit log
      - Event 1102: Log cleared
      - Event 4624: Successful logon
      - Event 4625: Failed logon
      - Event 4648: Explicit credential logon
      - Event 4672: Special privileges assigned
      - Event 4688: New process created
      - Event 4697: Service installed
      - Event 4698: Scheduled task created
      - Event 4720: User account created
      - Event 4732: Member added to security group

    SYSTEM LOGS:
    ------------
    - System                      : Core Windows system events
      - Event 7045: New service installed
      - Event 7040: Service start type changed
      - Event 104: Log cleared

    POWERSHELL LOGS:
    ----------------
    - Microsoft-Windows-PowerShell/Operational
      - Event 4104: Script block logging (code execution)
      - Event 4103: Module logging

    - Windows PowerShell          : Legacy PowerShell log
      - Event 400: Engine started
      - Event 800: Pipeline execution

    SYSMON LOGS (if installed):
    ---------------------------
    - Microsoft-Windows-Sysmon/Operational
      - Event 1: Process creation
      - Event 3: Network connection
      - Event 7: Image loaded
      - Event 11: File created
      - Event 13: Registry value set
      - Event 22: DNS query

    DEFENDER LOGS:
    --------------
    - Microsoft-Windows-Windows Defender/Operational
      - Event 1116: Malware detected
      - Event 1117: Action taken
      - Event 5001: Real-time protection disabled

    TASK SCHEDULER LOGS:
    --------------------
    - Microsoft-Windows-TaskScheduler/Operational
      - Event 106: Task registered
      - Event 140: Task updated
      - Event 141: Task deleted

    APPLICATION LOGS:
    -----------------
    - Application                 : Application events
      - Event 1000: Application crash
      - Event 1001: Windows Error Reporting

    TERMINAL SERVICES / RDP:
    ------------------------
    - Microsoft-Windows-TerminalServices-LocalSessionManager/Operational
      - Event 21: Session logon succeeded
      - Event 24: Session disconnected
      - Event 25: Session reconnected

    WMI LOGS:
    ---------
    - Microsoft-Windows-WMI-Activity/Operational
      - Event 5857: WMI provider started
      - Event 5858: WMI query executed
      - Event 5861: WMI subscription created

    BITS (Background Intelligent Transfer):
    ---------------------------------------
    - Microsoft-Windows-Bits-Client/Operational
      - Event 59: BITS job started
      - Event 60: BITS job completed

    DNS CLIENT:
    -----------
    - Microsoft-Windows-DNS-Client/Operational
      - DNS query events

    FIREWALL:
    ---------
    - Microsoft-Windows-Windows Firewall With Advanced Security/Firewall
      - Event 2004: Rule added
      - Event 2005: Rule modified
      - Event 2006: Rule deleted
    """

    # Define all monitored logs with their clear event IDs
    MONITORED_LOGS = {
        # Core Windows logs
        "Security": {"clear_event": 1102, "description": "Security audit log"},
        "System": {"clear_event": 104, "description": "System events"},
        "Application": {"clear_event": 104, "description": "Application events"},

        # PowerShell
        "Microsoft-Windows-PowerShell/Operational": {
            "clear_event": None,
            "description": "PowerShell script execution"
        },
        "Windows PowerShell": {
            "clear_event": None,
            "description": "Legacy PowerShell events"
        },

        # Sysmon (if installed)
        "Microsoft-Windows-Sysmon/Operational": {
            "clear_event": None,
            "description": "Sysmon process/network monitoring"
        },

        # Defender
        "Microsoft-Windows-Windows Defender/Operational": {
            "clear_event": None,
            "description": "Windows Defender events"
        },

        # Task Scheduler
        "Microsoft-Windows-TaskScheduler/Operational": {
            "clear_event": None,
            "description": "Scheduled task events"
        },

        # Terminal Services / RDP
        "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational": {
            "clear_event": None,
            "description": "RDP session events"
        },

        # WMI
        "Microsoft-Windows-WMI-Activity/Operational": {
            "clear_event": None,
            "description": "WMI activity events"
        },

        # BITS
        "Microsoft-Windows-Bits-Client/Operational": {
            "clear_event": None,
            "description": "BITS file transfer events"
        },

        # Firewall
        "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall": {
            "clear_event": None,
            "description": "Firewall rule changes"
        },
    }

    # Interesting events to watch for (log_name: [event_ids])
    WATCH_EVENTS = {
        "Security": [
            1102,  # Log cleared
            4697,  # Service installed
            4698,  # Scheduled task created
            4720,  # User account created
        ],
        "System": [
            104,   # Log cleared
            7045,  # New service installed
        ],
        "Microsoft-Windows-Windows Defender/Operational": [
            1116,  # Malware detected
            5001,  # Real-time protection disabled
        ],
    }

    def __init__(self, queue: SignalQueue, baseline: Baseline):
        super().__init__(queue, baseline)
        self.last_log_time = {}
        self.last_log_count = {}
        self.last_event_counts = {}
        self.available_logs = set()
        self._check_available_logs()

    def _check_available_logs(self):
        """Check which logs are actually available on this system."""
        for log_name in self.MONITORED_LOGS.keys():
            try:
                result = subprocess.run(
                    ["powershell", "-Command",
                     f"(Get-WinEvent -LogName '{log_name}' -MaxEvents 1 -ErrorAction Stop) -ne \\$null"],
                    capture_output=True, text=True, timeout=10
                )
                if result.returncode == 0:
                    self.available_logs.add(log_name)
            except Exception:
                pass

        print(f"[*] Available logs: {len(self.available_logs)}/{len(self.MONITORED_LOGS)}")

    def check_log_health(self, log_name: str):
        """Check a specific log for gaps, clears, and event counts."""
        if log_name not in self.available_logs:
            return

        try:
            # Get latest event timestamp and count
            ps_cmd = f"""
                $events = Get-WinEvent -LogName '{log_name}' -MaxEvents 50 -ErrorAction SilentlyContinue
                if ($events) {{
                    @{{
                        'count' = $events.Count
                        'latest' = $events[0].TimeCreated.ToString('o')
                        'oldest' = $events[-1].TimeCreated.ToString('o')
                    }} | ConvertTo-Json
                }}
            """
            result = subprocess.run(
                ["powershell", "-Command", ps_cmd],
                capture_output=True, text=True, timeout=30
            )

            if result.stdout.strip():
                data = json.loads(result.stdout.strip())
                current_count = data.get('count', 0)
                latest_time = data.get('latest', '')

                # Check for sudden count drop (possible clear)
                prev_count = self.last_log_count.get(f"{log_name}_count", 0)
                if prev_count > 0 and current_count < prev_count * 0.5:
                    self.emit(
                        SignalTypes.LOG_CLEARED,
                        f"{log_name} log may have been cleared (count dropped)",
                        {"log": log_name, "prev": prev_count, "current": current_count}
                    )

                self.last_log_count[f"{log_name}_count"] = current_count
                self.last_log_time[log_name] = latest_time

        except Exception as e:
            # Log became unavailable
            if log_name in self.last_log_time:
                self.emit(
                    SignalTypes.LOG_GAP,
                    f"Cannot read {log_name} log",
                    {"log": log_name, "error": str(e)[:100]}
                )

    def check_specific_events(self, log_name: str, event_ids: list):
        """Check for specific event IDs in a log."""
        if log_name not in self.available_logs:
            return

        try:
            id_filter = " -or ".join([f"\\$_.Id -eq {eid}" for eid in event_ids])
            ps_cmd = f"""
                Get-WinEvent -LogName '{log_name}' -MaxEvents 100 -ErrorAction SilentlyContinue |
                Where-Object {{ {id_filter} }} |
                Select-Object Id, TimeCreated, Message |
                ConvertTo-Json
            """
            result = subprocess.run(
                ["powershell", "-Command", ps_cmd],
                capture_output=True, text=True, timeout=30
            )

            if result.stdout.strip():
                events = json.loads(result.stdout.strip())
                if isinstance(events, dict):
                    events = [events]

                for event in events:
                    event_key = f"{log_name}:{event['Id']}:{event['TimeCreated']}"
                    if event_key not in self.last_event_counts:
                        self.last_event_counts[event_key] = True
                        # Only emit for new events (not on first run)
                        if len(self.last_event_counts) > len(event_ids):
                            msg = event.get('Message', '')[:100] if event.get('Message') else ''
                            self.emit(
                                SignalTypes.LOG_GAP,  # Reusing for interesting events
                                f"Interesting event in {log_name}: ID {event['Id']}",
                                {"log": log_name, "event_id": event['Id'], "message": msg}
                            )

        except Exception:
            pass

    def scan(self):
        """Scan all monitored logs."""
        # Check health of each available log
        for log_name in self.available_logs:
            self.check_log_health(log_name)

        # Check for specific interesting events
        for log_name, event_ids in self.WATCH_EVENTS.items():
            self.check_specific_events(log_name, event_ids)

    @classmethod
    def list_monitored_logs(cls):
        """Print a formatted list of all monitored logs."""
        print("\n" + "=" * 60)
        print("LOGS MONITORED BY EDGE PARSER")
        print("=" * 60)
        for log_name, info in cls.MONITORED_LOGS.items():
            print(f"\n  {log_name}")
            print(f"    Description: {info['description']}")
            if info.get('clear_event'):
                print(f"    Clear event ID: {info['clear_event']}")
        print("\n" + "=" * 60)


class DNSMonitor(SurfaceMonitor):
    """
    Monitor DNS cache for new domains and suspicious patterns (cross-platform).

    Detects:
    - New domains resolved for the first time
    - Suspicious TLDs (.xyz, .top, .tk, etc.)
    - DGA-like patterns (high entropy random-looking domains)
    """

    def __init__(self, queue, baseline):
        super().__init__(queue, baseline)
        self._platform = get_dns_impl()
        self.config = get_config().dns

    def get_dns_cache(self) -> List[str]:
        """Get domains from DNS cache."""
        try:
            return self._platform.get_dns_cache()
        except Exception as e:
            print(f"[!] DNS cache scan failed: {e}")
            return []

    def calculate_entropy(self, s: str) -> float:
        """Calculate Shannon entropy of a string (DGA detection)."""
        if not s:
            return 0.0
        prob = [s.count(c) / len(s) for c in set(s)]
        return -sum(p * math.log2(p) for p in prob if p > 0)

    def is_suspicious_tld(self, domain: str) -> bool:
        """Check if domain has a suspicious TLD."""
        for tld in self.config.suspicious_tlds:
            if domain.endswith(tld):
                return True
        return False

    def is_dga_like(self, domain: str) -> bool:
        """Check if domain looks like DGA (Domain Generation Algorithm)."""
        # Get the main domain part (remove TLD)
        parts = domain.split('.')
        if len(parts) < 2:
            return False

        # Check the second-level domain
        sld = parts[-2]

        # Too short or too long = suspicious
        if len(sld) < 3 or len(sld) > 20:
            return False

        # High entropy = random-looking = suspicious
        entropy = self.calculate_entropy(sld)
        if entropy > self.config.dga_entropy_threshold:
            # Also check for excessive consonant clusters
            vowels = set('aeiou')
            consonant_run = 0
            max_consonant_run = 0
            for c in sld:
                if c.isalpha() and c not in vowels:
                    consonant_run += 1
                    max_consonant_run = max(max_consonant_run, consonant_run)
                else:
                    consonant_run = 0

            # 5+ consonants in a row = very suspicious
            if max_consonant_run >= 5 or entropy > 4.0:
                return True

        return False

    def scan(self):
        domains = self.get_dns_cache()
        if not domains:
            return

        appeared, _ = self.baseline.update_surface("dns_domains", domains)

        for domain in appeared:
            severity = Severity.INFO

            # Check for suspicious patterns
            if self.is_dga_like(domain):
                self.emit_v2(
                    SignalTypesV2.SUSPICIOUS_DOMAIN,
                    "DNSMonitor",
                    f"DGA-like domain: {domain}",
                    {"domain": domain, "reason": "dga_pattern"},
                    Severity.ALERT,
                    Category.NETWORK
                )
            elif self.is_suspicious_tld(domain):
                self.emit_v2(
                    SignalTypesV2.SUSPICIOUS_DOMAIN,
                    "DNSMonitor",
                    f"Suspicious TLD: {domain}",
                    {"domain": domain, "reason": "suspicious_tld"},
                    Severity.WARN,
                    Category.NETWORK
                )
            else:
                self.emit_v2(
                    SignalTypesV2.NEW_DNS_RESOLUTION,
                    "DNSMonitor",
                    f"New domain: {domain}",
                    {"domain": domain},
                    Severity.INFO,
                    Category.NETWORK
                )


class ProcessAncestryMonitor(SurfaceMonitor):
    """
    Monitor process parent-child relationships for unusual spawns (cross-platform).

    Detects:
    - Office apps spawning cmd/powershell (macro execution)
    - Browsers spawning shells (drive-by downloads)
    - Encoded/obfuscated command lines
    """

    def __init__(self, queue, baseline):
        super().__init__(queue, baseline)
        self._platform = get_processes_impl()
        self.config = get_config().process
        self.seen_chains = set()  # Track seen parent-child pairs

    def get_process_tree(self) -> List[Dict]:
        """Get process tree with parent info."""
        try:
            return self._platform.get_process_tree()
        except Exception as e:
            print(f"[!] Process tree scan failed: {e}")
            return []

    def is_suspicious_spawn(self, parent: str, child: str) -> bool:
        """Check if parent->child relationship is suspicious."""
        parent_upper = parent.upper()
        child_upper = child.upper()

        # Check against config
        for sus_parent in self.config.suspicious_parents:
            if parent_upper == sus_parent.upper():
                for sus_child in self.config.suspicious_children:
                    if child_upper == sus_child.upper():
                        return True
        return False

    def is_suspicious_cmdline(self, cmdline: str) -> Tuple[bool, str]:
        """Check command line for suspicious patterns."""
        if not cmdline:
            return False, ""

        cmdline_lower = cmdline.lower()

        # Encoded PowerShell
        if '-encodedcommand' in cmdline_lower or '-enc ' in cmdline_lower or '-e ' in cmdline_lower:
            if 'powershell' in cmdline_lower or 'pwsh' in cmdline_lower:
                return True, "encoded_powershell"

        # Download cradles
        download_patterns = [
            'downloadstring', 'downloadfile', 'downloaddata',
            'invoke-webrequest', 'iwr ', 'wget ', 'curl ',
            'start-bitstransfer', 'net.webclient',
            'invoke-restmethod', 'irm '
        ]
        for pattern in download_patterns:
            if pattern in cmdline_lower:
                return True, "download_cradle"

        # Execution bypass
        if '-executionpolicy' in cmdline_lower and 'bypass' in cmdline_lower:
            return True, "execution_bypass"

        # Hidden window
        if '-windowstyle' in cmdline_lower and 'hidden' in cmdline_lower:
            return True, "hidden_window"

        # Base64 in command
        if re.search(r'[A-Za-z0-9+/]{50,}={0,2}', cmdline):
            return True, "base64_blob"

        return False, ""

    def scan(self):
        processes = self.get_process_tree()

        for proc in processes:
            name = proc.get('name', '')
            parent = proc.get('parent_name', '')
            cmdline = proc.get('cmdline', '')

            # Check parent-child relationship
            if parent and name:
                chain = f"{parent}->{name}"
                if chain not in self.seen_chains:
                    if self.is_suspicious_spawn(parent, name):
                        self.seen_chains.add(chain)
                        self.emit_v2(
                            SignalTypesV2.UNUSUAL_PARENT_CHILD,
                            "ProcessAncestryMonitor",
                            f"Suspicious spawn: {parent} → {name}",
                            {"parent": parent, "child": name, "cmdline": cmdline[:200]},
                            Severity.ALERT,
                            Category.PROCESS
                        )

            # Check command line
            is_sus, reason = self.is_suspicious_cmdline(cmdline)
            if is_sus:
                cmd_hash = hashlib.md5(cmdline.encode()).hexdigest()[:8]
                chain_key = f"cmdline:{name}:{cmd_hash}"
                if chain_key not in self.seen_chains:
                    self.seen_chains.add(chain_key)
                    self.emit_v2(
                        SignalTypesV2.SUSPICIOUS_COMMAND_LINE,
                        "ProcessAncestryMonitor",
                        f"Suspicious command: {name} ({reason})",
                        {"process": name, "reason": reason, "cmdline": cmdline[:300]},
                        Severity.ALERT,
                        Category.PROCESS
                    )


class BeaconingMonitor(SurfaceMonitor):
    """
    Detect regular-interval connections (C2 beaconing).

    Tracks connection timestamps per destination and looks for
    suspiciously regular patterns that indicate automated callbacks.
    """

    def __init__(self, queue, baseline):
        super().__init__(queue, baseline)
        self.config = get_config().network
        # Track connection times per destination: {dest: [timestamp, ...]}
        self.connection_times: Dict[str, List[float]] = defaultdict(list)
        self.alerted_destinations = set()

    def record_connection(self, dest: str):
        """Record a connection timestamp for a destination."""
        now = time.time()
        self.connection_times[dest].append(now)

        # Keep only last 20 timestamps per dest
        if len(self.connection_times[dest]) > 20:
            self.connection_times[dest] = self.connection_times[dest][-20:]

    def detect_beaconing(self, dest: str) -> Optional[Dict]:
        """
        Detect if connections to this dest show beaconing pattern.
        Returns dict with interval info if beaconing detected.
        """
        times = self.connection_times.get(dest, [])

        if len(times) < self.config.beaconing_min_connections:
            return None

        # Calculate inter-arrival times
        intervals = []
        for i in range(1, len(times)):
            intervals.append(times[i] - times[i-1])

        if len(intervals) < 2:
            return None

        # Calculate mean and standard deviation
        mean_interval = sum(intervals) / len(intervals)
        if mean_interval < 10:  # Ignore very rapid connections
            return None

        variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
        std_dev = math.sqrt(variance)

        # Coefficient of variation (CV) = std_dev / mean
        # Low CV means regular intervals
        cv = std_dev / mean_interval if mean_interval > 0 else float('inf')

        # If CV is below jitter tolerance, it's beaconing
        if cv <= self.config.beaconing_jitter_tolerance:
            return {
                "interval_seconds": round(mean_interval, 1),
                "jitter_percent": round(cv * 100, 1),
                "samples": len(times)
            }

        return None

    def get_current_connections(self) -> List[str]:
        """Get current outbound connections."""
        connections = []

        if HAS_PSUTIL:
            try:
                for conn in psutil.net_connections(kind='inet'):
                    if conn.status == 'ESTABLISHED' and conn.raddr:
                        raddr = conn.raddr.ip
                        if not raddr.startswith('127.') and raddr != '::1':
                            connections.append(f"{raddr}:{conn.raddr.port}")
            except Exception:
                pass

        return connections

    def scan(self):
        connections = self.get_current_connections()

        for dest in connections:
            self.record_connection(dest)

            # Check for beaconing
            if dest not in self.alerted_destinations:
                beacon_info = self.detect_beaconing(dest)
                if beacon_info:
                    self.alerted_destinations.add(dest)
                    self.emit_v2(
                        SignalTypesV2.BEACONING_DETECTED,
                        "BeaconingMonitor",
                        f"Beaconing: {dest} every ~{beacon_info['interval_seconds']}s",
                        {"destination": dest, **beacon_info},
                        Severity.CRITICAL,
                        Category.NETWORK
                    )


class FileSystemMonitor(SurfaceMonitor):
    """
    Monitor sensitive file system paths for new executables (cross-platform).

    Watches platform-specific sensitive paths like:
    - Windows: System32, Windows\\Temp, Downloads, Startup
    - Linux: /usr/bin, /tmp, ~/.local/bin, ~/Downloads
    - macOS: Similar to Linux
    """

    EXECUTABLE_EXTENSIONS = {'.exe', '.dll', '.sys', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.sh', '.py'}

    def __init__(self, queue, baseline):
        super().__init__(queue, baseline)
        self._platform = get_filesystem_impl()
        self.config = get_config().filesystem
        self.watch_paths = self._build_watch_paths()

    def _build_watch_paths(self) -> List[Path]:
        """Build list of paths to monitor (cross-platform)."""
        paths = set()

        # Add platform-specific sensitive paths
        for p in self._platform.get_sensitive_paths():
            paths.add(p)

        # Add configured paths (if they exist)
        for p in self.config.watch_paths:
            path = Path(p)
            if path.exists():
                paths.add(path)

        return list(paths)

    def get_executables(self, path: Path) -> List[str]:
        """Get executable files in a path (non-recursive for speed)."""
        executables = []
        try:
            for item in path.iterdir():
                if item.is_file():
                    ext = item.suffix.lower()
                    if ext in self.EXECUTABLE_EXTENSIONS:
                        # Include path and modification time for uniqueness
                        mtime = item.stat().st_mtime
                        executables.append(f"{item.name}|{int(mtime)}")
        except PermissionError:
            pass
        except Exception as e:
            print(f"[!] FileSystem scan error on {path}: {e}")
        return executables

    def scan(self):
        for watch_path in self.watch_paths:
            surface_name = f"fs:{watch_path.name}"
            executables = self.get_executables(watch_path)

            if not executables:
                continue

            appeared, disappeared = self.baseline.update_surface(surface_name, executables)

            for entry in appeared:
                filename = entry.split('|')[0]
                full_path = watch_path / filename

                # Determine severity based on location
                path_str = str(watch_path).lower()
                if 'system32' in path_str:
                    severity = Severity.CRITICAL
                    signal_type = SignalTypesV2.SYSTEM32_MODIFIED
                    message = f"System32 new file: {filename}"
                elif 'startup' in path_str:
                    severity = Severity.ALERT
                    signal_type = SignalTypesV2.STARTUP_FOLDER_MODIFIED
                    message = f"Startup folder: {filename}"
                else:
                    severity = Severity.WARN
                    signal_type = SignalTypesV2.NEW_EXECUTABLE_DROPPED
                    message = f"New executable: {filename} in {watch_path.name}"

                self.emit_v2(
                    signal_type,
                    "FileSystemMonitor",
                    message,
                    {"filename": filename, "path": str(full_path)},
                    severity,
                    Category.FILESYSTEM
                )


class DLLMonitor(SurfaceMonitor):
    """
    Monitor for unusual DLL loads.

    Detects:
    - DLLs loaded from temp/downloads folders
    - Side-loading attempts
    """

    def __init__(self, queue, baseline):
        super().__init__(queue, baseline)
        self.seen_dlls = set()

    def get_loaded_dlls(self) -> List[Dict]:
        """Get DLLs loaded by processes."""
        dlls = []

        if HAS_PSUTIL:
            # Focus on key processes
            target_processes = ['explorer.exe', 'svchost.exe', 'rundll32.exe', 'powershell.exe']
            try:
                for proc in psutil.process_iter(['name', 'pid']):
                    try:
                        name = proc.info['name'].lower()
                        if name in target_processes:
                            for dll in proc.memory_maps():
                                path = dll.path
                                if path.endswith('.dll'):
                                    dlls.append({
                                        'process': proc.info['name'],
                                        'pid': proc.info['pid'],
                                        'dll_path': path
                                    })
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
            except Exception:
                pass

        return dlls

    def is_suspicious_path(self, dll_path: str) -> Tuple[bool, str]:
        """Check if DLL path is suspicious."""
        path_lower = dll_path.lower()

        suspicious_locations = [
            ('temp', 'temp folder'),
            ('downloads', 'downloads folder'),
            ('appdata\\local\\temp', 'temp folder'),
            ('public', 'public folder'),
            ('users\\public', 'public folder'),
        ]

        for pattern, reason in suspicious_locations:
            if pattern in path_lower:
                return True, reason

        return False, ""

    def scan(self):
        dlls = self.get_loaded_dlls()

        for dll in dlls:
            dll_path = dll['dll_path']
            dll_key = f"{dll['process']}:{dll_path}"

            if dll_key in self.seen_dlls:
                continue

            is_sus, reason = self.is_suspicious_path(dll_path)
            if is_sus:
                self.seen_dlls.add(dll_key)
                filename = Path(dll_path).name
                self.emit_v2(
                    SignalTypesV2.UNUSUAL_DLL_LOADED,
                    "DLLMonitor",
                    f"Suspicious DLL: {filename} in {dll['process']} ({reason})",
                    {"dll": filename, "path": dll_path, "process": dll['process'], "reason": reason},
                    Severity.ALERT,
                    Category.PROCESS
                )


class NamedPipeMonitor(SurfaceMonitor):
    """
    Monitor named pipes for C2 indicators.

    Named pipes are commonly used by malware for:
    - Cobalt Strike beacons
    - Meterpreter sessions
    - Custom C2 channels
    """

    def __init__(self, queue, baseline):
        super().__init__(queue, baseline)

    def get_named_pipes(self) -> List[str]:
        """Get list of named pipes."""
        pipes = []
        try:
            # List pipes via PowerShell
            result = subprocess.run(
                ["powershell", "-Command", "[IO.Directory]::GetFiles('\\\\.\\pipe\\')"],
                capture_output=True, text=True, timeout=30
            )
            for line in result.stdout.strip().split('\n'):
                line = line.strip()
                if line:
                    # Extract pipe name from full path
                    pipe_name = line.replace('\\\\.\\pipe\\', '')
                    pipes.append(pipe_name)
        except Exception as e:
            print(f"[!] Named pipe scan failed: {e}")
        return pipes

    def scan(self):
        pipes = self.get_named_pipes()
        if not pipes:
            return

        appeared, _ = self.baseline.update_surface("named_pipes", pipes)

        for pipe in appeared:
            self.emit_v2(
                SignalTypesV2.NEW_NAMED_PIPE,
                "NamedPipeMonitor",
                f"New named pipe: {pipe}",
                {"pipe_name": pipe},
                Severity.WARN,
                Category.NETWORK
            )


class WMIMonitor(SurfaceMonitor):
    """
    Monitor WMI event subscriptions (common persistence mechanism).

    Detects:
    - __EventFilter creations
    - __EventConsumer bindings
    - CommandLineEventConsumer (code execution)
    """

    def __init__(self, queue, baseline):
        super().__init__(queue, baseline)

    def get_wmi_subscriptions(self) -> List[str]:
        """Get WMI event subscriptions."""
        subscriptions = []
        try:
            # Query for event filters
            ps_cmd = """
                Get-WmiObject -Namespace root\\subscription -Class __EventFilter -ErrorAction SilentlyContinue |
                ForEach-Object { $_.Name + '|' + $_.Query }
            """
            result = subprocess.run(
                ["powershell", "-Command", ps_cmd],
                capture_output=True, text=True, timeout=30
            )
            for line in result.stdout.strip().split('\n'):
                if line.strip():
                    subscriptions.append(f"Filter:{line.strip()}")

            # Query for event consumers
            ps_cmd = """
                Get-WmiObject -Namespace root\\subscription -Class CommandLineEventConsumer -ErrorAction SilentlyContinue |
                ForEach-Object { $_.Name + '|' + $_.CommandLineTemplate }
            """
            result = subprocess.run(
                ["powershell", "-Command", ps_cmd],
                capture_output=True, text=True, timeout=30
            )
            for line in result.stdout.strip().split('\n'):
                if line.strip():
                    subscriptions.append(f"Consumer:{line.strip()}")

        except Exception as e:
            print(f"[!] WMI subscription scan failed: {e}")
        return subscriptions

    def scan(self):
        subscriptions = self.get_wmi_subscriptions()
        if not subscriptions:
            return

        appeared, _ = self.baseline.update_surface("wmi_subscriptions", subscriptions)

        for sub in appeared:
            sub_type = sub.split(':')[0]
            sub_detail = sub.split(':', 1)[1] if ':' in sub else sub
            self.emit_v2(
                SignalTypesV2.NEW_WMI_SUBSCRIPTION,
                "WMIMonitor",
                f"WMI {sub_type}: {sub_detail[:60]}",
                {"type": sub_type, "detail": sub_detail},
                Severity.CRITICAL,
                Category.PERSISTENCE
            )


class COMMonitor(SurfaceMonitor):
    """
    Monitor for COM object hijacking.

    Checks common hijackable CLSIDs in registry.
    """

    # Common hijackable CLSIDs
    HIJACKABLE_CLSIDS = {
        "{BCDE0395-E52F-467C-8E3D-C4579291692E}": "MMDeviceEnumerator",
        "{4590F811-1D3A-11D0-891F-00AA004B2E24}": "Wscript.Shell",
        "{72C24DD5-D70A-438B-8A42-98424B88AFB8}": "Scripting.FileSystemObject",
    }

    def __init__(self, queue, baseline):
        super().__init__(queue, baseline)
        self.checked_clsids = {}

    def get_clsid_value(self, clsid: str) -> Optional[str]:
        """Get InprocServer32 value for a CLSID."""
        try:
            result = subprocess.run(
                ["reg", "query", f"HKCR\\CLSID\\{clsid}\\InprocServer32", "/ve"],
                capture_output=True, text=True, timeout=10
            )
            for line in result.stdout.split('\n'):
                if 'REG_SZ' in line or 'REG_EXPAND_SZ' in line:
                    parts = line.split('    ')
                    if len(parts) >= 3:
                        return parts[-1].strip()
        except Exception:
            pass
        return None

    def scan(self):
        for clsid, name in self.HIJACKABLE_CLSIDS.items():
            current_value = self.get_clsid_value(clsid)
            if current_value is None:
                continue

            # Check if value changed from last scan
            if clsid in self.checked_clsids:
                prev_value = self.checked_clsids[clsid]
                if current_value != prev_value:
                    self.emit_v2(
                        SignalTypesV2.COM_HIJACK_DETECTED,
                        "COMMonitor",
                        f"COM hijack: {name} ({clsid})",
                        {"clsid": clsid, "name": name, "old": prev_value, "new": current_value},
                        Severity.CRITICAL,
                        Category.PERSISTENCE
                    )

            self.checked_clsids[clsid] = current_value


class EdgeParser:
    """
    Main edge parser orchestrator.
    Runs surface monitors on a loop and emits signals.
    """

    def __init__(self, interval: int = 30):
        self.interval = interval
        self.queue = SignalQueue()
        self.baseline = Baseline()
        self.running = False
        self.is_first_run = self.baseline.is_first_run()
        self.first_run_counts: Dict[str, int] = {}  # Track signal counts for batching
        self.config = get_config()

        # Initialize monitors - cross-platform core
        self.monitors = [
            DriverMonitor(self.queue, self.baseline),
            ServiceMonitor(self.queue, self.baseline),
            ProcessMonitor(self.queue, self.baseline),
            NetworkMonitor(self.queue, self.baseline),
            AutorunMonitor(self.queue, self.baseline),
            ScheduledTaskMonitor(self.queue, self.baseline),
            DNSMonitor(self.queue, self.baseline),
            ProcessAncestryMonitor(self.queue, self.baseline),
            BeaconingMonitor(self.queue, self.baseline),
            FileSystemMonitor(self.queue, self.baseline),
        ]

        # Windows-specific monitors
        if IS_WINDOWS:
            self.monitors.extend([
                LogMonitor(self.queue, self.baseline),
                DLLMonitor(self.queue, self.baseline),
                NamedPipeMonitor(self.queue, self.baseline),
                WMIMonitor(self.queue, self.baseline),
                COMMonitor(self.queue, self.baseline),
            ])
            print(f"[*] Platform: Windows - {len(self.monitors)} monitors active")
        else:
            print(f"[*] Platform: {get_platform_name()} - {len(self.monitors)} monitors active (Windows-specific monitors disabled)")

        # Emit capability introspection
        self._emit_capabilities()

    def _emit_capabilities(self):
        """Emit a single INFO signal describing what this canary can see."""
        platform = get_platform_name()
        active = [m.__class__.__name__.replace('Monitor', '') for m in self.monitors]

        # Windows-only monitors that are disabled on other platforms
        windows_only = ['Log', 'DLL', 'NamedPipe', 'WMI', 'COM']
        disabled = [] if IS_WINDOWS else [(name, "Windows-only") for name in windows_only]

        # Build the message
        msg = f"I'm watching {len(active)} things on this {platform} machine."
        if disabled:
            msg += f" ({len(disabled)} monitors unavailable: {', '.join(d[0] for d in disabled)})"

        signal = Signal.create(
            signal_type=SignalTypes.PARSER_STARTED,
            source_surface="EdgeParser",
            trigger_reason=msg,
            artifacts={
                "platform": platform,
                "active_monitors": active,
                "disabled_monitors": {name: reason for name, reason in disabled},
                "monitor_count": len(active)
            }
        )
        self.queue.push(signal)
        print(f"[CANARY] {msg}")

    def run_once(self, standalone: bool = False):
        """Run all monitors once.

        Args:
            standalone: If True, this is being called directly (not from run loop)
                       so set up first-run mode if needed.
        """
        # Set up first-run mode if running standalone
        if standalone and self.is_first_run and self.config.scan.first_run_batch_signals:
            SurfaceMonitor._first_run_mode = True
            SurfaceMonitor._first_run_batch_enabled = True
            SurfaceMonitor._first_run_counts.clear()

        print(f"\n[{datetime.now().strftime('%H:%M:%S')}] Scanning surfaces...")

        # Run monitors in parallel for faster scanning
        workers = self.config.scan.parallel_workers
        if workers > 1:
            self._scan_parallel(workers)
        else:
            self._scan_sequential()

        self.baseline.save()

        # On first run, emit summary signals instead of individual ones
        if self.is_first_run and SurfaceMonitor._first_run_counts:
            self._emit_first_run_summaries()
            self.is_first_run = False
            SurfaceMonitor._first_run_mode = False

    def _scan_sequential(self):
        """Run monitors one at a time."""
        for monitor in self.monitors:
            try:
                monitor.scan()
            except Exception as e:
                print(f"[!] {monitor.__class__.__name__} error: {e}")
                traceback.print_exc()

    def _scan_parallel(self, workers: int):
        """Run monitors in parallel using thread pool."""
        def run_monitor(monitor):
            try:
                monitor.scan()
                return (monitor.__class__.__name__, None)
            except Exception as e:
                return (monitor.__class__.__name__, e)

        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(run_monitor, m): m for m in self.monitors}
            for future in as_completed(futures):
                name, error = future.result()
                if error:
                    print(f"[!] {name} error: {error}")
                    traceback.print_exc()

    def _emit_first_run_summaries(self):
        """Emit batched summary signals for first run."""
        print("\n[*] First run complete - emitting summaries...")

        # Group by monitor
        by_monitor: Dict[str, Dict[str, int]] = {}
        for key, count in SurfaceMonitor._first_run_counts.items():
            monitor_name, signal_type = key.split(':', 1)
            if monitor_name not in by_monitor:
                by_monitor[monitor_name] = {}
            by_monitor[monitor_name][signal_type] = count

        # Emit one summary signal per monitor
        for monitor_name, signals in by_monitor.items():
            total = sum(signals.values())
            details = ", ".join(f"{t}: {c}" for t, c in signals.items())

            signal = Signal.create(
                signal_type=SignalTypes.BASELINE_INITIALIZED,
                source_surface=monitor_name,
                trigger_reason=f"First run baseline: {total} items added ({details})",
                artifacts={"counts": signals, "total": total}
            )
            self.queue.push(signal)
            print(f"[SUMMARY] {monitor_name}: {total} items baselined")

        # Clear counts
        SurfaceMonitor._first_run_counts.clear()

    def run(self):
        """Run the parser loop."""
        print("=" * 50)
        print("EDGE PARSER - Local Surface Monitor")
        print("=" * 50)
        print(f"Interval: {self.interval}s")
        print(f"Baseline: {self.is_first_run and 'New' or 'Loaded'}")
        print(f"First-run batching: {self.config.scan.first_run_batch_signals}")
        print(f"psutil: {'Available' if HAS_PSUTIL else 'Not available (using fallback)'}")
        print("=" * 50)

        # Set up first-run mode for signal batching
        if self.is_first_run and self.config.scan.first_run_batch_signals:
            SurfaceMonitor._first_run_mode = True
            SurfaceMonitor._first_run_batch_enabled = True
            SurfaceMonitor._first_run_counts.clear()
            print("[*] First run mode: signals will be batched into summaries")

        # Emit startup signal
        self.queue.push(Signal.create(
            signal_type=SignalTypes.PARSER_STARTED,
            source_surface="EdgeParser",
            trigger_reason="Parser started",
            artifacts={"interval": self.interval, "first_run": self.is_first_run}
        ))

        if self.is_first_run:
            self.queue.push(Signal.create(
                signal_type=SignalTypes.BASELINE_INITIALIZED,
                source_surface="EdgeParser",
                trigger_reason="First run - initializing baseline",
                artifacts={}
            ))

        self.running = True
        try:
            while self.running:
                self.run_once()
                print(f"[*] Sleeping {self.interval}s...")
                time.sleep(self.interval)
        except KeyboardInterrupt:
            print("\n[!] Parser stopped by user")
        finally:
            self.running = False
            self.baseline.save()


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Edge Parser - Local Surface Monitor")
    parser.add_argument("-i", "--interval", type=int, default=30,
                        help="Scan interval in seconds (default: 30)")
    parser.add_argument("--once", action="store_true",
                        help="Run once and exit")
    parser.add_argument("--list-logs", action="store_true",
                        help="List all monitored Windows Event Logs and exit")
    args = parser.parse_args()

    if args.list_logs:
        LogMonitor.list_monitored_logs()
        return

    edge = EdgeParser(interval=args.interval)

    if args.once:
        edge.run_once(standalone=True)
    else:
        edge.run()


if __name__ == "__main__":
    main()
