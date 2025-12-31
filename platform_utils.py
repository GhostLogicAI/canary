"""
CANARY PLATFORM UTILITIES

Cross-platform abstraction layer.
Detects OS and provides platform-specific implementations.
"""

import os
import sys
import platform
import subprocess
from abc import ABC, abstractmethod
from typing import List, Dict, Tuple, Optional, Set
from pathlib import Path


# Detect platform
PLATFORM = sys.platform  # 'win32', 'linux', 'darwin'
IS_WINDOWS = PLATFORM == 'win32'
IS_LINUX = PLATFORM == 'linux'
IS_MACOS = PLATFORM == 'darwin'

def get_platform_name() -> str:
    """Get human-readable platform name."""
    if IS_WINDOWS:
        return "Windows"
    elif IS_LINUX:
        return "Linux"
    elif IS_MACOS:
        return "macOS"
    return PLATFORM


# ============================================================
# Abstract Base Classes for Platform-Specific Operations
# ============================================================

class PlatformDrivers(ABC):
    """Abstract interface for kernel module/driver operations."""

    @abstractmethod
    def get_loaded_drivers(self) -> List[str]:
        """Get list of loaded kernel drivers/modules."""
        pass


class PlatformServices(ABC):
    """Abstract interface for service/daemon operations."""

    @abstractmethod
    def get_running_services(self) -> List[str]:
        """Get list of running services."""
        pass


class PlatformProcesses(ABC):
    """Abstract interface for process operations."""

    @abstractmethod
    def get_running_processes(self) -> List[str]:
        """Get list of running process names."""
        pass

    @abstractmethod
    def get_process_tree(self) -> List[Dict]:
        """Get process tree with parent info."""
        pass


class PlatformNetwork(ABC):
    """Abstract interface for network operations."""

    @abstractmethod
    def get_connections(self) -> Tuple[List[str], List[str], int]:
        """Get (outbound, listening, total_count) connections."""
        pass


class PlatformPersistence(ABC):
    """Abstract interface for persistence mechanism checks."""

    @abstractmethod
    def get_autorun_entries(self) -> List[str]:
        """Get startup/autorun entries."""
        pass

    @abstractmethod
    def get_scheduled_tasks(self) -> List[str]:
        """Get scheduled tasks/cron jobs."""
        pass


class PlatformDNS(ABC):
    """Abstract interface for DNS operations."""

    @abstractmethod
    def get_dns_cache(self) -> List[str]:
        """Get cached DNS domains."""
        pass


class PlatformFilesystem(ABC):
    """Abstract interface for filesystem monitoring."""

    @abstractmethod
    def get_sensitive_paths(self) -> List[Path]:
        """Get paths to monitor for changes."""
        pass


# ============================================================
# Windows Implementations
# ============================================================

class WindowsDrivers(PlatformDrivers):
    def get_loaded_drivers(self) -> List[str]:
        try:
            result = subprocess.run(
                ["driverquery", "/fo", "csv", "/v"],
                capture_output=True, text=True, timeout=30
            )
            drivers = []
            for line in result.stdout.strip().split('\n')[1:]:
                if line.strip():
                    parts = line.split(',')
                    if parts:
                        name = parts[0].strip('"')
                        drivers.append(name)
            return drivers
        except Exception:
            return []


class WindowsServices(PlatformServices):
    def get_running_services(self) -> List[str]:
        try:
            result = subprocess.run(
                ["sc", "query", "type=", "service", "state=", "all"],
                capture_output=True, text=True, timeout=30
            )
            services = []
            current_service = None
            for line in result.stdout.split('\n'):
                if line.startswith("SERVICE_NAME:"):
                    current_service = line.split(":", 1)[1].strip()
                elif "RUNNING" in line and current_service:
                    services.append(f"{current_service}:running")
                    current_service = None
            return services
        except Exception:
            return []


class WindowsProcesses(PlatformProcesses):
    def get_running_processes(self) -> List[str]:
        try:
            import psutil
            return list(set(p.name() for p in psutil.process_iter(['name'])))
        except ImportError:
            # Fallback to tasklist
            try:
                result = subprocess.run(
                    ["tasklist", "/fo", "csv", "/nh"],
                    capture_output=True, text=True, timeout=30
                )
                processes = set()
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        parts = line.split(',')
                        if parts:
                            name = parts[0].strip('"')
                            processes.add(name)
                return list(processes)
            except Exception:
                return []

    def get_process_tree(self) -> List[Dict]:
        processes = []
        try:
            import psutil
            for proc in psutil.process_iter(['pid', 'name', 'ppid', 'cmdline']):
                try:
                    info = proc.info
                    parent_name = ""
                    if info['ppid']:
                        try:
                            parent = psutil.Process(info['ppid'])
                            parent_name = parent.name()
                        except Exception:
                            pass
                    processes.append({
                        'name': info['name'],
                        'parent_name': parent_name,
                        'cmdline': ' '.join(info['cmdline'] or [])
                    })
                except Exception:
                    pass
        except ImportError:
            pass
        return processes


class WindowsNetwork(PlatformNetwork):
    def get_connections(self) -> Tuple[List[str], List[str], int]:
        outbound = []
        listening = []
        total = 0

        try:
            import psutil
            for conn in psutil.net_connections(kind='inet'):
                total += 1
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    outbound.append(f"{conn.raddr.ip}:{conn.raddr.port}")
                elif conn.status == 'LISTEN':
                    listening.append(f":{conn.laddr.port}")
        except ImportError:
            # Fallback to netstat
            try:
                result = subprocess.run(
                    ["netstat", "-an"],
                    capture_output=True, text=True, timeout=30
                )
                for line in result.stdout.split('\n'):
                    if 'ESTABLISHED' in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            outbound.append(parts[2])
                            total += 1
                    elif 'LISTENING' in line:
                        parts = line.split()
                        if len(parts) >= 2:
                            listening.append(parts[1])
                            total += 1
            except Exception:
                pass

        return outbound, listening, total


class WindowsPersistence(PlatformPersistence):
    RUN_KEYS = [
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    ]

    def get_autorun_entries(self) -> List[str]:
        entries = []
        for key in self.RUN_KEYS:
            try:
                result = subprocess.run(
                    ["reg", "query", key],
                    capture_output=True, text=True, timeout=10
                )
                for line in result.stdout.split('\n'):
                    if 'REG_SZ' in line or 'REG_EXPAND_SZ' in line:
                        entries.append(line.strip())
            except Exception:
                pass
        return entries

    def get_scheduled_tasks(self) -> List[str]:
        try:
            result = subprocess.run(
                ["schtasks", "/query", "/fo", "csv", "/nh"],
                capture_output=True, text=True, timeout=30
            )
            tasks = []
            for line in result.stdout.strip().split('\n'):
                if line.strip() and not line.startswith('"TaskName"'):
                    parts = line.split(',')
                    if parts:
                        task = parts[0].strip('"')
                        if task and not task.startswith('\\Microsoft'):
                            tasks.append(task)
            return tasks
        except Exception:
            return []


class WindowsDNS(PlatformDNS):
    def get_dns_cache(self) -> List[str]:
        domains = set()
        try:
            result = subprocess.run(
                ["ipconfig", "/displaydns"],
                capture_output=True, text=True, timeout=30
            )
            for line in result.stdout.split('\n'):
                if 'Record Name' in line:
                    parts = line.split(':')
                    if len(parts) >= 2:
                        domain = parts[1].strip().lower()
                        if domain and '.' in domain:
                            domains.add(domain)
        except Exception:
            pass
        return list(domains)


class WindowsFilesystem(PlatformFilesystem):
    def get_sensitive_paths(self) -> List[Path]:
        paths = [
            Path(r"C:\Windows\System32"),
            Path(r"C:\Windows\Temp"),
        ]

        # Add user-specific paths
        user_profile = os.environ.get('USERPROFILE', '')
        if user_profile:
            paths.extend([
                Path(user_profile) / "Downloads",
                Path(user_profile) / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup",
                Path(user_profile) / "AppData" / "Local" / "Temp",
            ])

        return [p for p in paths if p.exists()]


# ============================================================
# Linux Implementations
# ============================================================

class LinuxDrivers(PlatformDrivers):
    def get_loaded_drivers(self) -> List[str]:
        """Get loaded kernel modules from /proc/modules."""
        modules = []
        try:
            with open('/proc/modules', 'r') as f:
                for line in f:
                    parts = line.split()
                    if parts:
                        modules.append(parts[0])
        except Exception:
            pass
        return modules


class LinuxServices(PlatformServices):
    def get_running_services(self) -> List[str]:
        """Get running systemd services."""
        services = []
        try:
            result = subprocess.run(
                ["systemctl", "list-units", "--type=service", "--state=running", "--no-pager", "--plain"],
                capture_output=True, text=True, timeout=30
            )
            for line in result.stdout.split('\n'):
                parts = line.split()
                if parts and parts[0].endswith('.service'):
                    services.append(f"{parts[0]}:running")
        except Exception:
            pass
        return services


class LinuxProcesses(PlatformProcesses):
    def get_running_processes(self) -> List[str]:
        try:
            import psutil
            return list(set(p.name() for p in psutil.process_iter(['name'])))
        except ImportError:
            # Fallback to ps
            try:
                result = subprocess.run(
                    ["ps", "-e", "-o", "comm="],
                    capture_output=True, text=True, timeout=30
                )
                return list(set(result.stdout.strip().split('\n')))
            except Exception:
                return []

    def get_process_tree(self) -> List[Dict]:
        processes = []
        try:
            import psutil
            for proc in psutil.process_iter(['pid', 'name', 'ppid', 'cmdline']):
                try:
                    info = proc.info
                    parent_name = ""
                    if info['ppid']:
                        try:
                            parent = psutil.Process(info['ppid'])
                            parent_name = parent.name()
                        except Exception:
                            pass
                    processes.append({
                        'name': info['name'],
                        'parent_name': parent_name,
                        'cmdline': ' '.join(info['cmdline'] or [])
                    })
                except Exception:
                    pass
        except ImportError:
            pass
        return processes


class LinuxNetwork(PlatformNetwork):
    def get_connections(self) -> Tuple[List[str], List[str], int]:
        outbound = []
        listening = []
        total = 0

        try:
            import psutil
            for conn in psutil.net_connections(kind='inet'):
                total += 1
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    outbound.append(f"{conn.raddr.ip}:{conn.raddr.port}")
                elif conn.status == 'LISTEN':
                    listening.append(f":{conn.laddr.port}")
        except ImportError:
            # Fallback to ss
            try:
                result = subprocess.run(
                    ["ss", "-tunap"],
                    capture_output=True, text=True, timeout=30
                )
                for line in result.stdout.split('\n'):
                    if 'ESTAB' in line:
                        parts = line.split()
                        if len(parts) >= 5:
                            outbound.append(parts[4])
                            total += 1
                    elif 'LISTEN' in line:
                        parts = line.split()
                        if len(parts) >= 4:
                            listening.append(parts[3])
                            total += 1
            except Exception:
                pass

        return outbound, listening, total


class LinuxPersistence(PlatformPersistence):
    def get_autorun_entries(self) -> List[str]:
        """Check common Linux autostart locations."""
        entries = []

        # Check user autostart
        autostart_dirs = [
            Path.home() / ".config" / "autostart",
            Path("/etc/xdg/autostart"),
        ]

        for autostart in autostart_dirs:
            if autostart.exists():
                for f in autostart.glob("*.desktop"):
                    entries.append(str(f))

        # Check rc.local
        rc_local = Path("/etc/rc.local")
        if rc_local.exists():
            entries.append(str(rc_local))

        # Check init.d
        init_d = Path("/etc/init.d")
        if init_d.exists():
            for f in init_d.iterdir():
                if f.is_file() and os.access(f, os.X_OK):
                    entries.append(str(f))

        return entries

    def get_scheduled_tasks(self) -> List[str]:
        """Get cron jobs."""
        tasks = []

        # System cron directories
        cron_dirs = [
            Path("/etc/cron.d"),
            Path("/etc/cron.daily"),
            Path("/etc/cron.hourly"),
            Path("/etc/cron.weekly"),
            Path("/etc/cron.monthly"),
        ]

        for cron_dir in cron_dirs:
            if cron_dir.exists():
                for f in cron_dir.iterdir():
                    if f.is_file():
                        tasks.append(str(f))

        # User crontab
        try:
            result = subprocess.run(
                ["crontab", "-l"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if line.strip() and not line.startswith('#'):
                        tasks.append(f"user_cron:{line.strip()[:50]}")
        except Exception:
            pass

        return tasks


class LinuxDNS(PlatformDNS):
    def get_dns_cache(self) -> List[str]:
        """Try to get DNS cache from systemd-resolved or read /etc/hosts."""
        domains = set()

        # Try systemd-resolved
        try:
            result = subprocess.run(
                ["resolvectl", "statistics"],
                capture_output=True, text=True, timeout=10
            )
            # Note: resolvectl doesn't actually dump cached domains easily
            # This is a limitation on Linux
        except Exception:
            pass

        # Read /etc/hosts as fallback
        try:
            with open('/etc/hosts', 'r') as f:
                for line in f:
                    if not line.startswith('#') and line.strip():
                        parts = line.split()
                        for part in parts[1:]:
                            if '.' in part:
                                domains.add(part.lower())
        except Exception:
            pass

        return list(domains)


class LinuxFilesystem(PlatformFilesystem):
    def get_sensitive_paths(self) -> List[Path]:
        paths = [
            Path("/usr/bin"),
            Path("/usr/sbin"),
            Path("/usr/local/bin"),
            Path("/tmp"),
            Path("/var/tmp"),
            Path.home() / ".local" / "bin",
            Path.home() / "Downloads",
        ]
        return [p for p in paths if p.exists()]


# ============================================================
# macOS Implementations (similar to Linux with some differences)
# ============================================================

class MacOSDrivers(PlatformDrivers):
    def get_loaded_drivers(self) -> List[str]:
        """Get loaded kernel extensions."""
        modules = []
        try:
            result = subprocess.run(
                ["kextstat"],
                capture_output=True, text=True, timeout=30
            )
            for line in result.stdout.split('\n')[1:]:
                parts = line.split()
                if len(parts) >= 6:
                    modules.append(parts[5])
        except Exception:
            pass
        return modules


class MacOSServices(PlatformServices):
    def get_running_services(self) -> List[str]:
        """Get running launchd services."""
        services = []
        try:
            result = subprocess.run(
                ["launchctl", "list"],
                capture_output=True, text=True, timeout=30
            )
            for line in result.stdout.split('\n')[1:]:
                parts = line.split('\t')
                if len(parts) >= 3 and parts[0] != '-':
                    services.append(f"{parts[2]}:running")
        except Exception:
            pass
        return services


# Use Linux implementations for processes and network (psutil works on both)
MacOSProcesses = LinuxProcesses
MacOSNetwork = LinuxNetwork


class MacOSPersistence(PlatformPersistence):
    def get_autorun_entries(self) -> List[str]:
        """Check macOS LaunchAgents/Daemons."""
        entries = []

        launch_dirs = [
            Path.home() / "Library" / "LaunchAgents",
            Path("/Library/LaunchAgents"),
            Path("/Library/LaunchDaemons"),
            Path("/System/Library/LaunchAgents"),
            Path("/System/Library/LaunchDaemons"),
        ]

        for launch_dir in launch_dirs:
            if launch_dir.exists():
                for f in launch_dir.glob("*.plist"):
                    entries.append(str(f))

        return entries

    def get_scheduled_tasks(self) -> List[str]:
        """macOS uses launchd, not cron typically."""
        # Same as autorun for macOS
        return self.get_autorun_entries()


class MacOSDNS(PlatformDNS):
    def get_dns_cache(self) -> List[str]:
        """Try to get DNS cache from mDNSResponder."""
        domains = set()
        try:
            # Note: macOS doesn't easily expose DNS cache
            # Could use: sudo killall -INFO mDNSResponder and check syslog
            # For now, return empty
            pass
        except Exception:
            pass
        return list(domains)


MacOSFilesystem = LinuxFilesystem


# ============================================================
# Factory Functions
# ============================================================

def get_drivers_impl() -> PlatformDrivers:
    if IS_WINDOWS:
        return WindowsDrivers()
    elif IS_LINUX:
        return LinuxDrivers()
    elif IS_MACOS:
        return MacOSDrivers()
    raise NotImplementedError(f"Platform {PLATFORM} not supported")


def get_services_impl() -> PlatformServices:
    if IS_WINDOWS:
        return WindowsServices()
    elif IS_LINUX:
        return LinuxServices()
    elif IS_MACOS:
        return MacOSServices()
    raise NotImplementedError(f"Platform {PLATFORM} not supported")


def get_processes_impl() -> PlatformProcesses:
    if IS_WINDOWS:
        return WindowsProcesses()
    elif IS_LINUX:
        return LinuxProcesses()
    elif IS_MACOS:
        return MacOSProcesses()
    raise NotImplementedError(f"Platform {PLATFORM} not supported")


def get_network_impl() -> PlatformNetwork:
    if IS_WINDOWS:
        return WindowsNetwork()
    elif IS_LINUX:
        return LinuxNetwork()
    elif IS_MACOS:
        return MacOSNetwork()
    raise NotImplementedError(f"Platform {PLATFORM} not supported")


def get_persistence_impl() -> PlatformPersistence:
    if IS_WINDOWS:
        return WindowsPersistence()
    elif IS_LINUX:
        return LinuxPersistence()
    elif IS_MACOS:
        return MacOSPersistence()
    raise NotImplementedError(f"Platform {PLATFORM} not supported")


def get_dns_impl() -> PlatformDNS:
    if IS_WINDOWS:
        return WindowsDNS()
    elif IS_LINUX:
        return LinuxDNS()
    elif IS_MACOS:
        return MacOSDNS()
    raise NotImplementedError(f"Platform {PLATFORM} not supported")


def get_filesystem_impl() -> PlatformFilesystem:
    if IS_WINDOWS:
        return WindowsFilesystem()
    elif IS_LINUX:
        return LinuxFilesystem()
    elif IS_MACOS:
        return MacOSFilesystem()
    raise NotImplementedError(f"Platform {PLATFORM} not supported")


# ============================================================
# UI Transparency Support
# ============================================================

def supports_transparent_windows() -> bool:
    """Check if platform supports transparent windows."""
    return IS_WINDOWS  # macOS/Linux need different approaches


def configure_transparent_window(window):
    """Configure window transparency for the platform."""
    if IS_WINDOWS:
        # Windows uses color keying
        TRANSPARENT_COLOR = '#010101'
        window.configure(bg=TRANSPARENT_COLOR)
        window.attributes('-transparentcolor', TRANSPARENT_COLOR)
        return TRANSPARENT_COLOR
    elif IS_MACOS:
        # macOS uses alpha
        window.attributes('-alpha', 0.95)
        return None
    else:
        # Linux - depends on compositor
        try:
            window.attributes('-alpha', 0.95)
        except Exception:
            pass
        return None


if __name__ == "__main__":
    print(f"Platform: {get_platform_name()}")
    print(f"Transparent windows: {supports_transparent_windows()}")

    print("\n--- Testing Drivers ---")
    drivers = get_drivers_impl()
    loaded = drivers.get_loaded_drivers()
    print(f"Loaded drivers/modules: {len(loaded)}")
    if loaded:
        print(f"  Examples: {loaded[:3]}")

    print("\n--- Testing Services ---")
    services = get_services_impl()
    running = services.get_running_services()
    print(f"Running services: {len(running)}")
    if running:
        print(f"  Examples: {running[:3]}")

    print("\n--- Testing Processes ---")
    procs = get_processes_impl()
    names = procs.get_running_processes()
    print(f"Running processes: {len(names)}")

    print("\n--- Testing Network ---")
    net = get_network_impl()
    outbound, listening, total = net.get_connections()
    print(f"Connections: {total} total, {len(outbound)} outbound, {len(listening)} listening")

    print("\n--- Testing Persistence ---")
    persist = get_persistence_impl()
    autoruns = persist.get_autorun_entries()
    tasks = persist.get_scheduled_tasks()
    print(f"Autoruns: {len(autoruns)}, Scheduled: {len(tasks)}")

    print("\n--- Testing DNS ---")
    dns = get_dns_impl()
    domains = dns.get_dns_cache()
    print(f"DNS cache: {len(domains)} domains")

    print("\n--- Testing Filesystem ---")
    fs = get_filesystem_impl()
    paths = fs.get_sensitive_paths()
    print(f"Sensitive paths: {[str(p) for p in paths]}")
