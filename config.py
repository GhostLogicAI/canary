"""
CANARY CONFIGURATION SYSTEM

Centralized configuration with YAML file support.
All tunables in one place.
"""

import os
import yaml
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional

CANARY_DIR = Path(__file__).parent
CONFIG_FILE = CANARY_DIR / "config.yaml"


@dataclass
class ScanConfig:
    """Scan timing configuration."""
    interval_seconds: int = 30
    parallel_workers: int = 4
    first_run_batch_signals: bool = True  # Batch first-run signals


@dataclass
class BaselineConfig:
    """Baseline behavior configuration."""
    aging_days: int = 30              # Remove items not seen in N days
    frequency_tracking: bool = True    # Track occurrence counts
    time_of_day_awareness: bool = True # Weight by hour
    anomaly_threshold: float = 3.0     # Std deviations for anomaly


@dataclass
class NetworkConfig:
    """Network monitoring configuration."""
    spike_multiplier: float = 3.0      # Current > avg * N = spike
    min_baseline_samples: int = 5      # Samples before spike detection
    history_size: int = 20             # Rolling history length
    beaconing_min_connections: int = 3 # Connections to detect beaconing
    beaconing_jitter_tolerance: float = 0.1  # 10% variance allowed


@dataclass
class ProcessConfig:
    """Process monitoring configuration."""
    track_command_lines: bool = True
    suspicious_parents: List[str] = field(default_factory=lambda: [
        "WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE",  # Office
        "chrome.exe", "firefox.exe", "msedge.exe",   # Browsers
        "outlook.exe",                                # Email
    ])
    suspicious_children: List[str] = field(default_factory=lambda: [
        "cmd.exe", "powershell.exe", "pwsh.exe",
        "wscript.exe", "cscript.exe", "mshta.exe",
        "regsvr32.exe", "rundll32.exe",
    ])


@dataclass
class FileSystemConfig:
    """File system monitoring configuration."""
    watch_paths: List[str] = field(default_factory=lambda: [
        r"C:\Windows\System32",
        r"C:\Windows\Temp",
    ])
    watch_extensions: List[str] = field(default_factory=lambda: [
        ".exe", ".dll", ".sys", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js"
    ])
    include_user_paths: bool = True  # Auto-add Downloads, Startup, AppData


@dataclass
class DNSConfig:
    """DNS monitoring configuration."""
    suspicious_tlds: List[str] = field(default_factory=lambda: [
        ".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq",
        ".pw", ".cc", ".su", ".onion"
    ])
    dga_entropy_threshold: float = 3.5  # Shannon entropy for randomness


@dataclass
class AlertConfig:
    """Alert behavior configuration."""
    sound_enabled: bool = True
    sound_file: Optional[str] = None  # None = system beep
    snooze_duration_hours: int = 24
    max_bubbles: int = 5
    bubble_duration_ms: int = 8000


@dataclass
class UIConfig:
    """UI configuration."""
    system_tray_mode: bool = False
    start_minimized: bool = False
    notification_center_max_items: int = 500
    dark_theme: bool = True
    # Color mode: "binary" (red/green only) or "gradient" (4 severity colors)
    color_mode: str = "gradient"


@dataclass
class WatchdogConfig:
    """Watchdog configuration."""
    enabled: bool = True
    check_interval_seconds: int = 30
    restart_on_failure: bool = True
    remote_heartbeat_url: Optional[str] = None
    heartbeat_interval_minutes: int = 5


@dataclass
class CanaryConfig:
    """Master configuration."""
    scan: ScanConfig = field(default_factory=ScanConfig)
    baseline: BaselineConfig = field(default_factory=BaselineConfig)
    network: NetworkConfig = field(default_factory=NetworkConfig)
    process: ProcessConfig = field(default_factory=ProcessConfig)
    filesystem: FileSystemConfig = field(default_factory=FileSystemConfig)
    dns: DNSConfig = field(default_factory=DNSConfig)
    alert: AlertConfig = field(default_factory=AlertConfig)
    ui: UIConfig = field(default_factory=UIConfig)
    watchdog: WatchdogConfig = field(default_factory=WatchdogConfig)

    def save(self, path: Path = None):
        """Save configuration to YAML file."""
        path = path or CONFIG_FILE
        data = self._to_dict()
        with open(path, 'w') as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)

    def _to_dict(self) -> dict:
        """Convert to dictionary for YAML."""
        return {
            'scan': asdict(self.scan),
            'baseline': asdict(self.baseline),
            'network': asdict(self.network),
            'process': asdict(self.process),
            'filesystem': asdict(self.filesystem),
            'dns': asdict(self.dns),
            'alert': asdict(self.alert),
            'ui': asdict(self.ui),
            'watchdog': asdict(self.watchdog),
        }

    @classmethod
    def load(cls, path: Path = None) -> 'CanaryConfig':
        """Load configuration from YAML file."""
        path = path or CONFIG_FILE

        if not path.exists():
            # Create default config
            config = cls()
            config.save(path)
            return config

        with open(path, 'r') as f:
            data = yaml.safe_load(f) or {}

        return cls._from_dict(data)

    @classmethod
    def _from_dict(cls, data: dict) -> 'CanaryConfig':
        """Create config from dictionary."""
        return cls(
            scan=ScanConfig(**data.get('scan', {})),
            baseline=BaselineConfig(**data.get('baseline', {})),
            network=NetworkConfig(**data.get('network', {})),
            process=ProcessConfig(**data.get('process', {})),
            filesystem=FileSystemConfig(**data.get('filesystem', {})),
            dns=DNSConfig(**data.get('dns', {})),
            alert=AlertConfig(**data.get('alert', {})),
            ui=UIConfig(**data.get('ui', {})),
            watchdog=WatchdogConfig(**data.get('watchdog', {})),
        )


# Global config instance
_config: Optional[CanaryConfig] = None


def get_config() -> CanaryConfig:
    """Get the global configuration instance."""
    global _config
    if _config is None:
        _config = CanaryConfig.load()
    return _config


def reload_config():
    """Reload configuration from file."""
    global _config
    _config = CanaryConfig.load()
    return _config


def save_config():
    """Save current configuration to file."""
    global _config
    if _config:
        _config.save()


if __name__ == "__main__":
    # Generate default config file
    config = CanaryConfig()
    config.save()
    print(f"Default config saved to: {CONFIG_FILE}")
    print(yaml.dump(config._to_dict(), default_flow_style=False))
