"""
CANARY DAEMON - Startup service manager for the canary system.

Installs/uninstalls the canary to run at Windows startup via Task Scheduler.
Runs both the edge parser and canary UI as background processes.
Monitors health and restarts components if they die.
"""

import subprocess
import sys
import os
import time
import signal
import atexit
import json
from pathlib import Path
from datetime import datetime
import ctypes

# Paths
CANARY_DIR = Path(__file__).parent
PID_FILE = CANARY_DIR / ".canary_daemon.pid"
LOG_FILE = CANARY_DIR / "daemon.log"
TASK_NAME = "CanaryAlertSystem"


def is_admin():
    """Check if running with admin privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False


def log(msg: str):
    """Write to daemon log."""
    ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    line = f"[{ts}] {msg}"
    print(line)
    try:
        with open(LOG_FILE, 'a') as f:
            f.write(line + '\n')
    except Exception:
        pass


def get_python_path():
    """Get path to pythonw.exe for background execution."""
    python_dir = Path(sys.executable).parent
    pythonw = python_dir / "pythonw.exe"
    if pythonw.exists():
        return str(pythonw)
    return sys.executable


def install_startup():
    """Install canary to run at Windows startup via Task Scheduler."""
    if not is_admin():
        print("[!] Admin privileges required to install startup task.")
        print("    Right-click and 'Run as administrator'")
        return False

    python_path = get_python_path()
    daemon_path = str(CANARY_DIR / "canary_daemon.py")

    # Create scheduled task XML
    task_xml = f'''<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Canary Alert System - Desktop security monitor</Description>
    <Author>Canary</Author>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <DisallowStartOnRemoteAppSession>false</DisallowStartOnRemoteAppSession>
    <UseUnifiedSchedulingEngine>true</UseUnifiedSchedulingEngine>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
    <RestartOnFailure>
      <Interval>PT1M</Interval>
      <Count>3</Count>
    </RestartOnFailure>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>"{python_path}"</Command>
      <Arguments>"{daemon_path}" run</Arguments>
      <WorkingDirectory>{CANARY_DIR}</WorkingDirectory>
    </Exec>
  </Actions>
</Task>'''

    # Write task XML
    task_file = CANARY_DIR / ".canary_task.xml"
    with open(task_file, 'w', encoding='utf-16') as f:
        f.write(task_xml)

    # Delete existing task if present
    subprocess.run(
        ["schtasks", "/delete", "/tn", TASK_NAME, "/f"],
        capture_output=True
    )

    # Create new task
    result = subprocess.run(
        ["schtasks", "/create", "/tn", TASK_NAME, "/xml", str(task_file)],
        capture_output=True, text=True
    )

    # Clean up XML file
    task_file.unlink(missing_ok=True)

    if result.returncode == 0:
        print(f"[+] Installed startup task: {TASK_NAME}")
        print(f"    Canary will start automatically at login.")
        return True
    else:
        print(f"[!] Failed to install: {result.stderr}")
        return False


def uninstall_startup():
    """Remove canary from Windows startup."""
    if not is_admin():
        print("[!] Admin privileges required to uninstall startup task.")
        return False

    result = subprocess.run(
        ["schtasks", "/delete", "/tn", TASK_NAME, "/f"],
        capture_output=True, text=True
    )

    if result.returncode == 0:
        print(f"[+] Removed startup task: {TASK_NAME}")
        return True
    else:
        print(f"[!] Task not found or failed to remove: {result.stderr}")
        return False


def check_status():
    """Check if canary daemon is running."""
    # Check scheduled task
    result = subprocess.run(
        ["schtasks", "/query", "/tn", TASK_NAME],
        capture_output=True, text=True
    )
    task_installed = result.returncode == 0

    # Check PID file
    daemon_running = False
    if PID_FILE.exists():
        try:
            with open(PID_FILE) as f:
                data = json.load(f)
            daemon_pid = data.get('daemon_pid')
            if daemon_pid:
                # Check if process exists
                result = subprocess.run(
                    ["tasklist", "/fi", f"PID eq {daemon_pid}"],
                    capture_output=True, text=True
                )
                daemon_running = str(daemon_pid) in result.stdout
        except Exception:
            pass

    print("Canary Status:")
    print(f"  Startup task installed: {'Yes' if task_installed else 'No'}")
    print(f"  Daemon running: {'Yes' if daemon_running else 'No'}")

    if daemon_running:
        try:
            with open(PID_FILE) as f:
                data = json.load(f)
            print(f"  Parser PID: {data.get('parser_pid', 'N/A')}")
            print(f"  UI PID: {data.get('ui_pid', 'N/A')}")
            print(f"  Started: {data.get('started', 'N/A')}")
        except Exception:
            pass


def stop_daemon():
    """Stop the running daemon and its children."""
    if not PID_FILE.exists():
        print("[*] No daemon PID file found.")
        return

    try:
        with open(PID_FILE) as f:
            data = json.load(f)

        for key in ['parser_pid', 'ui_pid', 'daemon_pid']:
            pid = data.get(key)
            if pid:
                try:
                    subprocess.run(
                        ["taskkill", "/pid", str(pid), "/f"],
                        capture_output=True
                    )
                    print(f"[+] Stopped {key}: {pid}")
                except Exception:
                    pass

        PID_FILE.unlink(missing_ok=True)
        print("[+] Daemon stopped.")
    except Exception as e:
        print(f"[!] Error stopping daemon: {e}")


class CanaryDaemon:
    """
    Daemon that runs and monitors both parser and UI.
    Restarts components if they crash.
    """

    def __init__(self):
        self.parser_proc = None
        self.ui_proc = None
        self.running = False

    def start_parser(self):
        """Start the edge parser process."""
        log("Starting edge parser...")
        try:
            self.parser_proc = subprocess.Popen(
                [sys.executable, str(CANARY_DIR / "edge_parser.py")],
                cwd=str(CANARY_DIR),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            log(f"Parser started: PID {self.parser_proc.pid}")
            return True
        except Exception as e:
            log(f"Failed to start parser: {e}")
            return False

    def start_ui(self):
        """Start the canary UI process."""
        log("Starting canary UI...")
        try:
            pythonw = get_python_path()
            self.ui_proc = subprocess.Popen(
                [pythonw, str(CANARY_DIR / "canary_ui.py")],
                cwd=str(CANARY_DIR),
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            log(f"UI started: PID {self.ui_proc.pid}")
            return True
        except Exception as e:
            log(f"Failed to start UI: {e}")
            return False

    def write_pid_file(self):
        """Write PID file for status checking."""
        data = {
            'daemon_pid': os.getpid(),
            'parser_pid': self.parser_proc.pid if self.parser_proc else None,
            'ui_pid': self.ui_proc.pid if self.ui_proc else None,
            'started': datetime.now().isoformat()
        }
        with open(PID_FILE, 'w') as f:
            json.dump(data, f)

    def cleanup(self):
        """Clean up on exit."""
        log("Daemon shutting down...")
        if self.parser_proc:
            self.parser_proc.terminate()
        if self.ui_proc:
            self.ui_proc.terminate()
        PID_FILE.unlink(missing_ok=True)

    def run(self):
        """Main daemon loop."""
        log("=" * 50)
        log("CANARY DAEMON STARTING")
        log("=" * 50)

        # Register cleanup
        atexit.register(self.cleanup)

        # Start components
        self.start_parser()
        time.sleep(2)  # Let parser initialize
        self.start_ui()

        self.write_pid_file()
        self.running = True

        log("Daemon running. Monitoring components...")

        # Monitor loop
        check_interval = 30  # seconds
        while self.running:
            try:
                time.sleep(check_interval)

                # Check parser
                if self.parser_proc and self.parser_proc.poll() is not None:
                    log(f"Parser died (exit code {self.parser_proc.returncode}). Restarting...")
                    self.start_parser()
                    self.write_pid_file()

                # Check UI
                if self.ui_proc and self.ui_proc.poll() is not None:
                    log(f"UI died (exit code {self.ui_proc.returncode}). Restarting...")
                    self.start_ui()
                    self.write_pid_file()

            except KeyboardInterrupt:
                log("Interrupted by user.")
                self.running = False
            except Exception as e:
                log(f"Monitor error: {e}")

        self.cleanup()


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Canary Daemon - Startup service manager",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Commands:
  install     Install canary to run at Windows startup (requires admin)
  uninstall   Remove canary from Windows startup (requires admin)
  run         Start the daemon (runs parser + UI, monitors health)
  stop        Stop the running daemon
  status      Check if canary is installed/running

Examples:
  python canary_daemon.py install    # Add to startup (run as admin)
  python canary_daemon.py run        # Start now
  python canary_daemon.py status     # Check status
        """
    )
    parser.add_argument("command", choices=["install", "uninstall", "run", "stop", "status"],
                        help="Command to execute")
    args = parser.parse_args()

    if args.command == "install":
        install_startup()
    elif args.command == "uninstall":
        uninstall_startup()
    elif args.command == "run":
        daemon = CanaryDaemon()
        daemon.run()
    elif args.command == "stop":
        stop_daemon()
    elif args.command == "status":
        check_status()


if __name__ == "__main__":
    main()
