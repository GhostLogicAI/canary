# Canary Alert System

A loud, visible desktop canary. Not an EDR. Not a blocker. Just a watcher that talks.

## Components

### Edge Parser (`edge_parser.py`)
Fast, aggressive local parser for system surfaces. Disposable. Non-canonical.

**What it monitors:**
- Kernel drivers (driverquery)
- Windows services (Get-Service)
- Running processes (psutil/tasklist)
- Network connections (outbound + listening)
- Registry autoruns (Run/RunOnce keys)
- Scheduled tasks
- Windows Event Logs (see below)

**What it does:**
- Builds a baseline on first run
- Compares current state to baseline
- Emits mechanical signals when things change
- No inference. No correlation. No judgment.

**Signals emitted:**
```
new_kernel_driver_loaded
baseline_driver_missing
new_service_appeared
baseline_service_missing
new_process_name_observed
new_outbound_destination
new_listening_port
new_autorun_entry
autorun_entry_removed
new_scheduled_task
scheduled_task_removed
log_gap_detected
log_cleared
```

### Canary UI (`canary_ui.py`)
A visible desktop mascot that speaks in word bubbles.

**What it does:**
- Subscribes to signals from the parser
- Translates signals to plain English
- Pops speech bubbles on the desktop
- Never decides, judges, or blocks
- Only speaks facts

**Tone:** Dry, slightly sarcastic, factual.

**Example messages:**
- "A new kernel driver just showed up. That wasn't here before."
- "This machine just talked to a new place on the internet."
- "I stopped hearing logs for a bit. That's unusual."

### Daemon (`canary_daemon.py`)
Startup service manager. Installs canary to run at Windows login.

**Commands:**
```
python canary_daemon.py install    # Add to Windows startup (requires admin)
python canary_daemon.py uninstall  # Remove from startup (requires admin)
python canary_daemon.py run        # Run daemon (starts parser + UI)
python canary_daemon.py stop       # Stop running daemon
python canary_daemon.py status     # Check if running/installed
```

## Windows Event Logs Monitored

Run `python edge_parser.py --list-logs` to see all monitored logs.

### Security Logs
| Log | Description |
|-----|-------------|
| Security | Main security audit log |
| - Event 1102 | Log cleared |
| - Event 4624 | Successful logon |
| - Event 4625 | Failed logon |
| - Event 4648 | Explicit credential logon |
| - Event 4672 | Special privileges assigned |
| - Event 4688 | New process created |
| - Event 4697 | Service installed |
| - Event 4698 | Scheduled task created |
| - Event 4720 | User account created |
| - Event 4732 | Member added to security group |

### System Logs
| Log | Description |
|-----|-------------|
| System | Core Windows system events |
| - Event 7045 | New service installed |
| - Event 7040 | Service start type changed |
| - Event 104 | Log cleared |

### PowerShell Logs
| Log | Description |
|-----|-------------|
| Microsoft-Windows-PowerShell/Operational | Script block logging |
| - Event 4104 | Code execution |
| - Event 4103 | Module logging |
| Windows PowerShell | Legacy PowerShell log |
| - Event 400 | Engine started |
| - Event 800 | Pipeline execution |

### Sysmon Logs (if installed)
| Log | Description |
|-----|-------------|
| Microsoft-Windows-Sysmon/Operational | Process/network monitoring |
| - Event 1 | Process creation |
| - Event 3 | Network connection |
| - Event 7 | Image loaded |
| - Event 11 | File created |
| - Event 13 | Registry value set |
| - Event 22 | DNS query |

### Defender Logs
| Log | Description |
|-----|-------------|
| Microsoft-Windows-Windows Defender/Operational | Defender events |
| - Event 1116 | Malware detected |
| - Event 1117 | Action taken |
| - Event 5001 | Real-time protection disabled |

### Task Scheduler Logs
| Log | Description |
|-----|-------------|
| Microsoft-Windows-TaskScheduler/Operational | Task events |
| - Event 106 | Task registered |
| - Event 140 | Task updated |
| - Event 141 | Task deleted |

### RDP / Terminal Services
| Log | Description |
|-----|-------------|
| Microsoft-Windows-TerminalServices-LocalSessionManager/Operational | RDP sessions |
| - Event 21 | Session logon succeeded |
| - Event 24 | Session disconnected |
| - Event 25 | Session reconnected |

### WMI Logs
| Log | Description |
|-----|-------------|
| Microsoft-Windows-WMI-Activity/Operational | WMI activity |
| - Event 5857 | WMI provider started |
| - Event 5858 | WMI query executed |
| - Event 5861 | WMI subscription created |

### BITS (Background Intelligent Transfer)
| Log | Description |
|-----|-------------|
| Microsoft-Windows-Bits-Client/Operational | File transfers |
| - Event 59 | BITS job started |
| - Event 60 | BITS job completed |

### Firewall
| Log | Description |
|-----|-------------|
| Microsoft-Windows-Windows Firewall With Advanced Security/Firewall | Firewall changes |
| - Event 2004 | Rule added |
| - Event 2005 | Rule modified |
| - Event 2006 | Rule deleted |

### Application Logs
| Log | Description |
|-----|-------------|
| Application | Application events |
| - Event 1000 | Application crash |
| - Event 1001 | Windows Error Reporting |

## Signal Flow

```
┌─────────────────────┐
│    SYSTEM STATE     │
│  drivers, services  │
│ processes, network  │
│ autoruns, tasks     │
│   event logs        │
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│    EDGE PARSER      │
│                     │
│  scan surfaces      │
│  compare baseline   │
│  emit signals       │
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│   signals.json      │  ◄── file-based queue
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│    CANARY UI        │
│                     │
│  poll queue         │
│  translate signal   │
│  show bubble        │
└─────────────────────┘
```

## Files

```
canary/
├── shared.py              # Signal definitions, queue, baseline
├── edge_parser.py         # Surface monitors
├── canary_ui.py           # Desktop mascot
├── canary_daemon.py       # Startup service manager
├── baseline.json          # Created at runtime
├── signals.json           # Signal queue
├── daemon.log             # Daemon log (when running)
├── run_parser.bat         # Launch parser
├── run_canary.bat         # Launch canary UI
├── run_both.bat           # Launch both
├── install_startup.bat    # Install to Windows startup (admin)
├── uninstall_startup.bat  # Remove from startup (admin)
└── *.png                  # Mascot image
```

## Usage

### Install dependencies
```
pip install psutil filelock pillow
```

`psutil` and `pillow` are optional but recommended. Falls back to slower methods without them.

### Quick start
```
run_both.bat
```

### Install to run at startup
```
# Right-click and "Run as administrator"
install_startup.bat
```

### Run manually
```
# Terminal 1: Parser (keep visible to see what it finds)
python edge_parser.py

# Terminal 2: Canary UI
python canary_ui.py
```

### Command line options

**Parser:**
```
python edge_parser.py --interval 30    # Scan every 30 seconds (default)
python edge_parser.py --interval 10    # Faster scanning
python edge_parser.py --once           # Single scan and exit
python edge_parser.py --list-logs      # List all monitored event logs
```

**Canary:**
```
python canary_ui.py --test             # Show test bubble
```

**Daemon:**
```
python canary_daemon.py install        # Add to Windows startup
python canary_daemon.py uninstall      # Remove from startup
python canary_daemon.py run            # Start daemon
python canary_daemon.py stop           # Stop daemon
python canary_daemon.py status         # Check status
```

## Failure & Tamper

If the canary UI crashes or is killed, it emits a final signal:
```
canary_silenced
```

And attempts to show one last bubble:
> "I'm having trouble staying alive."

The daemon monitors both parser and UI. If either dies, it restarts them automatically.

Silence is a signal.

## Design Principles

1. **No inference** - Parser only detects changes, never interprets them
2. **No correlation** - Each surface is independent
3. **No blocking** - Canary observes, never prevents
4. **Local only** - Everything stays on this machine
5. **Expendable** - Raw logs exist elsewhere, these files can be deleted
6. **Visible** - Canary is always on screen, not hidden
7. **Loud** - Every signal gets a bubble
8. **Factual** - Dry tone, no alarm, no "attack" language

## Not an EDR

This is a canary. It chirps when something changes. It does not:
- Block or quarantine
- Score or prioritize
- Attribute intent
- Phone home
- Require admin (except for startup install)

It just watches and talks.
