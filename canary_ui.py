"""
CANARY UI - Desktop alert mascot with speech bubbles.

A visible, chatty canary assistant that:
- Floats on desktop like Clippy (transparent background)
- Subscribes to local signals from the edge parser
- Displays word bubbles with dry, factual observations
- Never decides, judges, or blocks
- Only speaks facts
"""

import tkinter as tk
from tkinter import ttk
import sys
import time
import threading
import queue
import random
from pathlib import Path
from typing import Optional, List
from datetime import datetime
from collections import deque

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from shared import (
    SignalQueue, Signal, SignalTypes,
    translate_signal, log_signal, read_log, clear_log, CANARY_DIR
)
from notification_center import show_notification_center, NotificationCenter
from signals import get_signals_db, Signal as SignalV2, Severity, Category

# Try to import PIL for the mascot image
try:
    from PIL import Image, ImageTk
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

# Transparent color key for Windows
TRANSPARENT_COLOR = '#010101'  # Near-black that we'll make transparent

# Behavioral escalation states (dying canary behavior)
class ThreatLevel:
    """
    Canaries don't go quiet when they're about to die.
    They get weird. Agitated. Flappy. Chirpy in short bursts.
    """
    IDLE = 0        # Calm, slow, long gaps
    SUSPICIOUS = 1  # More frequent, slight position changes, pacing
    AGITATED = 2    # Rapid, short duration, jittery, near cursor
    DEATH_SPIRAL = 3  # Frantic micro-movements, then gone

# Behavior parameters per threat level
THREAT_BEHAVIORS = {
    ThreatLevel.IDLE: {
        'poll_interval': 2000,      # ms between checks
        'appear_interval': (30, 60),  # seconds between position changes
        'jitter_px': 0,             # position jitter in pixels
        'scale_jitter': 0,          # scale variation %
        'opacity_min': 1.0,         # minimum opacity
        'duration_mult': 1.0,       # bubble duration multiplier
    },
    ThreatLevel.SUSPICIOUS: {
        'poll_interval': 1500,
        'appear_interval': (10, 20),
        'jitter_px': 5,
        'scale_jitter': 2,
        'opacity_min': 0.9,
        'duration_mult': 0.8,
    },
    ThreatLevel.AGITATED: {
        'poll_interval': 1000,
        'appear_interval': (3, 8),
        'jitter_px': 15,
        'scale_jitter': 4,
        'opacity_min': 0.85,
        'duration_mult': 0.5,
    },
    ThreatLevel.DEATH_SPIRAL: {
        'poll_interval': 500,
        'appear_interval': (1, 3),
        'jitter_px': 30,
        'scale_jitter': 6,
        'opacity_min': 0.7,
        'duration_mult': 0.3,
    },
}


class SpeechBubble(tk.Toplevel):
    """A floating speech bubble window. Red for alerts, cream for normal."""

    def __init__(self, parent, message: str, duration: int = 8000, is_alert: bool = False):
        super().__init__(parent)

        self.duration = duration
        self.parent_window = parent
        self.is_alert = is_alert

        # Window setup - no decorations, always on top
        self.overrideredirect(True)
        self.attributes('-topmost', True)
        self.attributes('-alpha', 0.95)

        # Color scheme based on alert status
        if is_alert:
            # RED ALERT - really bad
            bubble_bg = '#ffeded'      # Light red background
            border_color = '#cc0000'   # Dark red border
            text_color = '#990000'     # Dark red text
            time_color = '#cc6666'     # Muted red timestamp
        else:
            # Normal - cream/yellow
            bubble_bg = '#fffef0'
            border_color = '#333333'
            text_color = '#333333'
            time_color = '#888888'

        self.configure(bg=bubble_bg)

        # Create bubble frame with rounded appearance
        self.bubble = tk.Frame(self, bg=bubble_bg, bd=0)
        self.bubble.pack(fill='both', expand=True)

        # Add border effect (thicker for alerts)
        border_width = 2 if is_alert else 1
        border_frame = tk.Frame(self.bubble, bg=border_color, bd=0)
        border_frame.pack(fill='both', expand=True, padx=border_width, pady=border_width)

        inner_frame = tk.Frame(border_frame, bg=bubble_bg, bd=0)
        inner_frame.pack(fill='both', expand=True, padx=1, pady=1)

        # Alert indicator
        if is_alert:
            alert_label = tk.Label(
                inner_frame,
                text="⚠ ALERT",
                font=('Segoe UI', 9, 'bold'),
                fg='#cc0000',
                bg=bubble_bg
            )
            alert_label.pack(anchor='w', padx=8, pady=(6, 0))

        # Timestamp
        ts = datetime.now().strftime('%H:%M:%S')
        self.time_label = tk.Label(
            inner_frame,
            text=ts,
            font=('Consolas', 8),
            fg=time_color,
            bg=bubble_bg
        )
        self.time_label.pack(anchor='w', padx=8, pady=(2 if is_alert else 6, 0))

        # Message
        self.msg_label = tk.Label(
            inner_frame,
            text=message,
            font=('Segoe UI', 10, 'bold' if is_alert else 'normal'),
            fg=text_color,
            bg=bubble_bg,
            wraplength=280,
            justify='left'
        )
        self.msg_label.pack(padx=10, pady=(2, 8))

        # Click to dismiss
        for widget in [self, self.bubble, border_frame, inner_frame,
                       self.msg_label, self.time_label]:
            widget.bind('<Button-1>', lambda e: self.fade_out())

        # Position and show
        self.update_idletasks()
        self.position_bubble()

        # Auto-dismiss after duration
        self.after(duration, self.fade_out)

    def position_bubble(self):
        """Position bubble above the parent window."""
        self.parent_window.update_idletasks()
        px = self.parent_window.winfo_x()
        py = self.parent_window.winfo_y()
        pw = self.parent_window.winfo_width()

        bw = self.winfo_width()
        bh = self.winfo_height()

        # Position above and to the left of parent
        x = px + pw // 2 - bw // 2
        y = py - bh - 5

        # Keep on screen
        screen_w = self.winfo_screenwidth()
        screen_h = self.winfo_screenheight()

        if x < 10:
            x = 10
        if x + bw > screen_w - 10:
            x = screen_w - bw - 10
        if y < 10:
            y = py + self.parent_window.winfo_height() + 10

        self.geometry(f'+{x}+{y}')

    def fade_out(self):
        """Fade out and destroy."""
        try:
            alpha = self.attributes('-alpha')
            if alpha > 0.1:
                self.attributes('-alpha', alpha - 0.1)
                self.after(30, self.fade_out)
            else:
                self.destroy()
        except tk.TclError:
            pass


class LogViewer(tk.Toplevel):
    """Popup window showing the signal log."""

    def __init__(self, parent):
        super().__init__(parent)

        self.title("Canary Log")
        self.geometry("500x400")
        self.attributes('-topmost', True)

        # Dark theme
        self.configure(bg='#1e1e1e')

        # Header
        header = tk.Frame(self, bg='#1e1e1e')
        header.pack(fill='x', padx=10, pady=5)

        tk.Label(
            header,
            text="Signal Log",
            font=('Segoe UI', 12, 'bold'),
            fg='#ffffff',
            bg='#1e1e1e'
        ).pack(side='left')

        # Buttons
        btn_frame = tk.Frame(header, bg='#1e1e1e')
        btn_frame.pack(side='right')

        tk.Button(
            btn_frame,
            text="Refresh",
            command=self.refresh_log,
            bg='#333333',
            fg='#ffffff'
        ).pack(side='left', padx=2)

        tk.Button(
            btn_frame,
            text="Clear Log",
            command=self.clear_and_refresh,
            bg='#333333',
            fg='#ffffff'
        ).pack(side='left', padx=2)

        # Log text area with scrollbar
        text_frame = tk.Frame(self, bg='#1e1e1e')
        text_frame.pack(fill='both', expand=True, padx=10, pady=5)

        scrollbar = tk.Scrollbar(text_frame)
        scrollbar.pack(side='right', fill='y')

        self.log_text = tk.Text(
            text_frame,
            font=('Consolas', 9),
            bg='#0d0d0d',
            fg='#00ff00',
            insertbackground='#00ff00',
            selectbackground='#333333',
            wrap='word',
            yscrollcommand=scrollbar.set
        )
        self.log_text.pack(fill='both', expand=True)
        scrollbar.config(command=self.log_text.yview)

        # Configure tags for colored text
        self.log_text.tag_configure('alert', foreground='#ff4444')
        self.log_text.tag_configure('timestamp', foreground='#888888')

        # Load log
        self.refresh_log()

        # Auto-refresh every 5 seconds
        self.auto_refresh()

    def refresh_log(self):
        """Reload log from file."""
        self.log_text.config(state='normal')
        self.log_text.delete(1.0, tk.END)

        log_content = read_log(max_lines=200)

        # Colorize alerts
        for line in log_content.split('\n'):
            if '[ALERT]' in line:
                self.log_text.insert(tk.END, line + '\n', 'alert')
            elif line.startswith('['):
                self.log_text.insert(tk.END, line + '\n', 'timestamp')
            else:
                self.log_text.insert(tk.END, line + '\n')

        self.log_text.config(state='disabled')
        self.log_text.see(tk.END)  # Scroll to bottom

    def clear_and_refresh(self):
        """Clear log and refresh."""
        clear_log()
        self.refresh_log()

    def auto_refresh(self):
        """Auto-refresh log every 5 seconds."""
        if self.winfo_exists():
            self.refresh_log()
            self.after(5000, self.auto_refresh)


class CanaryWindow(tk.Tk):
    """
    Main canary window - transparent floating mascot like Clippy.
    Left-click opens notification center. Right-click opens menu.
    """

    def __init__(self):
        super().__init__()

        self.notification_center = None  # Track notification center window
        self.signals_db = get_signals_db()  # New signals database

        # Behavioral escalation tracking
        self.threat_level = ThreatLevel.IDLE
        self.recent_signals: deque = deque(maxlen=50)  # Last 50 signals with timestamps
        self.home_position = None  # Will be set after geometry
        self.current_jitter = (0, 0)
        self.behavior_after_id = None
        self.opacity_pulse_dir = -1
        self.current_opacity = 1.0

        self.title("Canary")
        self.overrideredirect(True)  # No window decorations
        self.attributes('-topmost', True)  # Always on top

        # Make window background transparent (Windows)
        self.configure(bg=TRANSPARENT_COLOR)
        self.attributes('-transparentcolor', TRANSPARENT_COLOR)

        # Position in bottom-right corner
        self.update_idletasks()
        screen_w = self.winfo_screenwidth()
        screen_h = self.winfo_screenheight()

        # Will resize after loading image
        initial_x = screen_w - 130
        initial_y = screen_h - 180
        self.geometry(f'100x120+{initial_x}+{initial_y}')
        self.home_position = (initial_x, initial_y)

        # Set up UI
        self.setup_ui()

        # Message queue for thread-safe bubble display
        self.msg_queue = queue.Queue()

        # Track active bubbles
        self.bubbles = []
        self.max_bubbles = 3

        # Signal queue connection
        self.signal_queue = SignalQueue()
        self.running = True
        self.last_signal_time = time.time()

        # Start signal polling
        self.poll_signals()

        # Check for silence
        self.check_health()

        # Bind right-click for menu
        self.bind('<Button-3>', self.show_menu)

    def setup_ui(self):
        """Set up the transparent canary UI."""
        # Main frame with transparent background
        self.main_frame = tk.Frame(self, bg=TRANSPARENT_COLOR)
        self.main_frame.pack(fill='both', expand=True)

        # Try to load mascot image - prefer transparent version
        mascot_candidates = [
            CANARY_DIR / "b8aeb8a0-0265-489d-90ce-fe5ede35ce8a.png",  # Transparent version
            CANARY_DIR / "81521232-4915-4417-910f-a2f225fe07cf.png",  # Original
        ]
        self.mascot_image = None
        self.mascot_label = None

        for mascot_path in mascot_candidates:
            if mascot_path.exists() and HAS_PIL:
                try:
                    # Load image
                    img = Image.open(mascot_path)

                    # Ensure RGBA mode for transparency
                    if img.mode != 'RGBA':
                        img = img.convert('RGBA')

                    # Resize while maintaining aspect ratio
                    img.thumbnail((100, 100), Image.Resampling.LANCZOS)

                    # Replace transparent pixels with our transparent color key
                    # Windows tkinter uses color keying for transparency
                    datas = img.getdata()
                    new_data = []
                    trans_rgb = tuple(int(TRANSPARENT_COLOR[i:i+2], 16) for i in (1, 3, 5))

                    for item in datas:
                        # If pixel is transparent (alpha < 128), replace with key color
                        if item[3] < 128:
                            new_data.append(trans_rgb + (255,))
                        else:
                            new_data.append(item)

                    img.putdata(new_data)
                    self.mascot_image = ImageTk.PhotoImage(img)

                    # Resize window to fit image
                    self.geometry(f'{img.width}x{img.height + 20}')
                    break  # Success, stop trying other files

                except Exception as e:
                    print(f"[!] Could not load mascot {mascot_path.name}: {e}")
                    continue

        if self.mascot_image:
            self.mascot_label = tk.Label(
                self.main_frame,
                image=self.mascot_image,
                bg=TRANSPARENT_COLOR,
                cursor='hand2'
            )
        else:
            # Fallback: emoji canary on transparent bg
            self.mascot_label = tk.Label(
                self.main_frame,
                text="🐤",
                font=('Segoe UI Emoji', 48),
                bg=TRANSPARENT_COLOR,
                cursor='hand2'
            )

        self.mascot_label.pack(pady=(0, 0))

        # Small status indicator (dot)
        self.status_dot = tk.Label(
            self.main_frame,
            text="●",
            font=('Arial', 8),
            fg='#00aa00',  # Green = watching
            bg=TRANSPARENT_COLOR
        )
        self.status_dot.pack()

        # Single click = open log, drag = move window
        self.mascot_label.bind('<Button-1>', self.on_click)
        self.mascot_label.bind('<B1-Motion>', self.drag)
        self.mascot_label.bind('<Double-Button-1>', self.open_log_viewer)
        self.main_frame.bind('<Button-1>', self.start_drag)
        self.main_frame.bind('<B1-Motion>', self.drag)

    def start_drag(self, event):
        """Start window drag."""
        self._drag_x = event.x
        self._drag_y = event.y

    def drag(self, event):
        """Handle window drag."""
        x = self.winfo_x() + event.x - self._drag_x
        y = self.winfo_y() + event.y - self._drag_y
        self.geometry(f'+{x}+{y}')

        # Update home position
        self.home_position = (x, y)

        # Reposition bubbles when dragged
        self.reposition_bubbles()

    def on_click(self, event):
        """Handle click - prepare for drag or log open."""
        self._drag_x = event.x
        self._drag_y = event.y
        self._click_time = time.time()

    def open_log_viewer(self, event=None):
        """Open or focus the notification center (replaces old log viewer)."""
        if self.notification_center is None or not self.notification_center.winfo_exists():
            self.notification_center = show_notification_center(self)
        else:
            # Bring to front
            self.notification_center.lift()
            self.notification_center.focus_force()

    def show_menu(self, event):
        """Show right-click context menu."""
        menu = tk.Menu(self, tearoff=0)
        menu.add_command(label="🔔 Notifications", command=self.open_log_viewer)
        menu.add_separator()
        menu.add_command(label="Test Bubble", command=self.test_bubble)
        menu.add_command(label="Test RED Alert", command=self.test_alert)
        menu.add_separator()

        # Behavioral test submenu
        behavior_menu = tk.Menu(menu, tearoff=0)
        behavior_menu.add_command(label="Suspicious (pace)", command=lambda: self.test_behavior(ThreatLevel.SUSPICIOUS))
        behavior_menu.add_command(label="Agitated (jitter)", command=lambda: self.test_behavior(ThreatLevel.AGITATED))
        behavior_menu.add_command(label="Death Spiral 💀", command=lambda: self.test_behavior(ThreatLevel.DEATH_SPIRAL))
        behavior_menu.add_separator()
        behavior_menu.add_command(label="Reset to Idle", command=lambda: self.test_behavior(ThreatLevel.IDLE))
        menu.add_cascade(label="🐤 Test Behavior", menu=behavior_menu)

        menu.add_separator()
        menu.add_command(label="Exit Canary", command=self.on_close)
        menu.tk_popup(event.x_root, event.y_root)

    def test_behavior(self, level: int):
        """Test a specific threat level behavior."""
        level_names = {0: 'IDLE', 1: 'SUSPICIOUS', 2: 'AGITATED', 3: 'DEATH_SPIRAL'}
        print(f"[TEST] Setting threat level to {level_names.get(level)}")

        # Inject fake signals to trigger the behavior
        if level == ThreatLevel.DEATH_SPIRAL:
            # 3 critical signals in last minute = death spiral
            for _ in range(3):
                self.recent_signals.append((time.time(), 'critical'))
        elif level == ThreatLevel.AGITATED:
            # 2 critical in 5 min
            for _ in range(2):
                self.recent_signals.append((time.time(), 'critical'))
        elif level == ThreatLevel.SUSPICIOUS:
            # 1 critical in 5 min
            self.recent_signals.append((time.time(), 'critical'))
        else:
            # Clear signals for idle
            self.recent_signals.clear()

        self.update_threat_level()

    def test_bubble(self):
        """Show a test bubble."""
        self.show_bubble("This is a test. The canary is watching.")

    def test_alert(self):
        """Show a test RED alert bubble."""
        self.show_bubble("This is a RED ALERT test. Something bad happened.", is_alert=True)

    def show_bubble(self, message: str, duration: int = 8000, is_alert: bool = False):
        """Show a speech bubble. Red if is_alert=True."""
        # Clean up old bubbles
        self.bubbles = [b for b in self.bubbles if b.winfo_exists()]

        # Limit active bubbles (but always allow alerts through)
        while len(self.bubbles) >= self.max_bubbles:
            # Don't remove alert bubbles to make room for normal ones
            if is_alert:
                break
            old = self.bubbles.pop(0)
            try:
                old.destroy()
            except tk.TclError:
                pass

        # Create new bubble
        bubble = SpeechBubble(self, message, duration, is_alert=is_alert)
        self.bubbles.append(bubble)

        # Reposition existing bubbles
        self.reposition_bubbles()

    def reposition_bubbles(self):
        """Stack bubbles above each other."""
        self.update_idletasks()
        px = self.winfo_x()
        py = self.winfo_y()
        pw = self.winfo_width()

        y_offset = py - 5

        for bubble in reversed(self.bubbles):
            if bubble.winfo_exists():
                bubble.update_idletasks()
                bw = bubble.winfo_width()
                bh = bubble.winfo_height()

                x = px + pw // 2 - bw // 2
                y_offset -= bh + 5

                # Keep on screen
                screen_w = self.winfo_screenwidth()
                if x < 10:
                    x = 10
                if x + bw > screen_w - 10:
                    x = screen_w - bw - 10
                if y_offset < 10:
                    y_offset = 10

                bubble.geometry(f'+{x}+{y_offset}')

    def poll_signals(self):
        """Poll for new signals from the parser."""
        if not self.running:
            return

        try:
            signals = self.signal_queue.pop_all()
            for signal in signals:
                self.last_signal_time = time.time()
                message, is_alert = translate_signal(signal)

                # Log to persistent file (legacy)
                log_signal(signal, message, is_alert)

                # Store in new signals DB for notification center
                severity = Severity.CRITICAL if is_alert else Severity.INFO
                try:
                    sig_v2 = SignalV2.create(
                        signal_type=signal.signal_type,
                        source_surface=signal.source_surface,
                        message=message,
                        artifacts=signal.artifacts,
                        severity=severity,
                        category=Category.META
                    )
                    self.signals_db.store(sig_v2)
                except Exception:
                    pass  # Don't break on new system errors

                # Track signal for behavioral escalation
                self.recent_signals.append((time.time(), severity.value if hasattr(severity, 'value') else str(severity)))

                # Show bubble (duration adjusted by threat level)
                behavior = THREAT_BEHAVIORS[self.threat_level]
                adjusted_duration = int(8000 * behavior['duration_mult'])
                self.show_bubble(message, duration=adjusted_duration, is_alert=is_alert)

                # Update status dot - red if alert, green otherwise
                if is_alert:
                    self.status_dot.config(fg='#cc0000')
                else:
                    self.status_dot.config(fg='#00aa00')

            # Update threat level based on recent patterns
            if signals:
                self.update_threat_level()

        except Exception as e:
            print(f"[!] Signal poll error: {e}")

        # Poll interval based on threat level
        poll_interval = THREAT_BEHAVIORS[self.threat_level]['poll_interval']
        self.after(poll_interval, self.poll_signals)

    def check_health(self):
        """Check if we're still receiving signals (parser alive)."""
        if not self.running:
            return

        # If no signals in 2 minutes, show warning
        silence_threshold = 120  # seconds
        elapsed = time.time() - self.last_signal_time

        if elapsed > silence_threshold:
            self.status_dot.config(fg='#aa0000')  # Red = no signal

        # Check every 30 seconds
        self.after(30000, self.check_health)

    # ==================== BEHAVIORAL ESCALATION ====================

    def compute_threat_level(self) -> int:
        """
        Compute threat level based on recent signal patterns.
        Canaries get weird before they die.
        """
        now = time.time()

        # Count signals in different time windows
        last_1min = sum(1 for ts, sev in self.recent_signals if now - ts < 60)
        last_5min = sum(1 for ts, sev in self.recent_signals if now - ts < 300)
        critical_1min = sum(1 for ts, sev in self.recent_signals
                           if now - ts < 60 and sev == 'critical')
        critical_5min = sum(1 for ts, sev in self.recent_signals
                           if now - ts < 300 and sev == 'critical')

        # Death spiral: 3+ critical in 1 minute
        if critical_1min >= 3:
            return ThreatLevel.DEATH_SPIRAL

        # Agitated: 2+ critical in 5 min, or 10+ signals in 1 min
        if critical_5min >= 2 or last_1min >= 10:
            return ThreatLevel.AGITATED

        # Suspicious: any critical in 5 min, or 5+ signals in 5 min
        if critical_5min >= 1 or last_5min >= 5:
            return ThreatLevel.SUSPICIOUS

        # Idle: all quiet
        return ThreatLevel.IDLE

    def update_threat_level(self):
        """Update threat level and apply behavioral changes."""
        old_level = self.threat_level
        self.threat_level = self.compute_threat_level()

        if self.threat_level != old_level:
            level_names = {0: 'IDLE', 1: 'SUSPICIOUS', 2: 'AGITATED', 3: 'DEATH_SPIRAL'}
            print(f"[BEHAVIOR] Threat level: {level_names.get(old_level)} -> {level_names.get(self.threat_level)}")

            # Start behavior loop if escalating
            if self.threat_level > ThreatLevel.IDLE:
                self.start_behavior_loop()
            else:
                self.stop_behavior_loop()

            # Death spiral triggers special handling
            if self.threat_level == ThreatLevel.DEATH_SPIRAL:
                self.start_death_spiral()

    def start_behavior_loop(self):
        """Start the behavioral jitter/pacing loop."""
        if self.behavior_after_id:
            self.after_cancel(self.behavior_after_id)

        self.apply_behavior()

    def stop_behavior_loop(self):
        """Stop behavioral loop and reset to home position."""
        if self.behavior_after_id:
            self.after_cancel(self.behavior_after_id)
            self.behavior_after_id = None

        # Reset to calm state
        self.current_jitter = (0, 0)
        self.current_opacity = 1.0
        try:
            self.attributes('-alpha', 1.0)
            if self.home_position:
                self.geometry(f'+{self.home_position[0]}+{self.home_position[1]}')
        except tk.TclError:
            pass

    def apply_behavior(self):
        """Apply behavioral effects based on threat level."""
        # Stop if not running or back to idle
        if not self.running or self.threat_level == ThreatLevel.IDLE:
            self.stop_behavior_loop()
            return

        # Don't continue if in death spiral (separate loop handles that)
        if self.threat_level == ThreatLevel.DEATH_SPIRAL:
            return

        behavior = THREAT_BEHAVIORS[self.threat_level]

        # Position jitter - small random movements (pacing)
        jitter_px = behavior['jitter_px']
        if jitter_px > 0:
            dx = random.randint(-jitter_px, jitter_px)
            dy = random.randint(-jitter_px, jitter_px)
            self.current_jitter = (dx, dy)

            if self.home_position:
                new_x = self.home_position[0] + dx
                new_y = self.home_position[1] + dy
                try:
                    self.geometry(f'+{new_x}+{new_y}')
                except tk.TclError:
                    pass

        # Opacity pulse - subtle breathing effect
        opacity_min = behavior['opacity_min']
        opacity_step = 0.05

        self.current_opacity += self.opacity_pulse_dir * opacity_step
        if self.current_opacity <= opacity_min:
            self.current_opacity = opacity_min
            self.opacity_pulse_dir = 1
        elif self.current_opacity >= 1.0:
            self.current_opacity = 1.0
            self.opacity_pulse_dir = -1

        try:
            self.attributes('-alpha', self.current_opacity)
        except tk.TclError:
            pass

        # Schedule next behavior tick (only if still in same threat level)
        if self.threat_level > ThreatLevel.IDLE and self.threat_level < ThreatLevel.DEATH_SPIRAL:
            interval = behavior['appear_interval']
            next_tick = random.randint(int(interval[0] * 100), int(interval[1] * 100))
            self.behavior_after_id = self.after(next_tick, self.apply_behavior)

    def start_death_spiral(self):
        """
        The killer move. Frantic behavior, then full-screen flash with final words.
        "Tell the Ghost I was right."
        """
        # Rapid jitter sequence
        self.death_spiral_ticks = 0
        self.death_spiral_loop()

    def death_spiral_loop(self):
        """Frantic micro-movements before the end."""
        if self.death_spiral_ticks >= 20:
            # Final flash and message
            self.full_screen_flash()
            return

        self.death_spiral_ticks += 1

        # Frantic position jitter
        dx = random.randint(-40, 40)
        dy = random.randint(-40, 40)
        if self.home_position:
            try:
                self.geometry(f'+{self.home_position[0] + dx}+{self.home_position[1] + dy}')
            except tk.TclError:
                pass

        # Rapid opacity flicker
        try:
            self.attributes('-alpha', random.uniform(0.6, 1.0))
        except tk.TclError:
            pass

        # Very fast ticks
        self.after(100, self.death_spiral_loop)

    def full_screen_flash(self):
        """
        Full screen death image - the cat got the canary.
        """
        try:
            # Create full-screen window
            flash = tk.Toplevel(self)
            flash.overrideredirect(True)
            flash.attributes('-topmost', True)

            screen_w = self.winfo_screenwidth()
            screen_h = self.winfo_screenheight()
            flash.geometry(f'{screen_w}x{screen_h}+0+0')
            flash.configure(bg='#000000')

            # Try to load death image
            death_image_path = CANARY_DIR / "death_screen.png"
            if death_image_path.exists() and HAS_PIL:
                try:
                    from PIL import Image, ImageTk
                    img = Image.open(death_image_path)

                    # Scale to fill screen while maintaining aspect ratio
                    img_ratio = img.width / img.height
                    screen_ratio = screen_w / screen_h

                    if img_ratio > screen_ratio:
                        # Image is wider - fit to height
                        new_h = screen_h
                        new_w = int(screen_h * img_ratio)
                    else:
                        # Image is taller - fit to width
                        new_w = screen_w
                        new_h = int(screen_w / img_ratio)

                    img = img.resize((new_w, new_h), Image.Resampling.LANCZOS)
                    self.death_image = ImageTk.PhotoImage(img)

                    label = tk.Label(flash, image=self.death_image, bg='#000000')
                    label.place(relx=0.5, rely=0.5, anchor='center')

                except Exception as e:
                    print(f"[!] Could not load death image: {e}")
                    self._show_fallback_death(flash, screen_w, screen_h)
            else:
                self._show_fallback_death(flash, screen_w, screen_h)

            # Click to dismiss
            flash.bind('<Button-1>', lambda e: self._end_death_screen(flash))
            flash.bind('<Escape>', lambda e: self._end_death_screen(flash))

            # Auto-dismiss after 10 seconds
            self.after(10000, lambda: self._end_death_screen(flash))

        except Exception as e:
            print(f"[!] Death screen error: {e}")
            self.show_bubble("Tell the Ghost I was right.", duration=5000, is_alert=True)

    def _show_fallback_death(self, flash, screen_w, screen_h):
        """Fallback death screen if image not available."""
        msg_frame = tk.Frame(flash, bg='#000000')
        msg_frame.place(relx=0.5, rely=0.5, anchor='center')

        tk.Label(
            msg_frame,
            text="THE CAT GOT THE CANARY.",
            font=('Consolas', 48, 'bold'),
            fg='#ff0000',
            bg='#000000'
        ).pack()

        tk.Label(
            msg_frame,
            text="Don't go it alone.",
            font=('Segoe UI', 24),
            fg='#ffffff',
            bg='#000000'
        ).pack(pady=20)

        tk.Label(
            msg_frame,
            text="canary@ghostlogic.tech",
            font=('Consolas', 18),
            fg='#888888',
            bg='#000000'
        ).pack()

    def _end_death_screen(self, flash):
        """Close death screen."""
        try:
            flash.destroy()
        except tk.TclError:
            pass
        # Reset behavior
        self.stop_behavior_loop()
        self.recent_signals.clear()
        self.threat_level = ThreatLevel.IDLE

    def emit_final_signal(self):
        """Emit canary_silenced signal before dying."""
        try:
            signal = Signal.create(
                signal_type=SignalTypes.CANARY_SILENCED,
                source_surface="CanaryUI",
                trigger_reason="Canary UI shutting down",
                artifacts={}
            )
            self.signal_queue.push(signal)
        except Exception:
            pass

    def on_close(self):
        """Handle window close - show death screen."""
        self.running = False
        self.emit_final_signal()

        # Show death screen
        try:
            self.full_screen_flash()
            # Destroy after death screen auto-dismisses
            self.after(11000, self.destroy)
        except Exception:
            self.destroy()

    def force_death_screen(self):
        """Called when process is being killed - show death screen immediately."""
        try:
            self.full_screen_flash()
        except Exception:
            pass


def setup_signal_handlers(app):
    """Set up signal handlers to show death screen on process kill."""
    import signal

    def handle_signal(signum, frame):
        print(f"[!] Received signal {signum} - showing death screen")
        try:
            app.force_death_screen()
            app.after(5000, app.destroy)
        except Exception:
            pass

    # Handle common termination signals
    try:
        signal.signal(signal.SIGTERM, handle_signal)
        signal.signal(signal.SIGINT, handle_signal)
    except Exception as e:
        print(f"[!] Could not set signal handlers: {e}")


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Canary UI - Desktop Alert Mascot")
    parser.add_argument("--test", action="store_true",
                        help="Show test bubble and exit")
    args = parser.parse_args()

    print("=" * 50)
    print("CANARY UI - Transparent Desktop Mascot")
    print("=" * 50)
    print(f"PIL: {'Available' if HAS_PIL else 'Not available'}")
    print(f"Death image: {(CANARY_DIR / 'death_screen.png').exists()}")
    print("Right-click mascot for menu")
    print("=" * 50)

    app = CanaryWindow()

    # Set up signal handlers for process kill
    setup_signal_handlers(app)

    if args.test:
        app.after(500, app.test_bubble)
        app.after(6000, app.destroy)

    app.mainloop()


if __name__ == "__main__":
    main()
