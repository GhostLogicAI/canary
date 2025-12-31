"""
CANARY NOTIFICATION CENTER

Filterable notification list that pops up when clicking the bird.
Replaces the simple LogViewer.
"""

import tkinter as tk
from tkinter import ttk
import time
from datetime import datetime, timedelta
from typing import Optional, List

from signals import (
    Signal, SignalsDB, get_signals_db,
    Severity, Category, SignalTypes
)
from config import get_config


# Try to import PIL for death image
try:
    from PIL import Image, ImageTk
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

# Path to death image
from pathlib import Path
CANARY_DIR = Path(__file__).parent
DEATH_IMAGE_PATH = CANARY_DIR / "death_screen.png"


class NotificationCard(tk.Frame):
    """A single notification card in the list."""

    # Class-level cached thumbnail
    _death_thumbnail = None

    # Gradient mode: 4 distinct colors
    SEVERITY_COLORS_GRADIENT = {
        'info': {'bg': '#2a2a3a', 'fg': '#888888', 'icon': 'ℹ'},
        'warn': {'bg': '#3a3a2a', 'fg': '#ffaa00', 'icon': '⚠'},
        'alert': {'bg': '#3a2a2a', 'fg': '#ff6644', 'icon': '🐱'},  # Cat for alerts
        'critical': {'bg': '#4a1a1a', 'fg': '#ff3333', 'icon': '🐱'},  # Cat for critical
    }

    # Binary mode: just OK (green) or BAD (red)
    SEVERITY_COLORS_BINARY = {
        'info': {'bg': '#1a3a1a', 'fg': '#44aa44', 'icon': '✓'},
        'warn': {'bg': '#4a1a1a', 'fg': '#ff3333', 'icon': '🐱'},  # Cat for bad
        'alert': {'bg': '#4a1a1a', 'fg': '#ff3333', 'icon': '🐱'},
        'critical': {'bg': '#4a1a1a', 'fg': '#ff3333', 'icon': '🐱'},
    }

    @classmethod
    def get_death_thumbnail(cls):
        """Get cached death image thumbnail."""
        if cls._death_thumbnail is None and HAS_PIL and DEATH_IMAGE_PATH.exists():
            try:
                img = Image.open(DEATH_IMAGE_PATH)
                img.thumbnail((30, 30), Image.Resampling.LANCZOS)
                cls._death_thumbnail = ImageTk.PhotoImage(img)
            except Exception:
                pass
        return cls._death_thumbnail

    def __init__(self, parent, signal: Signal, on_snooze=None, color_mode='gradient', **kwargs):
        super().__init__(parent, **kwargs)

        self.signal = signal
        self.on_snooze = on_snooze

        # Choose color scheme based on mode
        if color_mode == 'binary':
            color_map = self.SEVERITY_COLORS_BINARY
        else:
            color_map = self.SEVERITY_COLORS_GRADIENT

        colors = color_map.get(signal.severity, color_map.get('info', self.SEVERITY_COLORS_GRADIENT['info']))

        self.configure(bg=colors['bg'], pady=5, padx=5)

        # Left side - icon (use death thumbnail for critical/alert)
        is_bad = signal.severity in ('alert', 'critical', 'warn')
        death_thumb = self.get_death_thumbnail() if is_bad else None

        if death_thumb:
            icon_label = tk.Label(
                self,
                image=death_thumb,
                bg=colors['bg'],
                cursor='hand2',
            )
            icon_label.image = death_thumb  # Keep reference
            icon_label.bind('<Button-1>', lambda e: self._show_death_image())
        else:
            icon_label = tk.Label(
                self,
                text=colors['icon'],
                font=('Segoe UI Emoji', 14),
                fg=colors['fg'],
                bg=colors['bg'],
            )
        icon_label.pack(side='left', padx=(5, 10))

        # Middle - content
        content_frame = tk.Frame(self, bg=colors['bg'])
        content_frame.pack(side='left', fill='both', expand=True)

        # Time and category
        ts = datetime.fromtimestamp(signal.timestamp).strftime('%H:%M:%S')
        header = tk.Label(
            content_frame,
            text=f"{ts}  •  {signal.category.upper()}  •  {signal.source_surface}",
            font=('Consolas', 8),
            fg='#666666',
            bg=colors['bg'],
            anchor='w',
        )
        header.pack(fill='x')

        # Message with repeat count
        msg_text = signal.message.replace('\n', ' ')
        if hasattr(signal, 'repeat_count') and signal.repeat_count > 1:
            msg_text = f"{msg_text} (×{signal.repeat_count})"

        msg_label = tk.Label(
            content_frame,
            text=msg_text,
            font=('Segoe UI', 10),
            fg=colors['fg'],
            bg=colors['bg'],
            anchor='w',
            wraplength=400,
            justify='left',
        )
        msg_label.pack(fill='x', pady=(2, 0))

        # Right side - snooze button
        snooze_btn = tk.Button(
            self,
            text="Snooze",
            font=('Segoe UI', 8),
            bg='#333333',
            fg='#888888',
            relief='flat',
            command=self._snooze_clicked,
        )
        snooze_btn.pack(side='right', padx=5)

    def _snooze_clicked(self):
        if self.on_snooze:
            self.on_snooze(self.signal.signal_type)

    def _show_death_image(self):
        """Open death image in a popup window."""
        if not HAS_PIL or not DEATH_IMAGE_PATH.exists():
            return

        try:
            popup = tk.Toplevel(self)
            popup.title("Don't go it alone")
            popup.configure(bg='#000000')

            # Load full image
            img = Image.open(DEATH_IMAGE_PATH)
            # Scale to reasonable size
            img.thumbnail((800, 600), Image.Resampling.LANCZOS)
            photo = ImageTk.PhotoImage(img)

            label = tk.Label(popup, image=photo, bg='#000000')
            label.image = photo  # Keep reference
            label.pack()

            # Click to close
            popup.bind('<Button-1>', lambda e: popup.destroy())
            popup.bind('<Escape>', lambda e: popup.destroy())

            # Center on screen
            popup.update_idletasks()
            w, h = popup.winfo_width(), popup.winfo_height()
            sw, sh = popup.winfo_screenwidth(), popup.winfo_screenheight()
            popup.geometry(f'+{(sw-w)//2}+{(sh-h)//2}')

        except Exception as e:
            print(f"[!] Could not show death image: {e}")


class FilterBar(tk.Frame):
    """Filter controls for the notification center."""

    def __init__(self, parent, on_filter_change, **kwargs):
        super().__init__(parent, **kwargs)

        self.on_filter_change = on_filter_change
        self.configure(bg='#1a1a1a', pady=10, padx=10)

        # Category filter
        cat_frame = tk.Frame(self, bg='#1a1a1a')
        cat_frame.pack(side='left', padx=(0, 20))

        tk.Label(
            cat_frame,
            text="Category:",
            font=('Segoe UI', 9),
            fg='#888888',
            bg='#1a1a1a',
        ).pack(side='left')

        self.category_var = tk.StringVar(value='all')
        categories = ['all', 'network', 'process', 'kernel', 'persistence', 'forensics', 'filesystem', 'meta']
        self.category_combo = ttk.Combobox(
            cat_frame,
            textvariable=self.category_var,
            values=categories,
            width=12,
            state='readonly',
        )
        self.category_combo.pack(side='left', padx=(5, 0))
        self.category_combo.bind('<<ComboboxSelected>>', lambda e: self._filter_changed())

        # Severity filter
        sev_frame = tk.Frame(self, bg='#1a1a1a')
        sev_frame.pack(side='left', padx=(0, 20))

        tk.Label(
            sev_frame,
            text="Severity:",
            font=('Segoe UI', 9),
            fg='#888888',
            bg='#1a1a1a',
        ).pack(side='left')

        self.severity_var = tk.StringVar(value='all')
        severities = ['all', 'info', 'warn', 'alert', 'critical']
        self.severity_combo = ttk.Combobox(
            sev_frame,
            textvariable=self.severity_var,
            values=severities,
            width=10,
            state='readonly',
        )
        self.severity_combo.pack(side='left', padx=(5, 0))
        self.severity_combo.bind('<<ComboboxSelected>>', lambda e: self._filter_changed())

        # Time filter
        time_frame = tk.Frame(self, bg='#1a1a1a')
        time_frame.pack(side='left', padx=(0, 20))

        tk.Label(
            time_frame,
            text="Time:",
            font=('Segoe UI', 9),
            fg='#888888',
            bg='#1a1a1a',
        ).pack(side='left')

        self.time_var = tk.StringVar(value='all')
        times = ['all', 'last hour', 'today', 'last 24h', 'last 7 days']
        self.time_combo = ttk.Combobox(
            time_frame,
            textvariable=self.time_var,
            values=times,
            width=12,
            state='readonly',
        )
        self.time_combo.pack(side='left', padx=(5, 0))
        self.time_combo.bind('<<ComboboxSelected>>', lambda e: self._filter_changed())

        # Search
        search_frame = tk.Frame(self, bg='#1a1a1a')
        search_frame.pack(side='left', fill='x', expand=True)

        tk.Label(
            search_frame,
            text="Search:",
            font=('Segoe UI', 9),
            fg='#888888',
            bg='#1a1a1a',
        ).pack(side='left')

        self.search_var = tk.StringVar()
        self.search_entry = tk.Entry(
            search_frame,
            textvariable=self.search_var,
            font=('Segoe UI', 9),
            bg='#2a2a2a',
            fg='#ffffff',
            insertbackground='#ffffff',
            width=20,
        )
        self.search_entry.pack(side='left', padx=(5, 0), fill='x', expand=True)
        self.search_entry.bind('<Return>', lambda e: self._filter_changed())
        self.search_entry.bind('<KeyRelease>', lambda e: self._search_delayed())

        self._search_after_id = None

    def _search_delayed(self):
        """Debounce search input."""
        if self._search_after_id:
            self.after_cancel(self._search_after_id)
        self._search_after_id = self.after(300, self._filter_changed)

    def _filter_changed(self):
        """Notify parent of filter change."""
        filters = self.get_filters()
        self.on_filter_change(filters)

    def get_filters(self) -> dict:
        """Get current filter values."""
        category = self.category_var.get()
        severity = self.severity_var.get()
        time_filter = self.time_var.get()
        search = self.search_var.get().strip()

        # Convert time filter to timestamp
        since = None
        if time_filter == 'last hour':
            since = time.time() - 3600
        elif time_filter == 'today':
            since = datetime.now().replace(hour=0, minute=0, second=0).timestamp()
        elif time_filter == 'last 24h':
            since = time.time() - 86400
        elif time_filter == 'last 7 days':
            since = time.time() - (7 * 86400)

        return {
            'category': category if category != 'all' else None,
            'severity': severity if severity != 'all' else None,
            'since': since,
            'search': search if search else None,
        }


class NotificationCenter(tk.Toplevel):
    """Main notification center window."""

    def __init__(self, parent):
        super().__init__(parent)

        self.title("Canary Notifications")
        self.geometry("600x500")
        self.configure(bg='#1e1e1e')

        # Make it stay on top
        self.attributes('-topmost', True)

        self.db = get_signals_db()
        self.current_filters = {}
        self.color_mode = get_config().ui.color_mode

        self._setup_ui()
        self._load_signals()

        # Auto-refresh
        self._schedule_refresh()

    def _setup_ui(self):
        """Set up the UI components."""
        # Header
        header = tk.Frame(self, bg='#1a1a1a', pady=10, padx=10)
        header.pack(fill='x')

        tk.Label(
            header,
            text="🐤 Notifications",
            font=('Segoe UI', 14, 'bold'),
            fg='#ffffff',
            bg='#1a1a1a',
        ).pack(side='left')

        # Stats
        self.stats_label = tk.Label(
            header,
            text="",
            font=('Consolas', 9),
            fg='#666666',
            bg='#1a1a1a',
        )
        self.stats_label.pack(side='right')

        # Clear button
        tk.Button(
            header,
            text="Clear All",
            font=('Segoe UI', 9),
            bg='#333333',
            fg='#888888',
            relief='flat',
            command=self._clear_all,
        ).pack(side='right', padx=10)

        # Filter bar
        self.filter_bar = FilterBar(self, on_filter_change=self._on_filter_change)
        self.filter_bar.pack(fill='x')

        # Scrollable notification list
        list_container = tk.Frame(self, bg='#1e1e1e')
        list_container.pack(fill='both', expand=True, padx=5, pady=5)

        # Canvas + scrollbar for scrolling
        self.canvas = tk.Canvas(list_container, bg='#1e1e1e', highlightthickness=0)
        scrollbar = tk.Scrollbar(list_container, orient='vertical', command=self.canvas.yview)

        self.scrollable_frame = tk.Frame(self.canvas, bg='#1e1e1e')
        self.scrollable_frame.bind(
            '<Configure>',
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox('all'))
        )

        self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor='nw')
        self.canvas.configure(yscrollcommand=scrollbar.set)

        scrollbar.pack(side='right', fill='y')
        self.canvas.pack(side='left', fill='both', expand=True)

        # Mouse wheel scrolling
        self.canvas.bind_all('<MouseWheel>', self._on_mousewheel)

    def _on_mousewheel(self, event):
        """Handle mouse wheel scrolling."""
        self.canvas.yview_scroll(int(-1 * (event.delta / 120)), 'units')

    def _on_filter_change(self, filters: dict):
        """Handle filter change."""
        self.current_filters = filters
        self._load_signals()

    def _load_signals(self):
        """Load signals from database with current filters."""
        # Clear existing cards
        for widget in self.scrollable_frame.winfo_children():
            widget.destroy()

        # Get signals
        signals = self.db.get_signals(
            category=self.current_filters.get('category'),
            severity=self.current_filters.get('severity'),
            since=self.current_filters.get('since'),
            search=self.current_filters.get('search'),
            limit=get_config().ui.notification_center_max_items,
        )

        # Update stats
        total = self.db.get_count()
        critical = self.db.get_count(severity='critical')
        self.stats_label.config(text=f"{len(signals)} shown / {total} total • {critical} critical")

        # Create cards
        if not signals:
            no_data = tk.Label(
                self.scrollable_frame,
                text="No notifications match your filters.",
                font=('Segoe UI', 11),
                fg='#666666',
                bg='#1e1e1e',
                pady=50,
            )
            no_data.pack()
        else:
            for signal in signals:
                card = NotificationCard(
                    self.scrollable_frame,
                    signal,
                    on_snooze=self._snooze_type,
                    color_mode=self.color_mode,
                )
                card.pack(fill='x', pady=2)

        # Reset scroll
        self.canvas.yview_moveto(0)

    def _snooze_type(self, signal_type: str):
        """Snooze a signal type."""
        hours = get_config().alert.snooze_duration_hours
        self.db.snooze_type(signal_type, hours)
        self._load_signals()

    def _clear_all(self):
        """Clear all notifications."""
        self.db.clear_all()
        self._load_signals()

    def _schedule_refresh(self):
        """Schedule periodic refresh."""
        if self.winfo_exists():
            self._load_signals()
            self.after(5000, self._schedule_refresh)

    def destroy(self):
        """Clean up on close."""
        self.canvas.unbind_all('<MouseWheel>')
        super().destroy()


def show_notification_center(parent) -> NotificationCenter:
    """Show or create notification center window."""
    return NotificationCenter(parent)


if __name__ == "__main__":
    # Test notification center
    root = tk.Tk()
    root.withdraw()

    # Add some test signals
    from signals import Signal, SignalTypes, Severity, Category

    db = get_signals_db()

    # Test signals
    test_signals = [
        Signal.create(SignalTypes.NEW_KERNEL_DRIVER, "DriverMonitor",
                      "Test driver", {"name": "test.sys"},
                      Severity.CRITICAL, Category.KERNEL),
        Signal.create(SignalTypes.NEW_OUTBOUND_DEST, "NetworkMonitor",
                      "Test connection", {"address": "1.2.3.4:443"},
                      Severity.INFO, Category.NETWORK),
        Signal.create(SignalTypes.CONNECTION_SPIKE, "NetworkMonitor",
                      "Connection spike", {"count": 50, "baseline": 10},
                      Severity.CRITICAL, Category.NETWORK),
    ]

    for sig in test_signals:
        db.store(sig)

    nc = NotificationCenter(root)
    nc.mainloop()
