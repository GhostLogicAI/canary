"""
CANARY BASELINE SYSTEM v2

SQLite-backed baseline with:
- Item aging (remove stale entries)
- Frequency tracking (occurrence counts)
- Time-of-day awareness (hourly histograms)
- Anomaly scoring (deviation from normal)
"""

import sqlite3
import time
import hashlib
import json
from pathlib import Path
from datetime import datetime, timedelta
from typing import List, Tuple, Dict, Optional, Set
from dataclasses import dataclass
from contextlib import contextmanager

from config import get_config

CANARY_DIR = Path(__file__).parent
BASELINE_DB = CANARY_DIR / "baseline.db"
BASELINE_HASH_FILE = CANARY_DIR / ".baseline_hash"


@dataclass
class BaselineItem:
    """A single baseline item with metadata."""
    surface: str
    item: str
    first_seen: float
    last_seen: float
    occurrence_count: int
    hourly_counts: Dict[int, int]  # hour -> count


class BaselineDB:
    """
    SQLite-backed baseline with smart features.
    """

    def __init__(self, db_path: Path = None):
        self.db_path = db_path or BASELINE_DB
        self.config = get_config().baseline
        self._init_db()

    def _init_db(self):
        """Initialize database schema."""
        with self._get_conn() as conn:
            conn.executescript("""
                -- Main baseline items table
                CREATE TABLE IF NOT EXISTS baseline_items (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    surface TEXT NOT NULL,
                    item TEXT NOT NULL,
                    item_hash TEXT NOT NULL,
                    first_seen REAL NOT NULL,
                    last_seen REAL NOT NULL,
                    occurrence_count INTEGER DEFAULT 1,
                    hourly_counts TEXT DEFAULT '{}',
                    UNIQUE(surface, item_hash)
                );

                -- Index for fast lookups
                CREATE INDEX IF NOT EXISTS idx_surface ON baseline_items(surface);
                CREATE INDEX IF NOT EXISTS idx_item_hash ON baseline_items(item_hash);
                CREATE INDEX IF NOT EXISTS idx_last_seen ON baseline_items(last_seen);

                -- Surface metadata
                CREATE TABLE IF NOT EXISTS surface_meta (
                    surface TEXT PRIMARY KEY,
                    last_scan REAL,
                    total_items INTEGER DEFAULT 0,
                    avg_count REAL DEFAULT 0
                );

                -- Baseline version tracking
                CREATE TABLE IF NOT EXISTS baseline_version (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    version INTEGER DEFAULT 1,
                    created_at REAL,
                    last_modified REAL,
                    hash TEXT
                );

                -- Initialize version if not exists
                INSERT OR IGNORE INTO baseline_version (id, version, created_at, last_modified)
                VALUES (1, 1, strftime('%s', 'now'), strftime('%s', 'now'));
            """)

    @contextmanager
    def _get_conn(self):
        """Get database connection with context manager."""
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

    def _hash_item(self, item: str) -> str:
        """Create hash of item for indexing."""
        return hashlib.sha256(item.encode()).hexdigest()[:16]

    def update_surface(self, surface: str, current_items: List[str]) -> Tuple[List[str], List[str]]:
        """
        Update baseline for a surface.
        Returns (appeared, disappeared) lists.
        """
        now = time.time()
        current_hour = datetime.now().hour
        current_set = set(current_items)

        with self._get_conn() as conn:
            # Get existing items for this surface
            cursor = conn.execute(
                "SELECT item, item_hash, hourly_counts FROM baseline_items WHERE surface = ?",
                (surface,)
            )
            existing = {row['item']: (row['item_hash'], row['hourly_counts']) for row in cursor}
            existing_set = set(existing.keys())

            # Calculate differences
            appeared = list(current_set - existing_set)
            disappeared = list(existing_set - current_set)

            # Insert new items
            for item in appeared:
                item_hash = self._hash_item(item)
                hourly = {current_hour: 1}
                conn.execute("""
                    INSERT INTO baseline_items
                    (surface, item, item_hash, first_seen, last_seen, occurrence_count, hourly_counts)
                    VALUES (?, ?, ?, ?, ?, 1, ?)
                """, (surface, item, item_hash, now, now, json.dumps(hourly)))

            # Update existing items (still present)
            for item in current_set & existing_set:
                item_hash, hourly_json = existing[item]
                hourly = json.loads(hourly_json) if hourly_json else {}
                hourly[str(current_hour)] = hourly.get(str(current_hour), 0) + 1

                conn.execute("""
                    UPDATE baseline_items
                    SET last_seen = ?, occurrence_count = occurrence_count + 1, hourly_counts = ?
                    WHERE surface = ? AND item_hash = ?
                """, (now, json.dumps(hourly), surface, item_hash))

            # Update surface metadata
            conn.execute("""
                INSERT OR REPLACE INTO surface_meta (surface, last_scan, total_items)
                VALUES (?, ?, ?)
            """, (surface, now, len(current_set)))

            # Update version
            conn.execute("""
                UPDATE baseline_version SET last_modified = ?, version = version + 1 WHERE id = 1
            """, (now,))

        return appeared, disappeared

    def age_out_stale_items(self) -> List[Tuple[str, str]]:
        """
        Remove items not seen in aging_days.
        Returns list of (surface, item) removed.
        """
        cutoff = time.time() - (self.config.aging_days * 86400)
        removed = []

        with self._get_conn() as conn:
            # Find stale items
            cursor = conn.execute(
                "SELECT surface, item FROM baseline_items WHERE last_seen < ?",
                (cutoff,)
            )
            removed = [(row['surface'], row['item']) for row in cursor]

            # Delete them
            conn.execute("DELETE FROM baseline_items WHERE last_seen < ?", (cutoff,))

        return removed

    def get_item_stats(self, surface: str, item: str) -> Optional[BaselineItem]:
        """Get statistics for a specific item."""
        item_hash = self._hash_item(item)

        with self._get_conn() as conn:
            cursor = conn.execute("""
                SELECT * FROM baseline_items WHERE surface = ? AND item_hash = ?
            """, (surface, item_hash))
            row = cursor.fetchone()

            if row:
                hourly = json.loads(row['hourly_counts']) if row['hourly_counts'] else {}
                return BaselineItem(
                    surface=row['surface'],
                    item=row['item'],
                    first_seen=row['first_seen'],
                    last_seen=row['last_seen'],
                    occurrence_count=row['occurrence_count'],
                    hourly_counts={int(k): v for k, v in hourly.items()}
                )
        return None

    def get_surface_items(self, surface: str) -> List[str]:
        """Get all current items for a surface."""
        with self._get_conn() as conn:
            cursor = conn.execute(
                "SELECT item FROM baseline_items WHERE surface = ?",
                (surface,)
            )
            return [row['item'] for row in cursor]

    def get_surface_stats(self, surface: str) -> Dict:
        """Get statistics for a surface."""
        with self._get_conn() as conn:
            cursor = conn.execute("""
                SELECT
                    COUNT(*) as total_items,
                    AVG(occurrence_count) as avg_occurrences,
                    MIN(first_seen) as oldest_item,
                    MAX(last_seen) as newest_activity
                FROM baseline_items WHERE surface = ?
            """, (surface,))
            row = cursor.fetchone()

            return {
                'total_items': row['total_items'] or 0,
                'avg_occurrences': row['avg_occurrences'] or 0,
                'oldest_item': row['oldest_item'],
                'newest_activity': row['newest_activity'],
            }

    def is_anomalous_count(self, surface: str, current_count: int) -> Tuple[bool, float]:
        """
        Check if current item count is anomalous for this surface.
        Returns (is_anomaly, score).
        """
        with self._get_conn() as conn:
            # Get historical counts from surface_meta
            cursor = conn.execute("""
                SELECT total_items FROM surface_meta WHERE surface = ?
            """, (surface,))
            rows = [row['total_items'] for row in cursor]

            if len(rows) < 3:
                return False, 0.0

            avg = sum(rows) / len(rows)
            if avg == 0:
                return False, 0.0

            # Simple anomaly: how many times above average
            ratio = current_count / avg
            is_anomaly = ratio > self.config.anomaly_threshold

            return is_anomaly, ratio

    def is_unusual_hour(self, surface: str, item: str) -> bool:
        """Check if seeing this item now is unusual based on hourly patterns."""
        if not self.config.time_of_day_awareness:
            return False

        stats = self.get_item_stats(surface, item)
        if not stats or not stats.hourly_counts:
            return False

        current_hour = datetime.now().hour
        total_occurrences = sum(stats.hourly_counts.values())

        if total_occurrences < 10:  # Not enough data
            return False

        hour_count = stats.hourly_counts.get(current_hour, 0)
        hour_pct = hour_count / total_occurrences

        # Unusual if this hour has < 5% of historical occurrences
        return hour_pct < 0.05

    def is_first_run(self) -> bool:
        """Check if this is the first run (empty baseline)."""
        with self._get_conn() as conn:
            cursor = conn.execute("SELECT COUNT(*) as cnt FROM baseline_items")
            return cursor.fetchone()['cnt'] == 0

    def get_hash(self) -> str:
        """Get hash of current baseline for tamper detection."""
        with self._get_conn() as conn:
            cursor = conn.execute("""
                SELECT surface, item_hash, first_seen FROM baseline_items
                ORDER BY surface, item_hash
            """)
            data = "|".join(f"{r['surface']}:{r['item_hash']}:{r['first_seen']}" for r in cursor)
            return hashlib.sha256(data.encode()).hexdigest()

    def verify_integrity(self) -> bool:
        """Verify baseline hasn't been tampered with."""
        if not BASELINE_HASH_FILE.exists():
            # First run, save hash
            self.save_hash()
            return True

        with open(BASELINE_HASH_FILE, 'r') as f:
            saved_hash = f.read().strip()

        current_hash = self.get_hash()
        return saved_hash == current_hash

    def save_hash(self):
        """Save current baseline hash."""
        current_hash = self.get_hash()
        with open(BASELINE_HASH_FILE, 'w') as f:
            f.write(current_hash)

    def export_json(self) -> dict:
        """Export baseline to JSON format."""
        with self._get_conn() as conn:
            cursor = conn.execute("SELECT * FROM baseline_items")
            items = [dict(row) for row in cursor]

            cursor = conn.execute("SELECT * FROM surface_meta")
            meta = [dict(row) for row in cursor]

            cursor = conn.execute("SELECT * FROM baseline_version")
            version = dict(cursor.fetchone())

            return {
                'items': items,
                'meta': meta,
                'version': version,
            }

    def clear_surface(self, surface: str):
        """Clear all items for a surface."""
        with self._get_conn() as conn:
            conn.execute("DELETE FROM baseline_items WHERE surface = ?", (surface,))
            conn.execute("DELETE FROM surface_meta WHERE surface = ?", (surface,))

    def clear_all(self):
        """Clear entire baseline (reset)."""
        with self._get_conn() as conn:
            conn.execute("DELETE FROM baseline_items")
            conn.execute("DELETE FROM surface_meta")
            conn.execute("UPDATE baseline_version SET version = 1, last_modified = ?", (time.time(),))


# Convenience functions for compatibility
_baseline: Optional[BaselineDB] = None


def get_baseline() -> BaselineDB:
    """Get global baseline instance."""
    global _baseline
    if _baseline is None:
        _baseline = BaselineDB()
    return _baseline


if __name__ == "__main__":
    # Test baseline
    db = BaselineDB()
    print(f"Database: {BASELINE_DB}")
    print(f"First run: {db.is_first_run()}")

    # Test update
    appeared, disappeared = db.update_surface("test", ["item1", "item2", "item3"])
    print(f"Appeared: {appeared}")
    print(f"Disappeared: {disappeared}")

    # Test stats
    stats = db.get_surface_stats("test")
    print(f"Stats: {stats}")

    # Test hash
    print(f"Hash: {db.get_hash()[:16]}...")
    print(f"Integrity: {db.verify_integrity()}")
