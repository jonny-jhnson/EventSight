"""Events storage using SQLite - optimized for structured queries."""

import json
import sqlite3
from pathlib import Path
from typing import Optional

from .models import WindowsEvent


class EventsStore:
    """
    SQLite-based storage for parsed Windows events.

    Optimized for:
    - Exact lookups by Event ID, timestamp, provider
    - Bulk inserts of large event sets
    - Filtering and aggregation queries
    """

    def __init__(self, db_path: str = "./data/learnings/events.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.row_factory = sqlite3.Row
        self._init_db()

    def _init_db(self):
        """Initialize SQLite database schema."""
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                analysis_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                event_id INTEGER NOT NULL,
                channel TEXT,
                provider TEXT,
                computer TEXT,
                user_sid TEXT,
                process_id INTEGER,
                event_data_json TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_events_analysis ON events(analysis_id);
            CREATE INDEX IF NOT EXISTS idx_events_event_id ON events(event_id);
            CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_events_provider ON events(provider);
        """)
        self.conn.commit()

    def save_events(self, analysis_id: str, events: list[WindowsEvent]):
        """
        Save parsed events to the database.

        Args:
            analysis_id: The analysis ID to associate events with
            events: List of WindowsEvent objects to store
        """
        if not events:
            return

        # Use executemany for better performance with large event sets
        event_rows = [
            (
                analysis_id,
                event.timestamp.isoformat(),
                event.event_id,
                event.channel,
                event.provider,
                event.computer,
                event.user_sid,
                event.process_id,
                json.dumps(event.event_data)
            )
            for event in events
        ]

        self.conn.executemany("""
            INSERT INTO events (
                analysis_id, timestamp, event_id, channel, provider,
                computer, user_sid, process_id, event_data_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, event_rows)
        self.conn.commit()

    def get_events_for_analysis(self, analysis_id: str,
                                 event_ids: Optional[list[int]] = None,
                                 limit: int = 1000) -> list[dict]:
        """
        Retrieve events for a specific analysis.

        Args:
            analysis_id: The analysis ID to get events for
            event_ids: Optional list of Event IDs to filter by
            limit: Maximum number of events to return

        Returns:
            List of event dictionaries
        """
        if event_ids:
            placeholders = ','.join('?' * len(event_ids))
            rows = self.conn.execute(f"""
                SELECT * FROM events
                WHERE analysis_id = ? AND event_id IN ({placeholders})
                ORDER BY timestamp
                LIMIT ?
            """, [analysis_id] + event_ids + [limit]).fetchall()
        else:
            rows = self.conn.execute("""
                SELECT * FROM events
                WHERE analysis_id = ?
                ORDER BY timestamp
                LIMIT ?
            """, (analysis_id, limit)).fetchall()

        return [self._row_to_event_dict(row) for row in rows]

    def query_events(self,
                     event_ids: Optional[list[int]] = None,
                     provider: Optional[str] = None,
                     start_time: Optional[str] = None,
                     end_time: Optional[str] = None,
                     limit: int = 1000) -> list[dict]:
        """
        Query events across all analyses with flexible filters.

        Args:
            event_ids: Optional list of Event IDs to filter by
            provider: Optional provider name to filter by
            start_time: Optional start timestamp (ISO format)
            end_time: Optional end timestamp (ISO format)
            limit: Maximum number of events to return

        Returns:
            List of event dictionaries
        """
        conditions = []
        params = []

        if event_ids:
            placeholders = ','.join('?' * len(event_ids))
            conditions.append(f"event_id IN ({placeholders})")
            params.extend(event_ids)

        if provider:
            conditions.append("provider LIKE ?")
            params.append(f"%{provider}%")

        if start_time:
            conditions.append("timestamp >= ?")
            params.append(start_time)

        if end_time:
            conditions.append("timestamp <= ?")
            params.append(end_time)

        where_clause = " AND ".join(conditions) if conditions else "1=1"
        params.append(limit)

        rows = self.conn.execute(f"""
            SELECT * FROM events
            WHERE {where_clause}
            ORDER BY timestamp
            LIMIT ?
        """, params).fetchall()

        return [self._row_to_event_dict(row) for row in rows]

    def get_events_count(self, analysis_id: Optional[str] = None) -> int:
        """Get total count of stored events, optionally filtered by analysis."""
        if analysis_id:
            result = self.conn.execute(
                "SELECT COUNT(*) FROM events WHERE analysis_id = ?", (analysis_id,)
            ).fetchone()
        else:
            result = self.conn.execute("SELECT COUNT(*) FROM events").fetchone()
        return result[0] if result else 0

    def clear_events(self, analysis_id: Optional[str] = None) -> int:
        """
        Clear stored events from the database.

        Args:
            analysis_id: Optional analysis ID. If provided, only clear events
                        for that analysis. If None, clear ALL events.

        Returns:
            Number of events deleted
        """
        if analysis_id:
            cursor = self.conn.execute(
                "DELETE FROM events WHERE analysis_id = ?", (analysis_id,)
            )
        else:
            cursor = self.conn.execute("DELETE FROM events")

        self.conn.commit()
        return cursor.rowcount

    def _row_to_event_dict(self, row: sqlite3.Row) -> dict:
        """Convert a database row to an event dictionary."""
        return {
            "id": row["id"],
            "analysis_id": row["analysis_id"],
            "timestamp": row["timestamp"],
            "event_id": row["event_id"],
            "channel": row["channel"],
            "provider": row["provider"],
            "computer": row["computer"],
            "user_sid": row["user_sid"],
            "process_id": row["process_id"],
            "event_data": json.loads(row["event_data_json"]) if row["event_data_json"] else {}
        }

    def close(self):
        """Close database connection."""
        self.conn.close()
