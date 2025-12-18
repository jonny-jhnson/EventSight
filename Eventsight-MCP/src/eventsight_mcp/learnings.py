"""Learning storage and retrieval system with vector-based semantic search."""

import json
import sqlite3
import numpy as np
from datetime import datetime
from pathlib import Path
from typing import Optional
import re

from .models import Learning, Verdict, Finding, CorrelationRule, Severity


class VectorStore:
    """
    Simple vector store using sentence-transformers for embeddings.

    Stores embeddings alongside SQLite data for semantic similarity search.
    """

    def __init__(self, embeddings_path: str):
        self.embeddings_path = Path(embeddings_path)
        self.embeddings_path.parent.mkdir(parents=True, exist_ok=True)

        self.model = None
        self._embeddings: dict[str, np.ndarray] = {}  # id -> embedding
        self._load_embeddings()

    def _get_model(self):
        """Lazy load the embedding model."""
        if self.model is None:
            try:
                from sentence_transformers import SentenceTransformer
                # Use a small, fast model optimized for semantic similarity
                self.model = SentenceTransformer('all-MiniLM-L6-v2')
                print("Loaded embedding model: all-MiniLM-L6-v2")
            except ImportError:
                print("Warning: sentence-transformers not installed. Using keyword search fallback.")
                return None
        return self.model

    def _load_embeddings(self):
        """Load existing embeddings from disk."""
        if self.embeddings_path.exists():
            try:
                data = np.load(str(self.embeddings_path), allow_pickle=True)
                self._embeddings = data.item() if data.ndim == 0 else {}
            except Exception:
                self._embeddings = {}

    def _save_embeddings(self):
        """Save embeddings to disk."""
        # Convert to plain numpy arrays to avoid pickle issues
        clean_embeddings = {
            k: np.array(v, dtype=np.float32) for k, v in self._embeddings.items()
        }
        np.save(str(self.embeddings_path), clean_embeddings)

    def add_embedding(self, id: str, text: str):
        """Generate and store embedding for text."""
        try:
            model = self._get_model()
            if model is None:
                return

            embedding = model.encode(text, convert_to_numpy=True)
            # Ensure it's a plain numpy array
            self._embeddings[id] = np.array(embedding, dtype=np.float32)
            self._save_embeddings()
        except Exception as e:
            # Don't let embedding failures block learning creation
            print(f"Warning: Could not generate embedding for {id}: {e}")

    def remove_embedding(self, id: str):
        """Remove an embedding."""
        if id in self._embeddings:
            del self._embeddings[id]
            self._save_embeddings()

    def search(self, query: str, top_k: int = 10) -> list[tuple[str, float]]:
        """
        Search for similar items using cosine similarity.

        Returns:
            List of (id, similarity_score) tuples, sorted by similarity descending
        """
        model = self._get_model()
        if model is None or not self._embeddings:
            return []

        query_embedding = model.encode(query, convert_to_numpy=True)

        # Calculate cosine similarity with all stored embeddings
        results = []
        for id, embedding in self._embeddings.items():
            similarity = np.dot(query_embedding, embedding) / (
                np.linalg.norm(query_embedding) * np.linalg.norm(embedding)
            )
            results.append((id, float(similarity)))

        # Sort by similarity descending
        results.sort(key=lambda x: x[1], reverse=True)
        return results[:top_k]

    def has_embeddings(self) -> bool:
        """Check if there are any embeddings stored."""
        return len(self._embeddings) > 0


class LearningsStore:
    """
    Storage and retrieval system for analyst learnings.

    Uses:
    - SQLite for structured data (learnings, correlations, analysis history)
    - Vector embeddings for semantic similarity search (RAG)
    """

    def __init__(self, db_path: str = "./data/learnings/learnings.db",
                 embeddings_path: str = "./data/learnings/embeddings.npy",
                 use_vectors: bool = True):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.row_factory = sqlite3.Row
        self._init_db()

        # Initialize vector store for semantic search
        self.use_vectors = use_vectors
        self.vector_store = VectorStore(embeddings_path) if use_vectors else None

        # Event ID to learnings cache for O(1) lookup
        self._event_id_cache: dict[int, list[str]] = {}  # event_id -> [learning_ids]
        self._learnings_cache: dict[str, Learning] = {}  # learning_id -> Learning
        self._build_event_id_cache()

        # Migrate existing learnings to vector store if needed
        if use_vectors and self.vector_store:
            self._ensure_embeddings()

    def _init_db(self):
        """Initialize SQLite database schema."""
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS learnings (
                id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                type TEXT NOT NULL,
                original_finding_id TEXT,
                original_finding_summary TEXT,
                analyst_explanation TEXT NOT NULL,
                insight TEXT NOT NULL,
                keywords TEXT NOT NULL,
                event_ids TEXT DEFAULT '',
                times_applied INTEGER DEFAULT 0,
                last_applied TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_learnings_type ON learnings(type);
            CREATE INDEX IF NOT EXISTS idx_learnings_keywords ON learnings(keywords);

            CREATE TABLE IF NOT EXISTS analysis_history (
                id TEXT PRIMARY KEY,
                file_path TEXT NOT NULL,
                analyzed_at TEXT NOT NULL,
                total_events INTEGER,
                findings_count INTEGER,
                findings_json TEXT,
                learnings_applied TEXT
            );

            CREATE TABLE IF NOT EXISTS feedback_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                finding_id TEXT NOT NULL,
                learning_id TEXT,
                verdict TEXT NOT NULL,
                explanation TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS correlation_rules (
                id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                source_event_id INTEGER NOT NULL,
                source_conditions TEXT,
                target_event_id INTEGER NOT NULL,
                target_conditions TEXT,
                source_field TEXT NOT NULL,
                target_field TEXT NOT NULL,
                name TEXT NOT NULL,
                description TEXT NOT NULL,
                security_context TEXT NOT NULL,
                severity_hint TEXT DEFAULT 'medium',
                technique TEXT,
                tactic TEXT,
                keywords TEXT,
                times_applied INTEGER DEFAULT 0,
                last_applied TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_correlation_source ON correlation_rules(source_event_id);
            CREATE INDEX IF NOT EXISTS idx_correlation_target ON correlation_rules(target_event_id);
        """)

        # Migration: Add source_field and target_field columns if they don't exist
        try:
            cursor = self.conn.execute("PRAGMA table_info(correlation_rules)")
            columns = {row[1] for row in cursor.fetchall()}

            if columns and 'source_field' not in columns and 'correlation_field' in columns:
                self.conn.execute("ALTER TABLE correlation_rules ADD COLUMN source_field TEXT DEFAULT ''")
                self.conn.execute("ALTER TABLE correlation_rules ADD COLUMN target_field TEXT DEFAULT ''")
                self.conn.execute("UPDATE correlation_rules SET source_field = correlation_field, target_field = correlation_field")
                self.conn.commit()
        except Exception:
            pass

        # Migration: Add event_ids column to learnings if it doesn't exist
        try:
            cursor = self.conn.execute("PRAGMA table_info(learnings)")
            columns = {row[1] for row in cursor.fetchall()}

            if columns and 'event_ids' not in columns:
                self.conn.execute("ALTER TABLE learnings ADD COLUMN event_ids TEXT DEFAULT ''")
                self.conn.commit()
        except Exception:
            pass

        self.conn.commit()

    def _build_event_id_cache(self):
        """Build in-memory cache mapping Event IDs to learnings for O(1) lookup."""
        self._event_id_cache.clear()
        self._learnings_cache.clear()

        learnings = self.get_all_learnings(limit=10000)
        for learning in learnings:
            # Cache the learning object
            self._learnings_cache[learning.id] = learning

            # Index by Event IDs
            for event_id in learning.event_ids:
                if event_id not in self._event_id_cache:
                    self._event_id_cache[event_id] = []
                if learning.id not in self._event_id_cache[event_id]:
                    self._event_id_cache[event_id].append(learning.id)

    def _ensure_embeddings(self):
        """Ensure all learnings have embeddings (for migration)."""
        if not self.vector_store:
            return

        learnings = self.get_all_learnings(limit=1000)
        for learning in learnings:
            if learning.id not in self.vector_store._embeddings:
                # Create embedding from insight + explanation
                text = f"{learning.insight} {learning.analyst_explanation}"
                self.vector_store.add_embedding(learning.id, text)

    def add_learning(self, learning: Learning) -> str:
        """Add a new learning to the store."""
        # Store in SQLite
        self.conn.execute("""
            INSERT INTO learnings (
                id, created_at, type, original_finding_id, original_finding_summary,
                analyst_explanation, insight, keywords, event_ids, times_applied, last_applied
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            learning.id,
            learning.created_at.isoformat(),
            learning.type.value,
            learning.original_finding_id,
            learning.original_finding_summary,
            learning.analyst_explanation,
            learning.insight,
            ','.join(learning.keywords),
            ','.join(str(eid) for eid in learning.event_ids),
            learning.times_applied,
            learning.last_applied.isoformat() if learning.last_applied else None
        ))
        self.conn.commit()

        # Add to vector store for semantic search
        if self.vector_store:
            text = f"{learning.insight} {learning.analyst_explanation}"
            self.vector_store.add_embedding(learning.id, text)

        # Update in-memory cache
        self._learnings_cache[learning.id] = learning
        for event_id in learning.event_ids:
            if event_id not in self._event_id_cache:
                self._event_id_cache[event_id] = []
            if learning.id not in self._event_id_cache[event_id]:
                self._event_id_cache[event_id].append(learning.id)

        return learning.id

    def get_learning(self, learning_id: str) -> Optional[Learning]:
        """Retrieve a specific learning by ID."""
        row = self.conn.execute(
            "SELECT * FROM learnings WHERE id = ?", (learning_id,)
        ).fetchone()

        if not row:
            return None

        return self._row_to_learning(row)

    def get_all_learnings(self, limit: int = 100) -> list[Learning]:
        """Retrieve all learnings."""
        rows = self.conn.execute(
            "SELECT * FROM learnings ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()

        return [self._row_to_learning(row) for row in rows]

    def search_learnings(self, query: str, limit: int = 10) -> list[Learning]:
        """
        Search for relevant learnings using semantic similarity.
        Falls back to keyword search if vectors unavailable.
        """
        if self.vector_store and self.vector_store.has_embeddings():
            return self._vector_search(query, limit)
        else:
            return self._keyword_search(query, limit)

    def get_relevant_learnings(self, events_summary: str, limit: int = 10) -> list[Learning]:
        """Get learnings relevant to a set of events using semantic search."""
        return self.search_learnings(events_summary, limit)

    def get_learnings_by_event_ids(self, event_ids: set[int], limit: int = 50) -> list[Learning]:
        """
        Get learnings relevant to a set of Event IDs using O(1) cache lookup.

        This is much faster than vector search for continuous analysis where
        you know which Event IDs you're analyzing.

        Args:
            event_ids: Set of Event IDs being analyzed
            limit: Maximum number of learnings to return

        Returns:
            List of Learning objects relevant to the provided Event IDs
        """
        seen_ids: set[str] = set()
        learnings: list[Learning] = []

        for event_id in event_ids:
            if event_id in self._event_id_cache:
                for learning_id in self._event_id_cache[event_id]:
                    if learning_id not in seen_ids:
                        seen_ids.add(learning_id)
                        # Get from cache if available, otherwise fetch from DB
                        if learning_id in self._learnings_cache:
                            learnings.append(self._learnings_cache[learning_id])
                        else:
                            learning = self.get_learning(learning_id)
                            if learning:
                                learnings.append(learning)
                                self._learnings_cache[learning_id] = learning

                        if len(learnings) >= limit:
                            return learnings

        return learnings

    def _vector_search(self, query: str, limit: int) -> list[Learning]:
        """Search using vector similarity."""
        results = self.vector_store.search(query, top_k=limit)

        learnings = []
        for learning_id, score in results:
            if score > 0.3:  # Minimum similarity threshold
                learning = self.get_learning(learning_id)
                if learning:
                    learnings.append(learning)

        return learnings

    def _keyword_search(self, query: str, limit: int) -> list[Learning]:
        """Fallback search using keyword matching."""
        query_words = set(re.findall(r'\b\w+\b', query.lower()))

        all_learnings = self.get_all_learnings(limit=500)

        scored = []
        for learning in all_learnings:
            learning_words = set(kw.lower() for kw in learning.keywords)
            learning_words.update(re.findall(r'\b\w+\b', learning.insight.lower()))

            overlap = len(query_words & learning_words)
            if overlap > 0:
                scored.append((overlap, learning))

        scored.sort(key=lambda x: x[0], reverse=True)
        return [learning for _, learning in scored[:limit]]

    def update_applied(self, learning_ids: list[str]):
        """Update the times_applied and last_applied for learnings."""
        now = datetime.now().isoformat()
        for learning_id in learning_ids:
            self.conn.execute("""
                UPDATE learnings
                SET times_applied = times_applied + 1, last_applied = ?
                WHERE id = ?
            """, (now, learning_id))
        self.conn.commit()

    def delete_learning(self, learning_id: str) -> bool:
        """Delete a learning."""
        # Get the learning first to remove from event_id cache
        learning = self._learnings_cache.get(learning_id) or self.get_learning(learning_id)

        cursor = self.conn.execute(
            "DELETE FROM learnings WHERE id = ?", (learning_id,)
        )
        self.conn.commit()

        # Remove from vector store
        if self.vector_store:
            self.vector_store.remove_embedding(learning_id)

        # Remove from caches
        if learning_id in self._learnings_cache:
            del self._learnings_cache[learning_id]

        if learning:
            for event_id in learning.event_ids:
                if event_id in self._event_id_cache:
                    if learning_id in self._event_id_cache[event_id]:
                        self._event_id_cache[event_id].remove(learning_id)
                    # Clean up empty lists
                    if not self._event_id_cache[event_id]:
                        del self._event_id_cache[event_id]

        return cursor.rowcount > 0

    def update_learning_insight(self, learning_id: str, new_insight: str) -> bool:
        """Update a learning's insight text."""
        keywords = extract_keywords(new_insight)
        cursor = self.conn.execute(
            "UPDATE learnings SET insight = ?, keywords = ? WHERE id = ?",
            (new_insight, ','.join(keywords), learning_id)
        )
        self.conn.commit()

        # Update embedding
        if self.vector_store and cursor.rowcount > 0:
            learning = self.get_learning(learning_id)
            if learning:
                text = f"{new_insight} {learning.analyst_explanation}"
                self.vector_store.add_embedding(learning_id, text)

        return cursor.rowcount > 0

    def update_learning_event_ids(self, learning_id: str, event_ids: list[int]) -> bool:
        """
        Update a learning's Event IDs for fast lookup.

        Args:
            learning_id: The learning ID to update
            event_ids: List of Event IDs this learning applies to

        Returns:
            True if the learning was updated successfully
        """
        # Get current learning to update cache
        old_learning = self.get_learning(learning_id)
        if not old_learning:
            return False

        # Update database
        event_ids_str = ','.join(str(eid) for eid in event_ids)
        cursor = self.conn.execute(
            "UPDATE learnings SET event_ids = ? WHERE id = ?",
            (event_ids_str, learning_id)
        )
        self.conn.commit()

        if cursor.rowcount > 0:
            # Remove from old Event ID cache entries
            for old_eid in old_learning.event_ids:
                if old_eid in self._event_id_cache:
                    if learning_id in self._event_id_cache[old_eid]:
                        self._event_id_cache[old_eid].remove(learning_id)
                    if not self._event_id_cache[old_eid]:
                        del self._event_id_cache[old_eid]

            # Add to new Event ID cache entries
            for new_eid in event_ids:
                if new_eid not in self._event_id_cache:
                    self._event_id_cache[new_eid] = []
                if learning_id not in self._event_id_cache[new_eid]:
                    self._event_id_cache[new_eid].append(learning_id)

            # Update learnings cache
            if learning_id in self._learnings_cache:
                self._learnings_cache[learning_id].event_ids = event_ids

            return True

        return False

    def save_analysis(self, analysis_id: str, file_path: str, total_events: int,
                      findings: list[Finding], learnings_applied: list[str]):
        """Save analysis history."""
        self.conn.execute("""
            INSERT INTO analysis_history (
                id, file_path, analyzed_at, total_events, findings_count,
                findings_json, learnings_applied
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            analysis_id,
            file_path,
            datetime.now().isoformat(),
            total_events,
            len(findings),
            json.dumps([f.model_dump() for f in findings], default=str),
            ','.join(learnings_applied)
        ))
        self.conn.commit()

    def save_feedback(self, finding_id: str, verdict: str, explanation: str,
                      learning_id: Optional[str] = None):
        """Save feedback history."""
        self.conn.execute("""
            INSERT INTO feedback_history (
                finding_id, learning_id, verdict, explanation, created_at
            ) VALUES (?, ?, ?, ?, ?)
        """, (
            finding_id,
            learning_id,
            verdict,
            explanation,
            datetime.now().isoformat()
        ))
        self.conn.commit()

    def _row_to_learning(self, row: sqlite3.Row) -> Learning:
        """Convert a database row to a Learning object."""
        # Parse event_ids - handle missing column for migration
        event_ids_str = row['event_ids'] if 'event_ids' in row.keys() else ''
        event_ids = []
        if event_ids_str:
            for eid_str in event_ids_str.split(','):
                try:
                    event_ids.append(int(eid_str.strip()))
                except ValueError:
                    pass

        return Learning(
            id=row['id'],
            created_at=datetime.fromisoformat(row['created_at']),
            type=Verdict(row['type']),
            original_finding_id=row['original_finding_id'],
            original_finding_summary=row['original_finding_summary'] or '',
            analyst_explanation=row['analyst_explanation'],
            insight=row['insight'],
            keywords=row['keywords'].split(',') if row['keywords'] else [],
            event_ids=event_ids,
            times_applied=row['times_applied'],
            last_applied=datetime.fromisoformat(row['last_applied']) if row['last_applied'] else None
        )

    def get_stats(self) -> dict:
        """Get statistics about the learnings store."""
        total = self.conn.execute("SELECT COUNT(*) FROM learnings").fetchone()[0]
        by_type = {}
        for row in self.conn.execute("SELECT type, COUNT(*) as cnt FROM learnings GROUP BY type"):
            by_type[row['type']] = row['cnt']

        most_applied = self.conn.execute("""
            SELECT insight, times_applied FROM learnings
            ORDER BY times_applied DESC LIMIT 5
        """).fetchall()

        total_correlations = self.conn.execute("SELECT COUNT(*) FROM correlation_rules").fetchone()[0]

        return {
            "total_learnings": total,
            "total_correlation_rules": total_correlations,
            "by_type": by_type,
            "most_applied": [(row['insight'][:50], row['times_applied']) for row in most_applied],
            "using_vectors": self.use_vectors and self.vector_store and self.vector_store.has_embeddings()
        }

    # ==================== Correlation Rules ====================

    def add_correlation_rule(self, rule: CorrelationRule) -> str:
        """Add a new correlation rule to the store."""
        self.conn.execute("""
            INSERT INTO correlation_rules (
                id, created_at, source_event_id, source_conditions,
                target_event_id, target_conditions, source_field, target_field,
                name, description, security_context, severity_hint,
                technique, tactic, keywords, times_applied, last_applied
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            rule.id,
            rule.created_at.isoformat(),
            rule.source_event_id,
            json.dumps(rule.source_conditions),
            rule.target_event_id,
            json.dumps(rule.target_conditions),
            rule.source_field,
            rule.target_field,
            rule.name,
            rule.description,
            rule.security_context,
            rule.severity_hint.value,
            rule.technique,
            rule.tactic,
            ','.join(rule.keywords),
            rule.times_applied,
            rule.last_applied.isoformat() if rule.last_applied else None
        ))
        self.conn.commit()
        return rule.id

    def get_correlation_rule(self, rule_id: str) -> Optional[CorrelationRule]:
        """Retrieve a specific correlation rule by ID."""
        row = self.conn.execute(
            "SELECT * FROM correlation_rules WHERE id = ?", (rule_id,)
        ).fetchone()

        if not row:
            return None

        return self._row_to_correlation_rule(row)

    def get_all_correlation_rules(self, limit: int = 100) -> list[CorrelationRule]:
        """Retrieve all correlation rules."""
        rows = self.conn.execute(
            "SELECT * FROM correlation_rules ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()

        return [self._row_to_correlation_rule(row) for row in rows]

    def get_correlation_rules_for_events(self, event_ids: set[int]) -> list[CorrelationRule]:
        """Get correlation rules relevant to a set of Event IDs."""
        if not event_ids:
            return []

        placeholders = ','.join('?' * len(event_ids))
        rows = self.conn.execute(f"""
            SELECT * FROM correlation_rules
            WHERE source_event_id IN ({placeholders})
               OR target_event_id IN ({placeholders})
            ORDER BY times_applied DESC
        """, list(event_ids) + list(event_ids)).fetchall()

        return [self._row_to_correlation_rule(row) for row in rows]

    def delete_correlation_rule(self, rule_id: str) -> bool:
        """Delete a correlation rule."""
        cursor = self.conn.execute(
            "DELETE FROM correlation_rules WHERE id = ?", (rule_id,)
        )
        self.conn.commit()
        return cursor.rowcount > 0

    def update_correlation_applied(self, rule_ids: list[str]):
        """Update the times_applied and last_applied for correlation rules."""
        now = datetime.now().isoformat()
        for rule_id in rule_ids:
            self.conn.execute("""
                UPDATE correlation_rules
                SET times_applied = times_applied + 1, last_applied = ?
                WHERE id = ?
            """, (now, rule_id))
        self.conn.commit()

    def _row_to_correlation_rule(self, row: sqlite3.Row) -> CorrelationRule:
        """Convert a database row to a CorrelationRule object."""
        source_field = row['source_field'] if 'source_field' in row.keys() and row['source_field'] else row.get('correlation_field', '')
        target_field = row['target_field'] if 'target_field' in row.keys() and row['target_field'] else row.get('correlation_field', '')

        return CorrelationRule(
            id=row['id'],
            created_at=datetime.fromisoformat(row['created_at']),
            source_event_id=row['source_event_id'],
            source_conditions=json.loads(row['source_conditions']) if row['source_conditions'] else {},
            target_event_id=row['target_event_id'],
            target_conditions=json.loads(row['target_conditions']) if row['target_conditions'] else {},
            source_field=source_field,
            target_field=target_field,
            name=row['name'],
            description=row['description'],
            security_context=row['security_context'],
            severity_hint=Severity(row['severity_hint']) if row['severity_hint'] else Severity.MEDIUM,
            technique=row['technique'],
            tactic=row['tactic'],
            keywords=row['keywords'].split(',') if row['keywords'] else [],
            times_applied=row['times_applied'],
            last_applied=datetime.fromisoformat(row['last_applied']) if row['last_applied'] else None
        )

    def close(self):
        """Close database connections."""
        self.conn.close()


def export_learnings(db_path: str, output_path: str, include_embeddings: bool = True) -> dict:
    """
    Export learnings database to a portable ZIP package.

    This creates a self-contained package that can be imported into
    another EventSight instance or a different project.

    Args:
        db_path: Path to the learnings.db file
        output_path: Path for the output ZIP file
        include_embeddings: Whether to include embeddings.npy (larger but faster import)

    Returns:
        Export metadata including counts
    """
    import zipfile
    import shutil
    from pathlib import Path

    db_path = Path(db_path)
    output_path = Path(output_path)

    if not db_path.exists():
        raise FileNotFoundError(f"Learnings database not found: {db_path}")

    # Get counts before export
    conn = sqlite3.connect(str(db_path))
    learning_count = conn.execute("SELECT COUNT(*) FROM learnings").fetchone()[0]
    rule_count = conn.execute("SELECT COUNT(*) FROM correlation_rules").fetchone()[0]
    conn.close()

    embeddings_path = db_path.parent / "embeddings.npy"

    with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zf:
        # Add the database
        zf.write(db_path, "learnings.db")

        # Add embeddings if requested and available
        if include_embeddings and embeddings_path.exists():
            zf.write(embeddings_path, "embeddings.npy")

        # Add metadata
        metadata = {
            "version": "1.0",
            "exported_at": datetime.now().isoformat(),
            "learning_count": learning_count,
            "correlation_rule_count": rule_count,
            "includes_embeddings": include_embeddings and embeddings_path.exists()
        }
        zf.writestr("metadata.json", json.dumps(metadata, indent=2))

    return {
        "success": True,
        "output_path": str(output_path),
        "learning_count": learning_count,
        "correlation_rule_count": rule_count,
        "includes_embeddings": include_embeddings and embeddings_path.exists(),
        "file_size_mb": round(output_path.stat().st_size / (1024 * 1024), 2)
    }


def import_learnings(package_path: str, target_dir: str,
                     merge: bool = True) -> dict:
    """
    Import learnings from an exported package.

    Args:
        package_path: Path to the exported ZIP file
        target_dir: Directory to import into (will create learnings.db here)
        merge: If True, merge with existing learnings. If False, replace.

    Returns:
        Import metadata including counts
    """
    import zipfile
    import shutil
    from pathlib import Path

    package_path = Path(package_path)
    target_dir = Path(target_dir)
    target_dir.mkdir(parents=True, exist_ok=True)

    if not package_path.exists():
        raise FileNotFoundError(f"Package not found: {package_path}")

    target_db = target_dir / "learnings.db"
    target_embeddings = target_dir / "embeddings.npy"

    with zipfile.ZipFile(package_path, 'r') as zf:
        # Read metadata
        metadata = json.loads(zf.read("metadata.json"))

        if merge and target_db.exists():
            # Merge mode: extract to temp, then merge
            import tempfile
            with tempfile.TemporaryDirectory() as tmpdir:
                zf.extractall(tmpdir)
                imported = _merge_learnings(
                    source_db=Path(tmpdir) / "learnings.db",
                    target_db=target_db,
                    source_embeddings=Path(tmpdir) / "embeddings.npy" if metadata.get("includes_embeddings") else None,
                    target_embeddings=target_embeddings
                )
                return {
                    "success": True,
                    "mode": "merge",
                    "learnings_imported": imported["learnings_imported"],
                    "learnings_skipped": imported["learnings_skipped"],
                    "rules_imported": imported["rules_imported"],
                    "rules_skipped": imported["rules_skipped"]
                }
        else:
            # Replace mode: extract directly
            zf.extractall(target_dir)
            return {
                "success": True,
                "mode": "replace",
                "learnings_imported": metadata.get("learning_count", 0),
                "rules_imported": metadata.get("correlation_rule_count", 0)
            }


def _merge_learnings(source_db: Path, target_db: Path,
                     source_embeddings: Optional[Path] = None,
                     target_embeddings: Optional[Path] = None) -> dict:
    """Merge learnings from source into target, skipping duplicates."""
    source_conn = sqlite3.connect(str(source_db))
    source_conn.row_factory = sqlite3.Row
    target_conn = sqlite3.connect(str(target_db))
    target_conn.row_factory = sqlite3.Row

    # Get existing IDs to avoid duplicates
    existing_learning_ids = set(
        row[0] for row in target_conn.execute("SELECT id FROM learnings").fetchall()
    )
    existing_rule_ids = set(
        row[0] for row in target_conn.execute("SELECT id FROM correlation_rules").fetchall()
    )

    # Import learnings
    learnings_imported = 0
    learnings_skipped = 0

    for row in source_conn.execute("SELECT * FROM learnings").fetchall():
        if row["id"] in existing_learning_ids:
            learnings_skipped += 1
            continue

        target_conn.execute("""
            INSERT INTO learnings (
                id, created_at, type, original_finding_id, original_finding_summary,
                analyst_explanation, insight, keywords, event_ids, times_applied, last_applied
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            row["id"], row["created_at"], row["type"], row["original_finding_id"],
            row["original_finding_summary"], row["analyst_explanation"], row["insight"],
            row["keywords"], row.get("event_ids", ""), row["times_applied"], row["last_applied"]
        ))
        learnings_imported += 1

    # Import correlation rules
    rules_imported = 0
    rules_skipped = 0

    for row in source_conn.execute("SELECT * FROM correlation_rules").fetchall():
        if row["id"] in existing_rule_ids:
            rules_skipped += 1
            continue

        target_conn.execute("""
            INSERT INTO correlation_rules (
                id, created_at, source_event_id, source_conditions, target_event_id,
                target_conditions, source_field, target_field, name, description,
                security_context, severity_hint, technique, tactic, keywords,
                times_applied, last_applied
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            row["id"], row["created_at"], row["source_event_id"], row["source_conditions"],
            row["target_event_id"], row["target_conditions"],
            row.get("source_field", ""), row.get("target_field", ""),
            row["name"], row["description"], row["security_context"], row["severity_hint"],
            row["technique"], row["tactic"], row["keywords"],
            row["times_applied"], row["last_applied"]
        ))
        rules_imported += 1

    target_conn.commit()
    source_conn.close()
    target_conn.close()

    # Merge embeddings if available
    if source_embeddings and source_embeddings.exists():
        try:
            source_emb = np.load(str(source_embeddings), allow_pickle=True)
            if source_emb.ndim == 0:
                source_emb = source_emb.item()

            if target_embeddings and target_embeddings.exists():
                target_emb = np.load(str(target_embeddings), allow_pickle=True)
                if target_emb.ndim == 0:
                    target_emb = target_emb.item()
                # Merge, preferring target for duplicates
                for k, v in source_emb.items():
                    if k not in target_emb:
                        target_emb[k] = v
                np.save(str(target_embeddings), target_emb)
            else:
                # Just copy source embeddings
                np.save(str(target_embeddings), source_emb)
        except Exception as e:
            print(f"Warning: Could not merge embeddings: {e}")

    return {
        "learnings_imported": learnings_imported,
        "learnings_skipped": learnings_skipped,
        "rules_imported": rules_imported,
        "rules_skipped": rules_skipped
    }


def extract_keywords(text: str) -> list[str]:
    """Extract meaningful keywords from text."""
    security_terms = {
        'injection', 'createremotethread', 'process', 'powershell', 'cmd',
        'lsass', 'mimikatz', 'credential', 'token', 'privilege', 'admin',
        'system', 'service', 'registry', 'scheduled', 'task', 'wmi', 'psexec',
        'lateral', 'persistence', 'evasion', 'execution', 'discovery',
        'exfiltration', 'c2', 'beacon', 'cobalt', 'empire', 'metasploit',
        'mde', 'defender', 'sentinelone', 'carbon', 'edr',
        'antivirus', 'firewall', 'sysmon', 'eventlog', 'security', 'audit',
        'dll', 'exe', 'script', 'macro', 'vba', 'javascript', 'wscript',
        'cscript', 'mshta', 'rundll32', 'regsvr32', 'certutil', 'bitsadmin'
    }

    words = re.findall(r'\b[a-zA-Z][a-zA-Z0-9_\-\.]+\b', text.lower())

    keywords = []
    for word in words:
        if word in security_terms:
            keywords.append(word)
        elif word.endswith(('.exe', '.dll', '.ps1', '.bat', '.cmd', '.vbs', '.js')):
            keywords.append(word)
        elif '\\' in word or '/' in word:
            keywords.append(word.split('\\')[-1].split('/')[-1])
        elif len(word) > 4 and word not in {'this', 'that', 'with', 'from', 'have', 'been', 'were', 'what', 'when', 'where', 'which', 'their', 'about', 'would', 'could', 'should', 'there', 'these', 'those'}:
            keywords.append(word)

    seen = set()
    unique_keywords = []
    for kw in keywords:
        if kw not in seen:
            seen.add(kw)
            unique_keywords.append(kw)

    return unique_keywords[:20]
