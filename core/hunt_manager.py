import asyncio
import json
import datetime
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
import sqlite3
import threading
from queue import Queue

from dataclasses import dataclass, field

@dataclass
class HuntResult:
    id: str
    type: str
    target_id: str
    target_name: str
    start_time: str
    end_time: Optional[str]
    total_queries: int
    matched_queries: int
    results: Dict
    status: str
    strict_mode: bool = True
    filters: Dict = field(default_factory=dict)
    priority_queue: List = field(default_factory=list)
    correlated_events: List = field(default_factory=list)
    attack_timeline: Dict = field(default_factory=dict)
    suspicion_score: float = 0.0
    enrichment_data: Dict = field(default_factory=dict)

class HuntManager:
    def __init__(self, db_path="data/hunts.db"):
        self.db_path = db_path
        self.current_hunts: Dict[str, HuntResult] = {}
        self.result_queue = Queue()
        self.init_db()

        # Start background thread for result processing
        self._start_result_processor()

    def init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS hunts (
                    id TEXT PRIMARY KEY,
                    type TEXT,
                    target_id TEXT,
                    target_name TEXT,
                    start_time TEXT,
                    end_time TEXT,
                    total_queries INTEGER,
                    matched_queries INTEGER,
                    results TEXT,
                    status TEXT
                )
            """)

    def start_hunt(self, hunt_type: str, target_id: str, target_name: str,
                  strict_mode: bool = True, filters: Dict = None) -> str:
        """Start a new hunt and return its ID"""
        hunt_id = f"hunt_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
        hunt = HuntResult(
            id=hunt_id,
            type=hunt_type,
            target_id=target_id,
            target_name=target_name,
            start_time=datetime.datetime.now().isoformat(),
            end_time=None,
            total_queries=0,
            matched_queries=0,
            results={},
            status="running",
            strict_mode=strict_mode,
            filters=filters or {},
            priority_queue=[],
            correlated_events=[]
        )

        self.current_hunts[hunt_id] = hunt
        self._save_hunt(hunt)
        return hunt_id

    def update_hunt_progress(self, hunt_id: str, query_result: Dict):
        """Update hunt progress with new query results"""
        if hunt_id not in self.current_hunts:
            return

        hunt = self.current_hunts[hunt_id]
        hunt.total_queries += 1

        if query_result.get('matches', []):
            hunt.matched_queries += 1
            hunt.results[query_result['query_id']] = query_result
            
            # Correlate events and update timeline
            correlation_engine = CorrelationEngine()
            correlated_data = correlation_engine.correlate_events(query_result.get('matches', []))
            hunt.correlated_events = correlated_data['chains']
            hunt.attack_timeline = correlated_data['timeline']

        self._save_hunt(hunt)
        self.result_queue.put((hunt_id, query_result))

    def _save_hunt(self, hunt: HuntResult):
        """Save hunt to database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO hunts
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                hunt.id,
                hunt.type,
                hunt.target_id,
                hunt.target_name,
                hunt.start_time,
                hunt.end_time,
                hunt.total_queries,
                hunt.matched_queries,
                json.dumps(hunt.results),
                hunt.status
            ))

    def _start_result_processor(self):
        """Start background thread for processing results"""
        def process_results():
            while True:
                hunt_id, result = self.result_queue.get()
                # Notify websocket clients about new results
                # This will be implemented in the WebSocket handler

        thread = threading.Thread(target=process_results, daemon=True)
        thread.start()

    def get_hunt(self, hunt_id: str) -> Optional[HuntResult]:
        """Get hunt by ID"""
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute("SELECT * FROM hunts WHERE id = ?", (hunt_id,)).fetchone()
            if row:
                return HuntResult(
                    id=row[0],
                    type=row[1],
                    target_id=row[2],
                    target_name=row[3],
                    start_time=row[4],
                    end_time=row[5],
                    total_queries=row[6],
                    matched_queries=row[7],
                    results=json.loads(row[8]),
                    status=row[9]
                )
        return None

    def get_all_hunts(self) -> List[HuntResult]:
        """Get all hunts"""
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute("SELECT * FROM hunts ORDER BY start_time DESC").fetchall()
            return [HuntResult(
                id=row[0],
                type=row[1],
                target_id=row[2],
                target_name=row[3],
                start_time=row[4],
                end_time=row[5],
                total_queries=row[6],
                matched_queries=row[7],
                results=json.loads(row[8]),
                status=row[9]
            ) for row in rows]