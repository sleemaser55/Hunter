import logging
from typing import List, Dict, Any
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class CorrelationEngine:
    def __init__(self):
        self.events_cache = []
        self.correlation_window = timedelta(hours=24)

    def add_events(self, events: List[Dict[str, Any]]):
        """Add new events to correlation engine"""
        for event in events:
            if '_time' not in event:
                event['_time'] = datetime.now()
            self.events_cache.append(event)
        self._cleanup_old_events()

    def _cleanup_old_events(self):
        """Remove events older than correlation window"""
        cutoff_time = datetime.now() - self.correlation_window
        self.events_cache = [
            event for event in self.events_cache 
            if event['_time'] > cutoff_time
        ]

    def correlate_by_field(self, field: str) -> List[Dict[str, Any]]:
        """Group events by a common field value"""
        correlations = {}
        for event in self.events_cache:
            if field in event:
                field_value = event[field]
                if field_value not in correlations:
                    correlations[field_value] = []
                correlations[field_value].append(event)
        return list(correlations.values())

    def correlate_events(self) -> List[Dict[str, Any]]:
        """Correlate events based on common fields"""
        correlations = []

        # Correlate by fields
        for field in ['user', 'host', 'ip', 'session_id', 'process_guid']:
            field_correlations = self.correlate_by_field(field)
            correlations.extend(field_correlations)

        # Sort correlated events by time
        for correlation in correlations:
            correlation.sort(key=lambda x: x['_time'])

        return correlations

    def group_by_tactic(self, events: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Group events by MITRE tactic"""
        grouped = {}
        for event in events:
            if 'mitre_tactic' in event:
                tactic = event['mitre_tactic']
                if tactic not in grouped:
                    grouped[tactic] = []
                grouped[tactic].append(event)
        return grouped