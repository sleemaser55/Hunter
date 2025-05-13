import networkx as nx
from datetime import datetime, timedelta
from typing import List, Dict, Optional
import json

class CorrelationEngine:
    def __init__(self):
        self.graph = nx.DiGraph()
        self.time_window = timedelta(hours=24)

    def add_event(self, event: Dict):
        """Add an event to the correlation graph"""
        event_id = event['id']
        self.graph.add_node(event_id, **event)

        # Find potential correlations
        self._correlate_by_time(event)
        self._correlate_by_entity(event)
        self._correlate_by_tactic(event)

    def _correlate_by_time(self, event: Dict):
        """Correlate events within time window"""
        event_time = datetime.fromisoformat(event['timestamp'])

        for node in self.graph.nodes():
            node_data = self.graph.nodes[node]
            node_time = datetime.fromisoformat(node_data['timestamp'])

            if abs(event_time - node_time) <= self.time_window:
                if self._should_correlate(event, node_data):
                    self.graph.add_edge(event['id'], node)

    def _correlate_by_entity(self, event: Dict):
        """Correlate events by common entities"""
        entities = {
            'user': event.get('user'),
            'host': event.get('host'),
            'process': event.get('process_id'),
            'session': event.get('session_id')
        }

        for node in self.graph.nodes():
            node_data = self.graph.nodes[node]
            for entity_type, value in entities.items():
                if value and value == node_data.get(entity_type):
                    self.graph.add_edge(event['id'], node)
                    break

    def _correlate_by_tactic(self, event: Dict):
        """Correlate events by MITRE tactics"""
        event_tactic = event.get('tactic')
        if not event_tactic:
            return

        for node in self.graph.nodes():
            node_data = self.graph.nodes[node]
            if node_data.get('tactic') == event_tactic:
                self.graph.add_edge(event['id'], node)

    def _should_correlate(self, event1: Dict, event2: Dict) -> bool:
        """Determine if two events should be correlated"""
        # Implement correlation logic based on:
        # - Common attributes
        # - Tactical relationships
        # - Known attack patterns
        return any([
            event1.get('user') == event2.get('user'),
            event1.get('host') == event2.get('host'),
            event1.get('process_id') == event2.get('process_id'),
            event1.get('tactic') == event2.get('tactic')
        ])

    def get_attack_timeline(self) -> List[Dict]:
        """Generate timeline of correlated events"""
        timeline = []

        # Sort nodes by timestamp
        sorted_nodes = sorted(
            self.graph.nodes(data=True),
            key=lambda x: datetime.fromisoformat(x[1]['timestamp'])
        )

        # Build timeline with correlation info
        for node_id, node_data in sorted_nodes:
            timeline_entry = {
                'id': node_id,
                'timestamp': node_data['timestamp'],
                'description': node_data.get('description', ''),
                'tactic': node_data.get('tactic', 'Unknown'),
                'technique': node_data.get('technique', 'Unknown'),
                'suspicion_score': node_data.get('suspicion_score', 0),
                'correlated_events': list(self.graph.neighbors(node_id))
            }
            timeline.append(timeline_entry)

        return timeline

    def export_mindmap(self) -> Dict:
        """Export correlation data as a mindmap structure"""
        mindmap = {
            'nodes': [],
            'edges': []
        }

        for node, data in self.graph.nodes(data=True):
            mindmap['nodes'].append({
                'id': node,
                'label': data.get('description', ''),
                'type': data.get('tactic', 'Unknown'),
                'score': data.get('suspicion_score', 0)
            })

        for edge in self.graph.edges():
            mindmap['edges'].append({
                'from': edge[0],
                'to': edge[1]
            })

        return mindmap