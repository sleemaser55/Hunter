from typing import List, Dict, Any
from datetime import datetime
import networkx as nx

class CorrelationEngine:
    def __init__(self):
        self.graph = nx.DiGraph()

    def correlate_events(self, events: List[Dict[str, Any]]) -> Dict:
        """Correlate events based on common attributes and temporal relationships"""
        correlated = {}

        # Sort events by timestamp
        sorted_events = sorted(events, key=lambda x: x.get('_time', datetime.min))

        # Group by entities
        for event in sorted_events:
            self._add_event_to_graph(event)

        # Find connected components
        correlated['chains'] = self._find_attack_chains()
        correlated['timeline'] = self._build_timeline(sorted_events)

        return correlated

    def _add_event_to_graph(self, event: Dict):
        """Add event to correlation graph with edges based on relationships"""
        event_id = event.get('_raw', '')[:32]  # Use truncated raw as unique ID
        self.graph.add_node(event_id, **event)

        # Add edges based on common attributes
        for existing_id in self.graph.nodes():
            if existing_id != event_id:
                if self._events_are_related(event, self.graph.nodes[existing_id]):
                    self.graph.add_edge(existing_id, event_id)

    def _events_are_related(self, event1: Dict, event2: Dict) -> bool:
        """Check if events are related based on common attributes"""
        common_fields = ['user', 'host', 'process_guid', 'parent_process_guid']
        return any(
            event1.get(field) == event2.get(field)
            for field in common_fields
            if event1.get(field) and event2.get(field)
        )

    def _find_attack_chains(self, collapse_threshold: int = 200, time_window: int = 60, suspicion_threshold: float = 50.0) -> List[List[Dict]]:
        """Find attack chains with improved scoring and noise reduction"""
        chains = []
        for component in nx.weakly_connected_components(self.graph):
            chain = []
            subgraph = self.graph.subgraph(component)

            # Group events by time windows
            events_by_time = {}
            for node in nx.topological_sort(subgraph):
                event = self.graph.nodes[node]
                timestamp = event.get('_time', 0)
                window_key = int(timestamp / time_window)
                if window_key not in events_by_time:
                    events_by_time[window_key] = []
                events_by_time[window_key].append(event)

            # Collapse events if threshold exceeded
            for window_events in events_by_time.values():
                if len(window_events) > collapse_threshold:
                    # Create summary node
                    summary = {
                        'type': 'summary',
                        'count': len(window_events),
                        'command': window_events[0].get('command', 'activity'),
                        'start_time': min(e.get('_time', 0) for e in window_events),
                        'end_time': max(e.get('_time', 0) for e in window_events),
                        'events': window_events
                    }
                    chain.append(summary)
                else:
                    chain.extend(window_events)

            chains.append(chain)
        return chains

    def _build_timeline(self, events: List[Dict]) -> Dict:
        """Build a timeline of events grouped by MITRE tactics"""
        timeline = {
            'events': events,
            'tactics': {},
            'techniques': {}
        }

        for event in events:
            tactic = event.get('mitre_tactic', 'unknown')
            technique = event.get('mitre_technique', 'unknown')

            if tactic not in timeline['tactics']:
                timeline['tactics'][tactic] = []
            timeline['tactics'][tactic].append(event)

            if technique not in timeline['techniques']:
                timeline['techniques'][technique] = []
            timeline['techniques'][technique].append(event)

        return timeline