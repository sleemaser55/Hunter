import networkx as nx
from datetime import datetime
from typing import Dict, List, Optional

class CorrelationEngine:
    def __init__(self):
        self.graph = nx.DiGraph()

    def correlate_events(self, events: List[Dict]) -> Dict:
        """Correlate events and build attack timeline"""
        timeline = {}
        correlations = {}

        # Group by MITRE tactic/technique
        for event in events:
            tactic = event.get('tactic', 'Unknown')
            if tactic not in timeline:
                timeline[tactic] = []
            timeline[tactic].append(event)

        # Build entity correlations
        entity_types = ['user', 'host', 'process', 'ip']
        for entity_type in entity_types:
            correlations[entity_type] = self._correlate_by_entity(events, entity_type)

        return {
            'timeline': timeline,
            'correlations': correlations,
            'mindmap': self._build_mindmap(events)
        }

    def _correlate_by_entity(self, events: List[Dict], entity_type: str) -> Dict:
        """Group events by entity type (user, host, process, etc)"""
        correlations = {}
        for event in events:
            entity = event.get(entity_type)
            if entity:
                if entity not in correlations:
                    correlations[entity] = []
                correlations[entity].append(event)
        return correlations

    def _build_mindmap(self, events: List[Dict]) -> Dict:
        """Build visual mindmap of correlated events"""
        mindmap = {'nodes': [], 'links': []}

        # Add central node
        mindmap['nodes'].append({
            'id': 'root',
            'label': 'Investigation',
            'type': 'root'
        })

        # Add event nodes and links
        for i, event in enumerate(events):
            node_id = f'event_{i}'
            mindmap['nodes'].append({
                'id': node_id,
                'label': event.get('description', 'Unknown Event'),
                'type': event.get('tactic', 'unknown'),
                'suspicion_score': event.get('suspicion_score', 0)
            })
            mindmap['links'].append({
                'source': 'root',
                'target': node_id,
                'type': 'contains'
            })

        return mindmap

    def calculate_suspicion_score(self, event: Dict) -> float:
        """Calculate suspicion score based on various factors"""
        score = 0.0

        # Base score from MITRE tactic
        tactic_scores = {
            'Execution': 0.6,
            'Persistence': 0.7,
            'PrivilegeEscalation': 0.8,
            'DefenseEvasion': 0.8,
            'CredentialAccess': 0.9,
            'Discovery': 0.4,
            'LateralMovement': 0.8,
            'Collection': 0.7,
            'Exfiltration': 0.9,
            'CommandAndControl': 0.9
        }

        score += tactic_scores.get(event.get('tactic', ''), 0.5)

        # Adjust based on other factors
        if event.get('privileged_access', False):
            score += 0.2
        if event.get('rare_process', False):
            score += 0.1
        if event.get('known_malicious', False):
            score += 0.3

        return min(score, 1.0)