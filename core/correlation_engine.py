
import networkx as nx
from typing import List, Dict, Any
from dataclasses import dataclass
from datetime import datetime

@dataclass
class CorrelatedEvent:
    timestamp: datetime
    event_type: str
    tactic: str
    technique: str 
    source: str
    target: str
    suspicion_score: float
    details: Dict[str, Any]

class CorrelationEngine:
    def __init__(self):
        self.graph = nx.DiGraph()
        
    def correlate_events(self, events: List[Dict]) -> List[CorrelatedEvent]:
        """Correlate events based on common entities"""
        correlated = []
        
        # Group by common attributes
        entity_groups = self._group_by_entities(events)
        
        # Score and correlate each group
        for group in entity_groups:
            scored_events = self._score_events(group)
            correlated.extend(scored_events)
            
        return correlated
    
    def build_attack_timeline(self, events: List[CorrelatedEvent]) -> Dict:
        """Build timeline visualization data"""
        timeline = {
            "nodes": [],
            "edges": [],
            "phases": []
        }
        
        # Sort events chronologically
        sorted_events = sorted(events, key=lambda x: x.timestamp)
        
        # Build timeline structure
        current_phase = None
        for event in sorted_events:
            if event.tactic != current_phase:
                current_phase = event.tactic
                timeline["phases"].append({
                    "name": current_phase,
                    "start": event.timestamp.isoformat(),
                    "events": []
                })
            
            node = {
                "id": str(len(timeline["nodes"])),
                "label": event.event_type,
                "details": event.details,
                "score": event.suspicion_score,
                "tactic": event.tactic,
                "technique": event.technique
            }
            timeline["nodes"].append(node)
            timeline["phases"][-1]["events"].append(node["id"])
            
        return timeline
    
    def build_investigation_mindmap(self, events: List[CorrelatedEvent], 
                                  central_entity: str,
                                  max_nodes: int = 50) -> Dict:
        """Build mindmap visualization centered on an entity"""
        # Clear existing graph
        self.graph.clear()
        
        # Add central node
        self.graph.add_node(central_entity, 
                          type="central",
                          details={"type": "entity"})
        
        # Sort events by suspicion score and limit
        sorted_events = sorted(events, 
                             key=lambda x: x.suspicion_score,
                             reverse=True)[:max_nodes]
        
        # Build graph structure
        for event in sorted_events:
            # Add event node
            event_id = f"event_{len(self.graph)}"
            self.graph.add_node(event_id,
                              type="event",
                              details=event.details,
                              score=event.suspicion_score,
                              tactic=event.tactic,
                              technique=event.technique)
            
            # Connect to central node if related
            if event.source == central_entity or event.target == central_entity:
                self.graph.add_edge(central_entity, event_id)
            
            # Add related entity nodes
            for entity in [event.source, event.target]:
                if entity != central_entity:
                    self.graph.add_node(entity, 
                                      type="entity",
                                      details={"type": "related"})
                    self.graph.add_edge(event_id, entity)
        
        return self._graph_to_viz_format()
    
    def _group_by_entities(self, events: List[Dict]) -> List[List[Dict]]:
        """Group events by common entities (users, hosts, processes)"""
        groups = {}
        
        for event in events:
            key_entities = self._extract_key_entities(event)
            
            for entity in key_entities:
                if entity not in groups:
                    groups[entity] = []
                groups[entity].append(event)
                
        return list(groups.values())
    
    def _extract_key_entities(self, event: Dict) -> List[str]:
        """Extract key entities from event"""
        entities = []
        
        # Extract user
        if 'user' in event:
            entities.append(f"user:{event['user']}")
            
        # Extract host
        if 'host' in event:
            entities.append(f"host:{event['host']}")
            
        # Extract process
        if 'process_id' in event:
            entities.append(f"process:{event['process_id']}")
            
        return entities
    
    def _score_events(self, events: List[Dict]) -> List[CorrelatedEvent]:
        """Score events based on suspicion level"""
        scored = []
        
        for event in events:
            # Calculate base score
            score = 0
            
            # Score based on MITRE tactic
            tactic = event.get('tactic', '')
            if tactic in ['Execution', 'Persistence', 'PrivilegeEscalation']:
                score += 30
            elif tactic in ['Defense Evasion', 'Credential Access']:
                score += 40
            elif tactic in ['Discovery', 'Lateral Movement']:
                score += 20
                
            # Score based on target process
            target = event.get('target_process', '').lower()
            if 'lsass' in target:
                score += 50
            elif 'powershell' in target:
                score += 30
                
            # Normalize score
            score = min(score, 100)
            
            # Create correlated event
            corr_event = CorrelatedEvent(
                timestamp=datetime.fromisoformat(event['timestamp']),
                event_type=event.get('event_type', 'unknown'),
                tactic=tactic,
                technique=event.get('technique', ''),
                source=event.get('source', ''),
                target=event.get('target', ''),
                suspicion_score=score,
                details=event
            )
            scored.append(corr_event)
            
        return scored
    
    def _graph_to_viz_format(self) -> Dict:
        """Convert NetworkX graph to visualization format"""
        return {
            "nodes": [
                {
                    "id": node_id,
                    "label": str(node_id),
                    **self.graph.nodes[node_id]
                }
                for node_id in self.graph.nodes()
            ],
            "edges": [
                {
                    "from": u,
                    "to": v
                }
                for (u, v) in self.graph.edges()
            ]
        }
