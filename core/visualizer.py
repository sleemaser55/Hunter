"""
Visualization utilities for Security Hunter
Provides functions to visualize query results in various formats
"""
import logging
import json
import re
import networkx as nx
import datetime
from typing import List, Dict, Any, Optional, Set

logger = logging.getLogger(__name__)

class Visualizer:
    """
    Visualizer for security hunting results
    Provides functions to convert results to various visualization formats
    """
    
    @staticmethod
    def generate_pivot_mindmap(results: List[Dict[str, Any]], 
                             fields_of_interest: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Generate a pivot-based mind map visualization from query results
        
        Args:
            results: List of result dictionaries
            fields_of_interest: Optional list of fields to include as pivots
            
        Returns:
            Dictionary with nodes and edges for visualization
        """
        if not results:
            return {"nodes": [], "edges": []}
        
        # Detect important fields if not specified
        if not fields_of_interest:
            fields_of_interest = Visualizer._detect_important_fields(results)
        
        # Create a graph for visualization
        G = nx.Graph()
        
        # Create central node
        central_node = {
            "id": "center",
            "label": f"Results ({len(results)})",
            "title": f"{len(results)} total results",
            "group": "center",
            "shape": "dot",
            "size": 25
        }
        
        nodes = [central_node]
        edges = []
        
        # Track created nodes to avoid duplicates
        created_nodes = set()
        created_nodes.add("center")
        
        # Map field values and connect to central node
        node_counter = 0
        for field in fields_of_interest:
            # First level - field nodes
            field_id = f"field_{node_counter}"
            field_node = {
                "id": field_id,
                "label": field,
                "title": f"Field: {field}",
                "group": "field",
                "shape": "diamond"
            }
            nodes.append(field_node)
            created_nodes.add(field_id)
            
            # Connect field node to central node
            edges.append({
                "from": "center",
                "to": field_id,
                "value": 3
            })
            
            node_counter += 1
            
            # Second level - distinct values for each field
            field_values = {}
            for result in results:
                if field in result and result[field]:
                    value = str(result[field])
                    if value not in field_values:
                        field_values[value] = 0
                    field_values[value] += 1
            
            # Add value nodes with counts
            for value, count in field_values.items():
                # Create value node ID - ensure it's unique
                short_value = value[:30] + "..." if len(value) > 30 else value
                value_id = f"value_{node_counter}"
                
                # Create value node
                value_node = {
                    "id": value_id,
                    "label": short_value,
                    "title": f"{field}: {value} ({count} occurrences)",
                    "group": "value",
                    "field": field,
                    "value": value,
                    "count": count,
                    "shape": "box",
                    "size": min(20, 10 + count)
                }
                nodes.append(value_node)
                created_nodes.add(value_id)
                
                # Connect value node to field node
                edges.append({
                    "from": field_id,
                    "to": value_id,
                    "value": count,
                    "title": f"{count} occurrences"
                })
                
                node_counter += 1
        
        # Return nodes and edges for visualization
        return {
            "nodes": nodes,
            "edges": edges
        }
    
    @staticmethod
    def generate_ttp_mapping(results: List[Dict[str, Any]], 
                          mitre_techniques: Dict[str, Dict[str, Any]],
                          rule_mappings: Optional[Dict[str, List[Dict[str, Any]]]] = None) -> Dict[str, Any]:
        """
        Generate a TTP mapping visualization from query results and MITRE techniques
        
        Args:
            results: List of result dictionaries
            mitre_techniques: Dictionary of MITRE techniques
            rule_mappings: Optional mappings of results to MITRE technique IDs
            
        Returns:
            Dictionary with nodes and edges for visualization
        """
        if not results:
            return {"nodes": [], "edges": []}
        
        # Create a graph for visualization
        G = nx.DiGraph()
        
        nodes = []
        edges = []
        
        # Track created nodes to avoid duplicates
        created_nodes = set()
        
        # Add central results node
        central_node = {
            "id": "results",
            "label": f"Results ({len(results)})",
            "title": f"{len(results)} total results",
            "group": "results"
        }
        nodes.append(central_node)
        created_nodes.add("results")
        
        # Group techniques by tactic
        tactic_techniques = {}
        for technique_id, technique in mitre_techniques.items():
            if not technique:
                continue
                
            tactics = technique.get("tactics", [])
            for tactic in tactics:
                if tactic not in tactic_techniques:
                    tactic_techniques[tactic] = []
                
                if technique_id not in tactic_techniques[tactic]:
                    tactic_techniques[tactic].append(technique_id)
        
        # If we have rule mappings, add the techniques and their tactics
        if rule_mappings:
            for technique_id, technique_results in rule_mappings.items():
                # Get technique details if available
                technique = mitre_techniques.get(technique_id, {})
                
                if not technique:
                    continue
                
                # Create technique node
                if technique_id not in created_nodes:
                    technique_node = {
                        "id": technique_id,
                        "label": technique.get("name", technique_id),
                        "title": f"Technique: {technique.get('name', technique_id)}",
                        "technique_id": technique_id,
                        "description": technique.get("description", ""),
                        "group": "technique"
                    }
                    nodes.append(technique_node)
                    created_nodes.add(technique_id)
                    
                    # Connect technique to results
                    edges.append({
                        "from": "results",
                        "to": technique_id,
                        "title": f"{len(technique_results)} events match {technique_id}",
                        "value": len(technique_results)
                    })
                    
                    # Add tactics for this technique
                    tactics = technique.get("tactics", [])
                    for tactic in tactics:
                        tactic_id = tactic.replace(" ", "_").lower()
                        
                        # Create tactic node if it doesn't exist
                        if tactic_id not in created_nodes:
                            tactic_node = {
                                "id": tactic_id,
                                "label": tactic,
                                "title": f"Tactic: {tactic}",
                                "group": "tactic"
                            }
                            nodes.append(tactic_node)
                            created_nodes.add(tactic_id)
                        
                        # Connect technique to tactic
                        edges.append({
                            "from": tactic_id,
                            "to": technique_id,
                            "arrows": "to",
                            "dashes": True
                        })
        
        # Return nodes and edges for visualization
        return {
            "nodes": nodes,
            "edges": edges
        }
    
    @staticmethod
    def generate_timeline(results: List[Dict[str, Any]], 
                        timestamp_field: str = "_time",
                        entity_field: Optional[str] = None) -> Dict[str, Any]:
        """
        Generate a timeline visualization from query results
        
        Args:
            results: List of result dictionaries
            timestamp_field: Field containing timestamp information
            entity_field: Optional field to group events by (e.g., host, user)
            
        Returns:
            Dictionary with timeline visualization data
        """
        if not results:
            return {"items": []}
        
        # Generate timeline items
        items = []
        item_id = 0
        
        for result in results:
            # Skip if timestamp field is missing
            if timestamp_field not in result or not result[timestamp_field]:
                continue
            
            # Parse timestamp
            timestamp = result[timestamp_field]
            start_time = None
            
            # Try different timestamp formats
            try:
                # Splunk _time format (Unix epoch)
                if isinstance(timestamp, (int, float)):
                    start_time = datetime.datetime.fromtimestamp(timestamp)
                else:
                    # Try common time formats
                    for fmt in ["%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d %H:%M:%S"]:
                        try:
                            start_time = datetime.datetime.strptime(timestamp, fmt)
                            break
                        except ValueError:
                            continue
            except Exception as e:
                logger.warning(f"Could not parse timestamp '{timestamp}': {str(e)}")
                continue
            
            if not start_time:
                continue
            
            # Generate item content
            event_type = Visualizer._determine_event_type(result)
            event_label = Visualizer._generate_event_label(result)
            
            # Determine group (for entity-based grouping)
            group = None
            if entity_field and entity_field in result and result[entity_field]:
                group = str(result[entity_field])
            
            # Create timeline item
            item = {
                "id": item_id,
                "content": event_label,
                "start": start_time.isoformat(),
                "type": "box",
                "group": group,
                "title": json.dumps(result, indent=2),
                "event": result,
                "className": f"event-type-{event_type}"
            }
            
            # Add to items
            items.append(item)
            item_id += 1
        
        # Return timeline items
        return {
            "items": items
        }
    
    @staticmethod
    def _detect_important_fields(results: List[Dict[str, Any]]) -> List[str]:
        """
        Detect important fields for pivoting based on result content
        
        Args:
            results: List of result dictionaries
            
        Returns:
            List of field names deemed important for pivoting
        """
        if not results:
            return []
        
        # Count field occurrences and cardinality
        field_counts = {}
        field_values = {}
        
        for result in results:
            for field, value in result.items():
                # Skip empty values and internal fields
                if not value or field.startswith("_"):
                    continue
                
                # Count field occurrences
                if field not in field_counts:
                    field_counts[field] = 0
                    field_values[field] = set()
                
                field_counts[field] += 1
                field_values[field].add(str(value))
        
        # Calculate cardinality ratio (unique values / occurrences)
        field_cardinality = {}
        for field, count in field_counts.items():
            unique_values = len(field_values[field])
            cardinality_ratio = unique_values / count
            field_cardinality[field] = cardinality_ratio
        
        # Score fields based on occurrence and cardinality
        field_scores = {}
        for field, count in field_counts.items():
            cardinality_ratio = field_cardinality[field]
            
            # High occurrence is good
            occurrence_score = min(1.0, count / len(results))
            
            # Medium cardinality is good (not too many unique values, not too few)
            cardinality_score = 1.0 - abs(cardinality_ratio - 0.5) * 2.0
            
            # Known important field types
            importance_bonus = 0.0
            if any(term in field.lower() for term in ["user", "account", "host", "ip", "source", "dest", "target", "process", "file", "cmd", "command"]):
                importance_bonus = 0.5
            
            # Calculate final score
            field_scores[field] = (occurrence_score * 0.4) + (cardinality_score * 0.3) + importance_bonus
        
        # Select top-scoring fields (up to 8)
        top_fields = sorted(field_scores.keys(), key=lambda f: field_scores[f], reverse=True)[:8]
        
        return top_fields
    
    @staticmethod
    def _generate_event_label(event: Dict[str, Any]) -> str:
        """
        Generate a human-readable label for an event
        
        Args:
            event: Event dictionary
            
        Returns:
            Human-readable label
        """
        # Check for common fields to use in label
        for field in ["event_desc", "description", "message", "event_message", "command_line", "process_name"]:
            if field in event and event[field]:
                value = str(event[field])
                if len(value) > 50:
                    return value[:47] + "..."
                return value
        
        # Fall back to event type if available
        event_type = Visualizer._determine_event_type(event)
        
        # Check for source/destination for network events
        if event_type == "network":
            src = event.get("src_ip", event.get("source_ip", event.get("src_host", "")))
            dst = event.get("dst_ip", event.get("destination_ip", event.get("dst_host", "")))
            
            if src and dst:
                return f"Network: {src} → {dst}"
        
        # Check for process events
        elif event_type == "process":
            process = event.get("process_name", event.get("image", event.get("process_path", "")))
            if process:
                # Extract just the filename
                process_name = process.split("\\")[-1].split("/")[-1]
                return f"Process: {process_name}"
        
        # Check for authentication events
        elif event_type == "auth":
            user = event.get("user", event.get("username", event.get("account", "")))
            if user:
                return f"Auth: {user}"
        
        # Check for file events
        elif event_type == "file":
            file_path = event.get("file_path", event.get("target_filename", event.get("file_name", "")))
            if file_path:
                file_name = file_path.split("\\")[-1].split("/")[-1]
                return f"File: {file_name}"
        
        # Generic label with a few field:value pairs
        label_parts = []
        for field, value in event.items():
            if field.startswith("_") or field in ["_time", "timestamp", "time"]:
                continue
            
            if value and len(label_parts) < 3:
                value_str = str(value)
                if len(value_str) > 20:
                    value_str = value_str[:17] + "..."
                
                label_parts.append(f"{field}:{value_str}")
        
        if label_parts:
            return " | ".join(label_parts)
        
        # Last resort
        return f"Event {event.get('_time', '')}"
    
    @staticmethod
    def _determine_event_type(event: Dict[str, Any]) -> str:
        """
        Determine the type of event based on content
        
        Args:
            event: Event dictionary
            
        Returns:
            Event type string
        """
        # Network events
        if any(field in event for field in ["src_ip", "dst_ip", "source_ip", "destination_ip", "src_port", "dst_port"]):
            return "network"
        
        # Process events
        if any(field in event for field in ["process_name", "process_id", "command_line", "parent_process"]):
            return "process"
        
        # Authentication events
        if any(field in event for field in ["user", "username", "account_name", "logon_type", "authentication"]):
            return "auth"
        
        # File events
        if any(field in event for field in ["file_path", "file_name", "file_hash", "target_filename"]):
            return "file"
        
        # Registry events
        if any(field in event for field in ["registry_key", "registry_value", "registry_path"]):
            return "registry"
        
        # Default - other
        return "other"