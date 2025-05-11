"""
Visualization utilities for Security Hunter
Provides functions to visualize query results in various formats
"""
import logging
import json
import re
import networkx as nx
import datetime
import math
from collections import defaultdict
from typing import List, Dict, Any, Optional, Set, Tuple, Union

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
    def generate_mitre_killchain_mapping(results: List[Dict[str, Any]],
                                     mitre_matrix: Dict[str, Dict[str, Any]],
                                     highlight_type: str = "frequency") -> Dict[str, Any]:
        """
        Generate a MITRE/Kill Chain categorization visualization from query results
        
        Args:
            results: List of result dictionaries
            mitre_matrix: Dictionary with MITRE ATT&CK matrix data
            highlight_type: How to highlight techniques ("frequency", "severity", or "confidence")
            
        Returns:
            Dictionary with nodes and edges for visualization
        """
        if not results or not mitre_matrix:
            return {"nodes": [], "edges": []}
            
        # Extract tactics and techniques
        tactics = {}
        techniques = {}
        
        # Build the kill chain structure
        for tactic_id, tactic_data in mitre_matrix.get("tactics", {}).items():
            tactics[tactic_id] = {
                "id": tactic_id,
                "name": tactic_data.get("name", "Unknown"),
                "description": tactic_data.get("description", ""),
                "url": tactic_data.get("url", ""),
                "techniques": []
            }
            
        for technique_id, technique_data in mitre_matrix.get("techniques", {}).items():
            techniques[technique_id] = {
                "id": technique_id,
                "name": technique_data.get("name", "Unknown"),
                "description": technique_data.get("description", ""),
                "tactics": technique_data.get("tactics", []),
                "url": technique_data.get("url", ""),
                "severity": technique_data.get("severity", "medium"),
                "count": 0,
                "subtechniques": []
            }
            
            # Add to parent tactics
            for tactic_id in technique_data.get("tactics", []):
                if tactic_id in tactics:
                    tactics[tactic_id]["techniques"].append(technique_id)
                    
        # Count occurrences of techniques in results
        for result in results:
            # Check for mitre_technique_id in the result
            technique_id = result.get("mitre_technique_id", None)
            if technique_id and technique_id in techniques:
                techniques[technique_id]["count"] += 1
                continue
                
            # Check for rule_mitre_id in the result
            rule_technique_id = result.get("rule_mitre_id", None)
            if rule_technique_id and rule_technique_id in techniques:
                techniques[rule_technique_id]["count"] += 1
                continue
                
            # Check for mitre_technique_name in the result
            technique_name = result.get("mitre_technique_name", None)
            if technique_name:
                for tid, tdata in techniques.items():
                    if tdata["name"].lower() == technique_name.lower():
                        techniques[tid]["count"] += 1
                        break
        
        # Create nodes and edges for visualization
        nodes = []
        edges = []
        
        # Add root node
        root_node = {
            "id": "root",
            "label": "ATT&CK Matrix",
            "group": "root",
            "shape": "diamond",
            "size": 25,
            "color": {
                "background": "#673AB7",
                "border": "#512DA8",
                "highlight": {
                    "background": "#7E57C2",
                    "border": "#512DA8"
                }
            }
        }
        nodes.append(root_node)
        
        # Add tactic nodes
        for tactic_id, tactic_data in tactics.items():
            tactic_node = {
                "id": tactic_id,
                "label": tactic_data["name"],
                "title": tactic_data["description"],
                "group": "tactic",
                "shape": "box",
                "size": 20,
                "color": {
                    "background": "#2196F3",
                    "border": "#1976D2",
                    "highlight": {
                        "background": "#42A5F5",
                        "border": "#1976D2"
                    }
                },
                "url": tactic_data["url"]
            }
            nodes.append(tactic_node)
            
            # Connect to root
            edges.append({
                "from": "root",
                "to": tactic_id,
                "width": 2,
                "arrows": {
                    "to": {
                        "enabled": True,
                        "type": "arrow"
                    }
                },
                "color": {
                    "color": "#9E9E9E",
                    "opacity": 0.8
                }
            })
            
        # Add technique nodes with appropriate highlighting
        max_count = max([t["count"] for t in techniques.values()]) if techniques.values() else 1
        for technique_id, technique_data in techniques.items():
            # Skip techniques that aren't detected
            if highlight_type == "frequency" and technique_data["count"] == 0:
                continue
                
            # Calculate node size and color based on highlight type
            if highlight_type == "frequency":
                size = 10 + (technique_data["count"] / max_count) * 20
                # Color from green to red based on frequency
                color_intensity = min(1, technique_data["count"] / max_count)
                r = int(255 * color_intensity)
                g = int(255 * (1 - color_intensity))
                b = 0
                color = f"rgb({r},{g},{b})"
                border_color = f"rgb({max(0, r-40)},{max(0, g-40)},{b})"
            elif highlight_type == "severity":
                size = 15
                # Color based on severity
                severity_colors = {
                    "low": "#4CAF50",
                    "medium": "#FFC107", 
                    "high": "#FF5722",
                    "critical": "#F44336"
                }
                color = severity_colors.get(technique_data["severity"], "#9E9E9E")
                border_color = color
            else:  # confidence
                size = 15
                # Default color
                color = "#9C27B0"
                border_color = "#7B1FA2"
            
            technique_node = {
                "id": technique_id,
                "label": technique_data["name"],
                "title": technique_data["description"],
                "group": "technique",
                "shape": "ellipse",
                "size": size,
                "color": {
                    "background": color,
                    "border": border_color,
                    "highlight": {
                        "background": color,
                        "border": border_color
                    }
                },
                "count": technique_data["count"],
                "severity": technique_data["severity"],
                "url": technique_data["url"]
            }
            nodes.append(technique_node)
            
            # Connect to tactics
            for tactic_id in technique_data["tactics"]:
                if tactic_id in tactics:
                    edges.append({
                        "from": tactic_id,
                        "to": technique_id,
                        "width": 1 + (technique_data["count"] / max_count) * 3,
                        "arrows": {
                            "to": {
                                "enabled": True,
                                "type": "arrow"
                            }
                        },
                        "color": {
                            "opacity": 0.6,
                            "color": color
                        }
                    })
        
        return {
            "nodes": nodes,
            "edges": edges,
            "options": {
                "layout": {
                    "hierarchical": {
                        "enabled": True,
                        "direction": "UD",
                        "sortMethod": "directed",
                        "levelSeparation": 150
                    }
                },
                "physics": {
                    "hierarchicalRepulsion": {
                        "nodeDistance": 150
                    },
                    "stabilization": {
                        "iterations": 100
                    }
                }
            }
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
                        entity_field: Optional[str] = None,
                        mode: str = "grouped",
                        branch_fields: Optional[List[str]] = None,
                        connection_fields: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Generate a timeline visualization from query results
        
        Args:
            results: List of result dictionaries
            timestamp_field: Field containing timestamp information
            entity_field: Optional field to group events by (e.g., host, user)
            mode: Visualization mode (grouped, branch, or ungrouped)
            branch_fields: List of fields to create as timeline branches (for branch mode)
            connection_fields: List of fields to use for connecting related events
            
        Returns:
            Dictionary with timeline visualization data
        """
        if not results:
            return {"items": []}
        
        # Convert optional parameters to empty lists if None
        branch_fields = branch_fields or []
        connection_fields = connection_fields or []
        
        # Standard timeline mode (grouped by entity)
        if mode == "grouped":
            return Visualizer._generate_grouped_timeline(
                results, timestamp_field, entity_field
            )
        
        # Field branch timeline mode
        elif mode == "branch":
            return Visualizer._generate_branch_timeline(
                results, timestamp_field, branch_fields, connection_fields
            )
            
        # Non-grouped timeline mode with network visualization
        elif mode == "ungrouped":
            return Visualizer._generate_ungrouped_timeline(
                results, timestamp_field, connection_fields
            )
            
        # Fallback to standard grouped timeline
        else:
            return Visualizer._generate_grouped_timeline(
                results, timestamp_field, entity_field
            )
    
    @staticmethod
    def _generate_grouped_timeline(results: List[Dict[str, Any]],
                               timestamp_field: str = "_time",
                               entity_field: Optional[str] = None) -> Dict[str, Any]:
        """
        Generate a standard grouped timeline visualization
        
        Args:
            results: List of result dictionaries
            timestamp_field: Field containing timestamp information
            entity_field: Optional field to group events by
            
        Returns:
            Dictionary with timeline items and groups
        """
        if not results:
            return {"items": []}
        
        # Generate timeline items
        items = []
        item_id = 0
        groups = {}
        
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
                
                # Add to groups dictionary if not exists
                if group and group not in groups:
                    groups[group] = {
                        "id": group,
                        "content": f"{entity_field}: {group}"
                    }
            
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
        
        # Return timeline items and groups
        return {
            "items": items,
            "groups": list(groups.values())
        }
    
    @staticmethod
    def _generate_ungrouped_timeline(results: List[Dict[str, Any]],
                                 timestamp_field: str = "_time",
                                 connection_fields: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Generate a non-grouped timeline with network visualization
        
        Args:
            results: List of result dictionaries
            timestamp_field: Field containing timestamp information
            connection_fields: List of fields to use for connecting related events
            
        Returns:
            Dictionary with nodes and edges for network visualization
        """
        if not results:
            return {"nodes": [], "edges": []}
        
        # Initialize nodes and edges
        nodes = []
        edges = []
        node_count = 0
        
        # Create timeline axis node
        timeline_node = {
            "id": "timeline_axis",
            "label": "Timeline",
            "group": "axis",
            "shape": "box",
            "fixed": True,
            "physics": False,
            "x": 0,
            "y": 0
        }
        nodes.append(timeline_node)
        
        # Process results chronologically
        events_by_time = []
        event_nodes_by_id = {}
        
        for result in results:
            # Skip if timestamp field is missing
            if timestamp_field not in result or not result[timestamp_field]:
                continue
            
            # Parse timestamp
            timestamp = result[timestamp_field]
            event_time = None
            
            try:
                # Splunk _time format (Unix epoch)
                if isinstance(timestamp, (int, float)):
                    event_time = datetime.datetime.fromtimestamp(timestamp)
                else:
                    # Try common time formats
                    for fmt in ["%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d %H:%M:%S"]:
                        try:
                            event_time = datetime.datetime.strptime(timestamp, fmt)
                            break
                        except ValueError:
                            continue
            except Exception as e:
                logger.warning(f"Could not parse timestamp '{timestamp}': {str(e)}")
                continue
            
            if not event_time:
                continue
            
            # Track event for chronological ordering
            events_by_time.append((event_time, result, node_count))
            node_count += 1
        
        # Sort events by time
        events_by_time.sort(key=lambda x: x[0])
        
        # Create nodes and position them horizontally by time
        x_spacing = 100
        for i, (event_time, result, idx) in enumerate(events_by_time):
            # Generate node content
            event_type = Visualizer._determine_event_type(result)
            event_label = Visualizer._generate_event_label(result)
            
            # Create node
            node_id = f"event_{idx}"
            node = {
                "id": node_id,
                "label": event_label,
                "title": json.dumps(result, indent=2),
                "group": event_type,
                "event": result,
                "timestamp": event_time.isoformat(),
                "x": (i + 1) * x_spacing,  # Horizontal position by time
                "y": 0,                    # Initially on timeline axis
                "size": 10,                # Default size
                "fixed": True,             # Fixed position
                "physics": False           # No physics simulation
            }
            
            # Add event fields as node properties for hunting
            for field, value in result.items():
                if field != "_raw" and not isinstance(value, (dict, list)):
                    try:
                        node[field] = str(value)
                    except:
                        pass
            
            # Store node for connections
            event_nodes_by_id[node_id] = node
        
        # Connect events to timeline axis
        for node_id, node in event_nodes_by_id.items():
            edges.append({
                "from": "timeline_axis",
                "to": node_id,
                "arrows": "",
                "color": {
                    "opacity": 0.3
                }
            })
        
        # Connect related events by field values
        if connection_fields:
            # Track nodes that have connections to adjust their position
            connected_nodes = set()
            
            # Set y-offset for connected nodes
            y_offset = 100
            
            # Process each connection field
            for field in connection_fields:
                # Track events by field value
                field_value_map = {}
                
                # Group events by field value
                for node_id, node in event_nodes_by_id.items():
                    result = node["event"]
                    if field in result and result[field]:
                        value = str(result[field])
                        
                        if value not in field_value_map:
                            field_value_map[value] = []
                        
                        field_value_map[value].append(node_id)
                
                # Create connections for shared field values
                for value, node_ids in field_value_map.items():
                    # Skip if only one event has this value
                    if len(node_ids) <= 1:
                        continue
                    
                    # Mark these nodes as connected and adjust y position
                    for node_id in node_ids:
                        connected_nodes.add(node_id)
                        
                        # Move connected nodes below the timeline
                        node = event_nodes_by_id[node_id]
                        node["y"] = y_offset
                    
                    # Connect all nodes with this field value
                    for i in range(len(node_ids) - 1):
                        for j in range(i + 1, len(node_ids)):
                            source_id = node_ids[i]
                            target_id = node_ids[j]
                            
                            # Draw connection between related nodes
                            edges.append({
                                "from": source_id,
                                "to": target_id,
                                "label": field,
                                "font": {
                                    "size": 8,
                                    "color": "#ffffff"
                                },
                                "title": f"Shared {field}: {value}",
                                "color": {
                                    "color": "#2196F3",
                                    "opacity": 0.8
                                },
                                "arrows": {
                                    "to": {
                                        "enabled": True,
                                        "type": "arrow"
                                    }
                                },
                                "width": 1,
                                "dashes": [5, 5]
                            })
            
            # Adjust vertical position for unconnected nodes
            for node_id, node in event_nodes_by_id.items():
                if node_id not in connected_nodes:
                    # Leave unconnected nodes on the timeline
                    pass
                else:
                    # Adjust size of connected nodes to make them more visible
                    node["size"] = 15
                    node["color"] = {
                        "border": "#f44336",
                        "background": "#f44336",
                        "highlight": {
                            "border": "#f44336",
                            "background": "#f44336"
                        }
                    }
        
        # Add all event nodes to the final nodes list
        for node_id, node in event_nodes_by_id.items():
            nodes.append(node)
        
        # Return nodes and edges with layout information
        return {
            "nodes": nodes,
            "edges": edges,
            "layout": {
                "hierarchical": {
                    "enabled": False
                }
            },
            "physics": {
                "enabled": False
            },
            "interaction": {
                "hover": True,
                "dragNodes": True,
                "dragView": True,
                "zoomView": True
            }
        }
        
        # Return nodes and edges
        return {
            "nodes": nodes,
            "edges": edges
        }
    
    @staticmethod
    def _generate_branch_timeline(results: List[Dict[str, Any]],
                              timestamp_field: str = "_time",
                              branch_fields: Optional[List[str]] = None,
                              connection_fields: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Generate a timeline with horizontal branches for different fields
        
        Args:
            results: List of result dictionaries
            timestamp_field: Field containing timestamp information
            branch_fields: List of fields to create branches for (one horizontal line per field)
            connection_fields: List of fields to use for connecting related events across branches
            
        Returns:
            Dictionary with nodes and edges for network visualization
        """
        if not results:
            return {"nodes": [], "edges": []}
        
        # Use default branch fields if none provided
        if not branch_fields:
            # Try to detect common fields for branches
            field_counts = {}
            for result in results:
                for field, value in result.items():
                    if field.startswith('_') or field == timestamp_field:
                        continue
                    if value:
                        if field not in field_counts:
                            field_counts[field] = 0
                        field_counts[field] += 1
            
            # Select fields that appear frequently
            branch_fields = [field for field, count in field_counts.items() 
                           if count >= min(5, len(results) / 2)][:5]  # Limit to top 5 fields
        
        if not branch_fields:
            # Still no branch fields - use default fields
            branch_fields = ["host", "user", "process", "source", "dest"]
        
        # Initialize nodes and edges
        nodes = []
        edges = []
        node_count = 0
        
        # Track connected nodes for highlighting
        connected_nodes = set()
        
        # Track node positions for visual layout
        branch_y_positions = {}
        vertical_spacing = 100
        
        # Create timeline axis node
        timeline_node = {
            "id": "timeline_axis",
            "label": "Timeline",
            "group": "axis",
            "shape": "box",
            "fixed": True,
            "physics": False,
            "x": 0,
            "y": 0
        }
        nodes.append(timeline_node)
        
        # Create field branch nodes (horizontal lines)
        branch_nodes = {}
        for i, field in enumerate(branch_fields):
            y_position = (i + 1) * vertical_spacing
            branch_y_positions[field] = y_position
            
            branch_node_id = f"branch_{field}"
            branch_node = {
                "id": branch_node_id,
                "label": field,
                "title": f"Field: {field}",
                "group": "field",
                "shape": "box",
                "fixed": True,
                "physics": False,
                "x": 0,
                "y": y_position
            }
            nodes.append(branch_node)
            branch_nodes[field] = branch_node_id
        
        # Process results and create event nodes
        event_nodes_by_field = {}  # Track event nodes by field and value for connections
        event_nodes_by_id = {}     # Map node IDs to nodes
        events_by_time = []        # Sort events by time for x-axis positioning
        
        for result in results:
            # Skip if timestamp field is missing
            if timestamp_field not in result or not result[timestamp_field]:
                continue
            
            # Parse timestamp
            timestamp = result[timestamp_field]
            event_time = None
            
            try:
                # Splunk _time format (Unix epoch)
                if isinstance(timestamp, (int, float)):
                    event_time = datetime.datetime.fromtimestamp(timestamp)
                else:
                    # Try common time formats
                    for fmt in ["%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d %H:%M:%S"]:
                        try:
                            event_time = datetime.datetime.strptime(timestamp, fmt)
                            break
                        except ValueError:
                            continue
            except Exception as e:
                logger.warning(f"Could not parse timestamp '{timestamp}': {str(e)}")
                continue
            
            if not event_time:
                continue
            
            # Track event for positioning
            events_by_time.append((event_time, result, node_count))
            
            # Generate node content
            event_type = Visualizer._determine_event_type(result)
            event_label = Visualizer._generate_event_label(result)
            
            # Create event node - x position will be set later after sorting
            event_node_id = f"event_{node_count}"
            event_node = {
                "id": event_node_id,
                "label": event_label,
                "title": json.dumps(result, indent=2),
                "group": event_type,
                "event": result,
                "timestamp": event_time.isoformat(),
                "y": 0  # Will be positioned later
            }
            
            # Add event fields as node properties for filtering and hunting
            for field, value in result.items():
                if field != "_raw" and not isinstance(value, (dict, list)):
                    try:
                        event_node[field] = str(value)
                    except:
                        pass
            
            # Store node for later positioning and connections
            event_nodes_by_id[event_node_id] = event_node
            node_count += 1
            
            # Track nodes by field values for making connections
            for field in branch_fields:
                if field in result and result[field]:
                    value = str(result[field])
                    
                    if field not in event_nodes_by_field:
                        event_nodes_by_field[field] = {}
                    
                    if value not in event_nodes_by_field[field]:
                        event_nodes_by_field[field][value] = []
                    
                    event_nodes_by_field[field][value].append(event_node_id)
        
        # Sort events by time for x-axis positioning
        events_by_time.sort(key=lambda x: x[0])
        
        # Set x positions based on time sequence
        x_spacing = 100
        for i, (event_time, result, _) in enumerate(events_by_time):
            event_node_id = f"event_{_}"
            event_node = event_nodes_by_id[event_node_id]
            
            # Set x position 
            event_node["x"] = (i + 1) * x_spacing
            
            # Determine y position based on which branch it belongs to
            for field in branch_fields:
                if field in result and result[field]:
                    # Position on the branch line
                    event_node["y"] = branch_y_positions[field]
                    
                    # Connect to branch node
                    edges.append({
                        "from": branch_nodes[field],
                        "to": event_node_id,
                        "arrows": "",
                        "color": {
                            "opacity": 0.3
                        }
                    })
                    
                    # Only attach to one branch (first match)
                    break
        
        # Connect related events across branches based on connection fields
        if connection_fields:
            # Track nodes with connections for visual highlighting
            connected_nodes = set()
            
            # Create connections by field values
            field_value_map = {}
            
            # Organize events by field value
            for field in connection_fields:
                field_value_map[field] = {}
                
                for result_idx, (_, result, _) in enumerate(events_by_time):
                    if field not in result or not result[field]:
                        continue
                    
                    event_node_id = f"event_{events_by_time[result_idx][2]}"
                    value = str(result[field])
                    
                    if value not in field_value_map[field]:
                        field_value_map[field][value] = []
                    
                    field_value_map[field][value].append({
                        'node_id': event_node_id,
                        'timestamp': events_by_time[result_idx][0],
                        'result': result
                    })
            
            # Create connections between events with shared field values
            for field in connection_fields:
                # Create distinct color for each field's connections
                field_colors = {
                    'user': '#e91e63',      # Pink
                    'host': '#2196f3',      # Blue
                    'src_ip': '#4caf50',    # Green
                    'dest_ip': '#ff9800',   # Orange
                    'process': '#9c27b0',   # Purple
                    'command': '#795548',   # Brown
                    'service': '#607d8b'    # Blue-gray
                }
                
                connection_color = field_colors.get(field, '#f44336')  # Default to red
                
                for value, events in field_value_map[field].items():
                    # Skip if only one event has this value
                    if len(events) <= 1:
                        continue
                    
                    # Sort events by timestamp
                    events.sort(key=lambda x: x['timestamp'])
                    
                    # Connect events chronologically and mark them as connected
                    for i in range(len(events) - 1):
                        source_event = events[i]
                        target_event = events[i + 1]
                        
                        # Mark nodes as connected for visual highlighting
                        connected_nodes.add(source_event['node_id'])
                        connected_nodes.add(target_event['node_id'])
                        
                        # Connect the two event nodes
                        edges.append({
                            "from": source_event['node_id'],
                            "to": target_event['node_id'],
                            "title": f"Shared {field}: {value}",
                            "label": field,
                            "font": {
                                "size": 8,
                                "color": "#ffffff"
                            },
                            "color": {
                                "color": connection_color,
                                "opacity": 0.8
                            },
                            "arrows": {
                                "to": {
                                    "enabled": True,
                                    "type": "arrow"
                                }
                            },
                            "dashes": [5, 5],
                            "width": 2,
                            "field": field,
                            "value": value,
                            "selectionWidth": 3
                        })
                        
                        # Create cross-branch connecting events if they appear on different branches
                        source_field = None
                        target_field = None
                        
                        # Find which branch each event belongs to
                        for bf in branch_fields:
                            if bf in source_event['result'] and source_event['result'][bf]:
                                source_field = bf
                            if bf in target_event['result'] and target_event['result'][bf]:
                                target_field = bf
                        
                        # If events are on different branches, add a visual indicator
                        if source_field != target_field and source_field is not None and target_field is not None:
                            # Brighten the connection to highlight cross-branch connections
                            edges[-1]["width"] = 3
                            edges[-1]["color"]["opacity"] = 1.0
        
        # Add all event nodes to the final nodes list with visual enhancements for connected nodes
        for node_id, node in event_nodes_by_id.items():
            # Check if the connected_nodes variable exists and if the node is in it
            if connection_fields and node_id in connected_nodes:
                # Make connected nodes more visible
                node["size"] = 15
                node["borderWidth"] = 2
                node["color"] = {
                    "border": "#2196F3",  # Blue border
                    "background": "#2196F3",
                    "highlight": {
                        "border": "#1976D2",  # Darker blue on highlight
                        "background": "#42A5F5"  # Lighter blue on highlight
                    }
                }
            
            nodes.append(node)
        
        # Return nodes and edges with layout information
        return {
            "nodes": nodes,
            "edges": edges,
            "layout": {
                "hierarchical": {
                    "enabled": False
                }
            },
            "physics": {
                "enabled": False
            },
            "interaction": {
                "hover": True,
                "dragNodes": True,
                "dragView": True,
                "zoomView": True,
                "selectable": True,
                "multiselect": True
            }
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