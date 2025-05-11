import logging
import networkx as nx
import json
from typing import Dict, List, Any, Optional, Tuple
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import numpy as np

from core.mitre_parser import MitreAttackParser

logger = logging.getLogger(__name__)

class TTPMapper:
    """Map Splunk search results to potential MITRE ATT&CK techniques"""
    
    def __init__(self, mitre_parser = None):
        """
        Initialize the TTP mapper.
        
        Args:
            mitre_parser: Initialized MitreAttackParser instance
        """
        # Import here to avoid circular import issues
        from core.mitre_parser import MitreAttackParser
        self.mitre_parser = mitre_parser if mitre_parser is not None else MitreAttackParser()
        self.techniques = self.mitre_parser.get_techniques()
        self.vectorizer = TfidfVectorizer(stop_words='english')
        
        # Create technique corpus for text similarity
        technique_texts = []
        self.technique_ids = []
        
        for technique in self.techniques:
            text = f"{technique.get('name', '')} {technique.get('description', '')}"
            # Add any detection text if available
            if 'x_mitre_detection' in technique:
                text += f" {technique['x_mitre_detection']}"
            technique_texts.append(text)
            self.technique_ids.append(technique.get('id', ''))
        
        # Fit the vectorizer on technique descriptions
        if technique_texts:
            self.technique_matrix = self.vectorizer.fit_transform(technique_texts)
        else:
            logger.warning("No technique texts available for TTP mapping")
            self.technique_matrix = None
    
    def map_results_to_techniques(self, results: List[Dict[str, Any]], 
                                similarity_threshold: float = 0.2) -> Dict[str, Any]:
        """
        Map Splunk search results to potential MITRE ATT&CK techniques.
        
        Args:
            results: List of search result dictionaries
            similarity_threshold: Minimum similarity score to include a match
            
        Returns:
            Dictionary with mapping results and confidence scores
        """
        if not results or not self.technique_matrix:
            return {"mappings": []}
        
        # Extract all text from results
        result_texts = []
        for result in results:
            # Combine all textual fields
            text_values = []
            for key, value in result.items():
                if isinstance(value, str):
                    text_values.append(f"{key}: {value}")
            
            result_texts.append(" ".join(text_values))
        
        # Vectorize result texts
        try:
            result_vectors = self.vectorizer.transform(result_texts)
            
            # Calculate similarity between results and techniques
            similarity_matrix = cosine_similarity(result_vectors, self.technique_matrix)
            
            # Get top technique matches for each result
            mappings = []
            
            for i, result in enumerate(results):
                result_matches = []
                
                # Get techniques with similarity scores above threshold
                for j, score in enumerate(similarity_matrix[i]):
                    if score >= similarity_threshold:
                        technique_id = self.technique_ids[j]
                        technique = self.mitre_parser.get_technique_by_id(technique_id)
                        
                        if technique:
                            result_matches.append({
                                "technique_id": technique_id,
                                "technique_name": technique.get("name", ""),
                                "similarity_score": float(score),
                                "tactics": [t.get("name") for t in technique.get("tactics", [])]
                            })
                
                # Sort matches by similarity score descending
                result_matches.sort(key=lambda x: x["similarity_score"], reverse=True)
                
                # Take top 5 matches
                top_matches = result_matches[:5]
                
                mappings.append({
                    "result_index": i,
                    "matches": top_matches
                })
            
            return {
                "mappings": mappings
            }
            
        except Exception as e:
            logger.error(f"Error mapping results to techniques: {str(e)}")
            return {"mappings": [], "error": str(e)}
    
    def create_mindmap_data(self, results: List[Dict[str, Any]], 
                          mappings: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create a mindmap visualization data structure from search results and TTP mappings.
        
        Args:
            results: List of search result dictionaries
            mappings: TTP mapping result from map_results_to_techniques
            
        Returns:
            Dictionary with nodes and links for visualization
        """
        if not results:
            return {"nodes": [], "links": []}
        
        # Create a graph
        G = nx.Graph()
        
        # Add the search query as the central node
        root_node = {
            "id": "root",
            "label": "Search Results",
            "group": "search"
        }
        G.add_node("root", **root_node)
        
        # Keep track of all nodes and links for the mindmap
        nodes = [root_node]
        links = []
        
        # Process each result
        for i, result in enumerate(results):
            # Create result node
            result_id = f"result_{i}"
            
            # Get a good label for the result - try some common fields
            label = None
            for field in ["host", "source", "sourcetype", "CommandLine", "Image", "user"]:
                if field in result and result[field]:
                    label = f"{field}: {result[field]}"
                    break
            
            if not label and len(result) > 0:
                # Use the first field as label
                key, value = next(iter(result.items()))
                label = f"{key}: {value}"
            
            result_node = {
                "id": result_id,
                "label": label or f"Result #{i+1}",
                "group": "result",
                "data": result
            }
            nodes.append(result_node)
            
            # Add link from root to result
            links.append({
                "source": "root",
                "target": result_id,
                "value": 2
            })
            
            # Add field nodes for pivoting
            added_fields = set()  # Track added fields to avoid duplicates
            
            for field, value in result.items():
                if not isinstance(value, str) or not value:
                    continue
                
                # Skip fields that are too long
                if len(value) > 100:
                    continue
                
                field_id = f"field_{field}"
                
                # Add field node if it doesn't exist
                if field not in added_fields:
                    field_node = {
                        "id": field_id,
                        "label": field,
                        "group": "field"
                    }
                    nodes.append(field_node)
                    added_fields.add(field)
                
                # Add link from result to field
                links.append({
                    "source": result_id,
                    "target": field_id,
                    "value": 1
                })
                
                # Add value node
                value_id = f"value_{field}_{value}"[:50]  # Limit ID length
                value_node = {
                    "id": value_id,
                    "label": value,
                    "group": "value",
                    "field": field
                }
                nodes.append(value_node)
                
                # Add link from field to value
                links.append({
                    "source": field_id,
                    "target": value_id,
                    "value": 1
                })
            
            # Add TTP mappings if available
            for mapping in mappings.get("mappings", []):
                if mapping.get("result_index") == i:
                    for match in mapping.get("matches", []):
                        technique_id = match.get("technique_id")
                        technique_name = match.get("technique_name")
                        
                        if technique_id and technique_name:
                            # Add technique node
                            technique_node = {
                                "id": f"technique_{technique_id}",
                                "label": f"{technique_id}: {technique_name}",
                                "group": "technique",
                                "score": match.get("similarity_score", 0)
                            }
                            nodes.append(technique_node)
                            
                            # Add link from result to technique
                            links.append({
                                "source": result_id,
                                "target": f"technique_{technique_id}",
                                "value": 3
                            })
        
        # Create a unique list of nodes (by id)
        unique_nodes = []
        node_ids = set()
        
        for node in nodes:
            if node["id"] not in node_ids:
                unique_nodes.append(node)
                node_ids.add(node["id"])
        
        return {
            "nodes": unique_nodes,
            "links": links
        }
    
    def get_raw_results_view(self, results: List[Dict[str, Any]]) -> str:
        """
        Format search results in a raw text view.
        
        Args:
            results: List of search result dictionaries
            
        Returns:
            Formatted text for display
        """
        if not results:
            return "No results."
        
        output = []
        
        for i, result in enumerate(results):
            output.append(f"--- Result #{i+1} ---")
            for key, value in result.items():
                output.append(f"{key} = {value}")
            output.append("")
        
        return "\n".join(output)