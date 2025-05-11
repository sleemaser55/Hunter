import json
import logging
import os
import re
from typing import Dict, List, Optional, Union, Any, Tuple
from difflib import SequenceMatcher

import config

logger = logging.getLogger(__name__)

class FieldMapper:
    """Map fields between Sigma rules and Splunk fields"""
    
    def __init__(self, mapping_file: str = config.FIELD_MAPPING_FILE):
        """
        Initialize the field mapper.
        
        Args:
            mapping_file: Path to the JSON field mapping file
        """
        self.mapping_file = mapping_file
        self.mappings = {}
        self.potential_mappings = {}  # Stores auto-suggested mappings
        self._load_mappings()
    
    def _load_mappings(self):
        """Load field mappings from the mapping file"""
        # If file doesn't exist, use the default mappings
        if not os.path.exists(self.mapping_file):
            logger.info(f"Field mapping file not found, creating with default mappings")
            self.mappings = config.DEFAULT_FIELD_MAPPINGS
            self._save_mappings()
        else:
            # Load mappings from file
            try:
                with open(self.mapping_file, 'r') as f:
                    self.mappings = json.load(f)
                logger.info(f"Loaded field mappings from {self.mapping_file}")
            except json.JSONDecodeError as e:
                logger.error(f"Error loading field mappings: {str(e)}")
                self.mappings = config.DEFAULT_FIELD_MAPPINGS
                self._save_mappings()
    
    def _save_mappings(self):
        """Save current mappings to the mapping file"""
        try:
            # Ensure directory exists
            os.makedirs(os.path.dirname(self.mapping_file), exist_ok=True)
            
            with open(self.mapping_file, 'w') as f:
                json.dump(self.mappings, f, indent=2)
            logger.info(f"Saved field mappings to {self.mapping_file}")
        except Exception as e:
            logger.error(f"Error saving field mappings: {str(e)}")
    
    def get_mapping(self, category: str, field: str) -> Optional[str]:
        """
        Get the mapped field name for a given category and field.
        
        Args:
            category: The field category (e.g., 'process', 'file', 'network')
            field: The generic field name
        
        Returns:
            The mapped field name or None if no mapping exists
        """
        if category in self.mappings and field in self.mappings[category]:
            return self.mappings[category][field]
        return None
    
    def get_reverse_mapping(self, splunk_field: str) -> List[Dict[str, str]]:
        """
        Get the generic fields that map to a specific Splunk field.
        
        Args:
            splunk_field: The Splunk field name
        
        Returns:
            List of mappings with category and field name
        """
        results = []
        for category, mappings in self.mappings.items():
            for field, mapped_field in mappings.items():
                if mapped_field == splunk_field:
                    results.append({
                        "category": category,
                        "field": field,
                        "mapped_field": mapped_field
                    })
        return results
    
    def add_mapping(self, category: str, field: str, mapped_field: str) -> bool:
        """
        Add or update a field mapping.
        
        Args:
            category: The field category
            field: The generic field name
            mapped_field: The mapped field name
        
        Returns:
            True if mapping was added/updated successfully
        """
        try:
            # Ensure category exists
            if category not in self.mappings:
                self.mappings[category] = {}
            
            # Add/update mapping
            self.mappings[category][field] = mapped_field
            
            # Save mappings
            self._save_mappings()
            return True
        except Exception as e:
            logger.error(f"Error adding field mapping: {str(e)}")
            return False
    
    def remove_mapping(self, category: str, field: str) -> bool:
        """
        Remove a field mapping.
        
        Args:
            category: The field category
            field: The generic field name
        
        Returns:
            True if mapping was removed successfully
        """
        try:
            if category in self.mappings and field in self.mappings[category]:
                del self.mappings[category][field]
                self._save_mappings()
                return True
            return False
        except Exception as e:
            logger.error(f"Error removing field mapping: {str(e)}")
            return False
    
    def get_categories(self) -> List[str]:
        """
        Get all available field categories.
        
        Returns:
            List of category names
        """
        return list(self.mappings.keys())
    
    def get_fields_for_category(self, category: str) -> Dict[str, str]:
        """
        Get all field mappings for a specific category.
        
        Args:
            category: The field category
        
        Returns:
            Dictionary of field to mapped field mappings
        """
        return self.mappings.get(category, {})
    
    def get_all_mappings(self) -> Dict[str, Dict[str, str]]:
        """
        Get all field mappings.
        
        Returns:
            Complete mapping dictionary
        """
        return self.mappings
    
    def apply_mappings_to_query(self, query: str) -> str:
        """
        Apply field mappings to a query string.
        
        Args:
            query: Query string with generic field names
        
        Returns:
            Query string with mapped field names
        """
        # This is a simple implementation - a real one would need to parse the query
        # More complex implementations would need to understand the query syntax
        
        for category, mappings in self.mappings.items():
            for field, mapped_field in mappings.items():
                # Replace field names with mapped names
                # This assumes field names are used as standalone words
                query = query.replace(f" {field} ", f" {mapped_field} ")
                query = query.replace(f" {field}=", f" {mapped_field}=")
                query = query.replace(f"({field} ", f"({mapped_field} ")
                query = query.replace(f"({field}=", f"({mapped_field}=")
                
                # Handle query beginning with the field
                if query.startswith(f"{field} "):
                    query = f"{mapped_field} " + query[len(field)+1:]
                if query.startswith(f"{field}="):
                    query = f"{mapped_field}=" + query[len(field)+1:]
        
        return query
    
    def calculate_similarity(self, str1: str, str2: str) -> float:
        """
        Calculate string similarity using sequence matcher.
        
        Args:
            str1: First string
            str2: Second string
            
        Returns:
            Similarity score between 0.0 and 1.0
        """
        return SequenceMatcher(None, str1.lower(), str2.lower()).ratio()
    
    def normalize_field_name(self, field_name: str) -> str:
        """
        Normalize a field name for better matching.
        
        Args:
            field_name: Original field name
            
        Returns:
            Normalized field name
        """
        # Convert to lowercase
        result = field_name.lower()
        
        # Replace underscores, dots, and hyphens with spaces
        result = re.sub(r'[_.-]', ' ', result)
        
        # Remove common prefixes and suffixes
        prefixes = ['win', 'splunk', 'event', 'sysmon', 'data', 'evt', 'field', 'cim']
        for prefix in prefixes:
            if result.startswith(prefix):
                result = result[len(prefix):].lstrip()
                
        # Remove special characters
        result = re.sub(r'[^a-z0-9\s]', '', result)
        
        # Remove extra whitespace
        result = re.sub(r'\s+', ' ', result).strip()
        
        return result
    
    def get_potential_mappings(self, sigma_field: str, 
                             splunk_fields: List[Dict[str, Any]],
                             threshold: float = 0.7) -> List[Dict[str, Any]]:
        """
        Get potential Splunk field mappings for a Sigma field.
        
        Args:
            sigma_field: The Sigma field name to find mappings for
            splunk_fields: List of Splunk field metadata dictionaries
            threshold: Minimum similarity score for inclusion
            
        Returns:
            List of potential mappings sorted by similarity score
        """
        normalized_sigma = self.normalize_field_name(sigma_field)
        potential_matches = []
        
        for field_data in splunk_fields:
            splunk_field = field_data.get('field') or field_data.get('name', '')
            if not splunk_field:
                continue
                
            normalized_splunk = self.normalize_field_name(splunk_field)
            
            # Calculate similarity score
            similarity = self.calculate_similarity(normalized_sigma, normalized_splunk)
            
            # Check common field patterns
            # e.g., "process_name" might match "Image" or "CommandLine" based on sample values
            if splunk_field in field_data.get('sample_values', []):
                pattern_match_score = 0.4  # Default pattern match bonus
                
                # Boost certain well-known mappings
                process_fields = ['process', 'process_name', 'image', 'exec', 'command', 'cmdline']
                file_fields = ['file', 'file_path', 'filepath', 'targetfilename', 'path']
                network_fields = ['dest', 'src', 'destination', 'source', 'ip', 'address', 'host']
                
                if any(p in normalized_sigma for p in process_fields) and any(p in normalized_splunk for p in process_fields):
                    pattern_match_score = 0.5
                elif any(p in normalized_sigma for p in file_fields) and any(p in normalized_splunk for p in file_fields):
                    pattern_match_score = 0.5
                elif any(p in normalized_sigma for p in network_fields) and any(p in normalized_splunk for p in network_fields):
                    pattern_match_score = 0.5
                
                # Add pattern match bonus
                similarity = max(similarity, pattern_match_score)
            
            # Include if above threshold
            if similarity >= threshold:
                potential_matches.append({
                    'splunk_field': splunk_field,
                    'similarity': similarity,
                    'prevalence': field_data.get('prevalence', 0),
                    'count': field_data.get('count', 0),
                    'sample_values': field_data.get('sample_values', [])
                })
        
        # Sort by similarity score (descending)
        return sorted(potential_matches, key=lambda x: x['similarity'], reverse=True)
    
    def auto_detect_mappings(self, sigma_fields: Dict[str, List[str]], 
                           splunk_field_metadata: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, List[Dict[str, Any]]]]:
        """
        Auto-detect field mappings between Sigma and Splunk fields.
        
        Args:
            sigma_fields: Dictionary mapping field categories to field names
            splunk_field_metadata: Dictionary of Splunk field metadata
            
        Returns:
            Dictionary with suggested mappings for each category and field
        """
        suggested_mappings = {}
        splunk_fields = [
            {**metadata, 'field': field_name} 
            for field_name, metadata in splunk_field_metadata.items()
        ]
        
        # Process each category
        for category, fields in sigma_fields.items():
            suggested_mappings[category] = {}
            
            # Process each field in the category
            for field in fields:
                # Skip if mapping already exists
                if category in self.mappings and field in self.mappings[category]:
                    continue
                    
                # Get potential mappings for this field
                potential_matches = self.get_potential_mappings(field, splunk_fields)
                
                if potential_matches:
                    suggested_mappings[category][field] = potential_matches
        
        # Store the potential mappings for later use
        self.potential_mappings = suggested_mappings
        
        return suggested_mappings
    
    def apply_suggested_mappings(self, approved_mappings: Dict[str, Dict[str, str]]) -> bool:
        """
        Apply suggested mappings that have been approved by the user.
        
        Args:
            approved_mappings: Dictionary mapping categories -> fields -> approved Splunk field
            
        Returns:
            True if mappings were applied successfully
        """
        try:
            # Update mappings for each category and field
            for category, fields in approved_mappings.items():
                for field, mapped_field in fields.items():
                    self.add_mapping(category, field, mapped_field)
                    
            # Clear potential mappings for these fields
            for category, fields in approved_mappings.items():
                if category in self.potential_mappings:
                    for field in fields:
                        if field in self.potential_mappings[category]:
                            del self.potential_mappings[category][field]
            
            return True
            
        except Exception as e:
            logger.error(f"Error applying suggested mappings: {str(e)}")
            return False
    
    def extract_common_sigma_fields(self, categories: Optional[List[str]] = None) -> Dict[str, List[str]]:
        """
        Extract common Sigma fields from the default mappings.
        
        Args:
            categories: Optional list of categories to limit extraction to
            
        Returns:
            Dictionary mapping categories to lists of Sigma fields
        """
        # Start with default mappings
        default_mappings = config.DEFAULT_FIELD_MAPPINGS
        
        extracted_fields = {}
        target_categories = categories or list(default_mappings.keys())
        
        for category in target_categories:
            if category in default_mappings:
                extracted_fields[category] = list(default_mappings[category].keys())
        
        return extracted_fields
