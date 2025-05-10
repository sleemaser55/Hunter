import json
import logging
import os
from typing import Dict, List, Optional, Union, Any

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
