import glob
import logging
import os
import yaml
from typing import Dict, List, Optional, Union, Any

import config

logger = logging.getLogger(__name__)

class SigmaLoader:
    """Load and manage Sigma rules"""
    
    def __init__(self, rules_dir: str = config.SIGMA_RULES_DIR):
        """
        Initialize the Sigma rule loader.
        
        Args:
            rules_dir: Directory containing Sigma rule YAML files
        """
        self.rules_dir = rules_dir
        self.rules = {}  # Dictionary of rules by ID
        self.rules_by_technique = {}  # Dictionary of rules by MITRE technique ID
        self._load_rules()
    
    def _load_rules(self):
        """Load all Sigma rules from the rules directory"""
        # Ensure directory exists
        os.makedirs(self.rules_dir, exist_ok=True)
        
        # Find all YAML files recursively
        rule_files = glob.glob(os.path.join(self.rules_dir, "**/*.yml"), recursive=True)
        rule_files.extend(glob.glob(os.path.join(self.rules_dir, "**/*.yaml"), recursive=True))
        
        rules_count = 0
        for file_path in rule_files:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    rule_content = yaml.safe_load(f)
                
                # Handle both single rules and rule collections
                if rule_content.get('type') == 'group':
                    # It's a rule collection
                    for rule in rule_content.get('rules', []):
                        self._process_rule(rule, file_path)
                        rules_count += 1
                else:
                    # It's a single rule
                    self._process_rule(rule_content, file_path)
                    rules_count += 1
            
            except Exception as e:
                logger.error(f"Error loading Sigma rule from {file_path}: {str(e)}")
        
        logger.info(f"Loaded {rules_count} Sigma rules from {len(rule_files)} files")
    
    def _process_rule(self, rule: Dict[str, Any], file_path: str):
        """
        Process a single Sigma rule and add it to our collections.
        
        Args:
            rule: The rule dictionary
            file_path: Path to the file containing the rule
        """
        rule_id = rule.get('id')
        if not rule_id:
            logger.warning(f"Sigma rule without ID found in {file_path}, skipping")
            return
        
        # Add source file path to the rule
        rule['file_path'] = file_path
        
        # Store rule by ID
        self.rules[rule_id] = rule
        
        # Process MITRE ATT&CK tags
        tags = rule.get('tags', [])
        if not isinstance(tags, list):
            tags = [tags]  # Convert single tag to list
        
        # Extract MITRE technique IDs
        for tag in tags:
            if isinstance(tag, str) and tag.startswith('attack.t'):
                # Extract technique ID, handling both formats:
                # - attack.t1234
                # - attack.t1234.001
                technique_parts = tag.split('.')
                if len(technique_parts) >= 2:
                    technique_base = technique_parts[1].upper()
                    if technique_base.startswith('T'):
                        # Form full technique ID
                        if len(technique_parts) >= 3:
                            technique_id = f"{technique_base}.{technique_parts[2]}"
                        else:
                            technique_id = technique_base
                        
                        # Add to technique-indexed collection
                        if technique_id not in self.rules_by_technique:
                            self.rules_by_technique[technique_id] = []
                        self.rules_by_technique[technique_id].append(rule_id)
    
    def get_rule_by_id(self, rule_id: str) -> Optional[Dict[str, Any]]:
        """
        Get a specific Sigma rule by its ID.
        
        Args:
            rule_id: The rule ID
        
        Returns:
            Rule dictionary or None if not found
        """
        return self.rules.get(rule_id)
    
    def get_rules_by_technique(self, technique_id: str) -> List[Dict[str, Any]]:
        """
        Get all Sigma rules associated with a MITRE technique.
        
        Args:
            technique_id: MITRE ATT&CK technique ID (e.g., T1059.001)
        
        Returns:
            List of matching rule dictionaries
        """
        rule_ids = self.rules_by_technique.get(technique_id, [])
        return [self.rules[rid] for rid in rule_ids if rid in self.rules]
    
    def search_rules(self, query: str) -> List[Dict[str, Any]]:
        """
        Search for Sigma rules by title, description, or content.
        
        Args:
            query: Search string
        
        Returns:
            List of matching rule dictionaries
        """
        query = query.lower()
        results = []
        
        for rule in self.rules.values():
            if (query in rule.get('title', '').lower() or
                query in rule.get('description', '').lower() or
                any(query in str(detection).lower() for detection in rule.get('detection', {}).values())):
                results.append(rule)
        
        return results
    
    def get_all_rules(self) -> List[Dict[str, Any]]:
        """
        Get all loaded Sigma rules.
        
        Returns:
            List of all rule dictionaries
        """
        return list(self.rules.values())
    
    def convert_rule_to_splunk(self, rule_id: str) -> Optional[str]:
        """
        Convert a Sigma rule to Splunk SPL query.
        
        Args:
            rule_id: The rule ID
        
        Returns:
            Splunk SPL query string or None if conversion failed
        """
        try:
            from sigma.parser import SigmaCollectionParser
            from sigma.backends.splunk import SplunkBackend
            from sigma.collection import SigmaCollection
        except ImportError:
            logger.error("pySigma and required backends are not installed")
            return None
        
        rule = self.get_rule_by_id(rule_id)
        if not rule:
            return None
        
        try:
            # Create SigmaCollection from the rule
            sigma_collection = SigmaCollection([rule])
            
            # Create Splunk backend
            backend = SplunkBackend()
            
            # Convert to Splunk query
            queries = backend.convert(sigma_collection)
            
            # Return the first query (most rules generate only one)
            return queries[0] if queries else None
        except Exception as e:
            logger.error(f"Error converting rule {rule_id} to Splunk query: {str(e)}")
            return None
    
    def add_rule_file(self, file_path: str) -> List[str]:
        """
        Add a new rule file to the loader.
        
        Args:
            file_path: Path to the YAML rule file
        
        Returns:
            List of rule IDs that were added
        """
        added_rules = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                rule_content = yaml.safe_load(f)
            
            # Handle both single rules and rule collections
            if rule_content.get('type') == 'group':
                # It's a rule collection
                for rule in rule_content.get('rules', []):
                    rule_id = rule.get('id')
                    if rule_id:
                        self._process_rule(rule, file_path)
                        added_rules.append(rule_id)
            else:
                # It's a single rule
                rule_id = rule_content.get('id')
                if rule_id:
                    self._process_rule(rule_content, file_path)
                    added_rules.append(rule_id)
            
            logger.info(f"Added {len(added_rules)} rules from {file_path}")
        except Exception as e:
            logger.error(f"Error adding rule file {file_path}: {str(e)}")
        
        return added_rules
