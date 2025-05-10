import json
import logging
import os
import requests
import time
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any

import config

logger = logging.getLogger(__name__)

class MitreAttackParser:
    """Parse and interact with MITRE ATT&CK framework data"""
    
    def __init__(self, local_file_path: str = config.MITRE_LOCAL_FILE, 
                 remote_url: str = config.MITRE_ENTERPRISE_URL,
                 cache_duration: int = 86400):  # Default cache duration: 1 day
        """
        Initialize the MITRE ATT&CK parser.
        
        Args:
            local_file_path: Path to the local cache of the MITRE ATT&CK data
            remote_url: URL to fetch the latest MITRE ATT&CK data
            cache_duration: How long (in seconds) to use the cached data before refreshing
        """
        self.local_file_path = local_file_path
        self.remote_url = remote_url
        self.cache_duration = cache_duration
        self.attack_data = None
        self._tactics = None
        self._techniques = None
        self._load_attack_data()
    
    def _load_attack_data(self):
        """Load MITRE ATT&CK data from local cache or remote source"""
        should_download = True
        
        # Check if local file exists and is recent
        if os.path.exists(self.local_file_path):
            file_mod_time = os.path.getmtime(self.local_file_path)
            if (time.time() - file_mod_time) < self.cache_duration:
                try:
                    with open(self.local_file_path, 'r') as f:
                        self.attack_data = json.load(f)
                    should_download = False
                    logger.info(f"Loaded MITRE ATT&CK data from local cache: {self.local_file_path}")
                except json.JSONDecodeError:
                    logger.warning(f"Local MITRE ATT&CK data is corrupted, downloading fresh copy")
                    should_download = True
            else:
                logger.info(f"Local MITRE ATT&CK data is outdated, downloading fresh copy")
        
        # Download fresh data if needed
        if should_download:
            try:
                logger.info(f"Downloading MITRE ATT&CK data from {self.remote_url}")
                response = requests.get(self.remote_url, timeout=60)
                response.raise_for_status()
                self.attack_data = response.json()
                
                # Save to local file
                os.makedirs(os.path.dirname(self.local_file_path), exist_ok=True)
                with open(self.local_file_path, 'w') as f:
                    json.dump(self.attack_data, f)
                logger.info(f"MITRE ATT&CK data downloaded and saved to {self.local_file_path}")
            except Exception as e:
                logger.error(f"Failed to download MITRE ATT&CK data: {str(e)}")
                # Try to load from local file as fallback
                if os.path.exists(self.local_file_path):
                    try:
                        with open(self.local_file_path, 'r') as f:
                            self.attack_data = json.load(f)
                        logger.info(f"Loaded MITRE ATT&CK data from local cache as fallback")
                    except Exception as e2:
                        logger.error(f"Failed to load local MITRE ATT&CK data: {str(e2)}")
                        raise RuntimeError("Could not load MITRE ATT&CK data from any source")
                else:
                    raise RuntimeError("No local MITRE ATT&CK data available and download failed")
        
        # Parse the tactics and techniques
        self._parse_tactics_and_techniques()
    
    def _parse_tactics_and_techniques(self):
        """Parse the tactics and techniques from the ATT&CK data"""
        if not self.attack_data:
            return
        
        self._tactics = {}
        self._techniques = {}
        
        # Process all objects
        for obj in self.attack_data.get('objects', []):
            obj_type = obj.get('type')
            
            # Process tactics (x-mitre-tactic)
            if obj_type == 'x-mitre-tactic':
                tactic_id = obj.get('external_references', [{}])[0].get('external_id', '')
                if tactic_id:
                    self._tactics[tactic_id] = {
                        'id': tactic_id,
                        'name': obj.get('name', ''),
                        'description': obj.get('description', ''),
                        'short_name': obj.get('x_mitre_shortname', '')
                    }
            
            # Process techniques (attack-pattern)
            elif obj_type == 'attack-pattern':
                technique_refs = [ref for ref in obj.get('external_references', []) 
                                if ref.get('source_name') == 'mitre-attack']
                if technique_refs:
                    technique_id = technique_refs[0].get('external_id', '')
                    if technique_id:
                        # Determine if this is a sub-technique
                        is_subtechnique = '.' in technique_id
                        parent_id = technique_id.split('.')[0] if is_subtechnique else None
                        
                        # Determine the tactics this technique belongs to
                        kill_chain_phases = obj.get('kill_chain_phases', [])
                        tactic_names = [phase.get('phase_name') for phase in kill_chain_phases 
                                       if phase.get('kill_chain_name') == 'mitre-attack']
                        
                        self._techniques[technique_id] = {
                            'id': technique_id,
                            'name': obj.get('name', ''),
                            'description': obj.get('description', ''),
                            'tactics': tactic_names,
                            'is_subtechnique': is_subtechnique,
                            'parent_id': parent_id,
                            'detection': obj.get('x_mitre_detection', ''),
                            'url': technique_refs[0].get('url', '')
                        }
        
        logger.info(f"Parsed {len(self._tactics)} tactics and {len(self._techniques)} techniques")
    
    def get_tactics(self) -> List[Dict[str, str]]:
        """Get all ATT&CK tactics"""
        if not self._tactics:
            self._load_attack_data()
        return list(self._tactics.values())
    
    def get_techniques(self, tactic_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get ATT&CK techniques, optionally filtered by tactic.
        
        Args:
            tactic_id: Optional tactic ID to filter techniques
        
        Returns:
            List of technique dictionaries
        """
        if not self._techniques:
            self._load_attack_data()
        
        # Convert tactic_id to shortname if needed
        tactic_shortname = None
        if tactic_id and tactic_id in self._tactics:
            tactic_shortname = self._tactics[tactic_id]['short_name']
        
        # Filter techniques by tactic if specified
        if tactic_shortname:
            return [
                technique for technique in self._techniques.values()
                if tactic_shortname in technique.get('tactics', [])
            ]
        
        return list(self._techniques.values())
    
    def get_technique_by_id(self, technique_id: str) -> Optional[Dict[str, Any]]:
        """
        Get a specific technique by its ID.
        
        Args:
            technique_id: The technique ID (e.g., 'T1059.001')
        
        Returns:
            Technique dictionary or None if not found
        """
        if not self._techniques:
            self._load_attack_data()
        
        return self._techniques.get(technique_id)
    
    def get_tactic_by_id(self, tactic_id: str) -> Optional[Dict[str, str]]:
        """
        Get a specific tactic by its ID.
        
        Args:
            tactic_id: The tactic ID (e.g., 'TA0001')
        
        Returns:
            Tactic dictionary or None if not found
        """
        if not self._tactics:
            self._load_attack_data()
        
        return self._tactics.get(tactic_id)
    
    def search_techniques(self, query: str) -> List[Dict[str, Any]]:
        """
        Search for techniques by name or description.
        
        Args:
            query: Search string
        
        Returns:
            List of matching technique dictionaries
        """
        if not self._techniques:
            self._load_attack_data()
        
        query = query.lower()
        results = []
        
        for technique in self._techniques.values():
            if (query in technique['name'].lower() or 
                query in technique['description'].lower() or
                query in technique['id'].lower()):
                results.append(technique)
        
        return results
