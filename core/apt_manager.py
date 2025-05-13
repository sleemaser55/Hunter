
import json
import logging
import os
import requests
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

class APTManager:
    def __init__(self, cache_dir: str = "data/apt_cache"):
        self.cache_dir = cache_dir
        self.apt_data = {}
        self._load_apt_data()
        
    def _load_apt_data(self):
        """Load APT data from MITRE ATT&CK"""
        os.makedirs(self.cache_dir, exist_ok=True)
        cache_file = os.path.join(self.cache_dir, "apt_data.json")
        
        if os.path.exists(cache_file):
            with open(cache_file, 'r') as f:
                self.apt_data = json.load(f)
        else:
            # Fetch from MITRE ATT&CK API
            url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
            try:
                response = requests.get(url)
                data = response.json()
                
                # Process APT groups
                for obj in data['objects']:
                    if obj['type'] == 'intrusion-set':
                        apt_id = obj['external_references'][0]['external_id']
                        self.apt_data[apt_id] = {
                            'name': obj.get('name', ''),
                            'description': obj.get('description', ''),
                            'techniques': self._get_techniques(obj),
                            'tactics': self._get_tactics(obj)
                        }
                
                # Save to cache
                with open(cache_file, 'w') as f:
                    json.dump(self.apt_data, f)
                    
            except Exception as e:
                logger.error(f"Failed to fetch APT data: {str(e)}")
                
    def _get_techniques(self, apt_obj: Dict) -> List[str]:
        """Extract technique IDs from APT object"""
        techniques = []
        if 'relationship_type' in apt_obj:
            for rel in apt_obj.get('relationship_type', []):
                if rel.get('relationship_type') == 'uses':
                    target = rel.get('target_ref', '')
                    if target.startswith('attack-pattern'):
                        techniques.append(target)
        return techniques
        
    def _get_tactics(self, apt_obj: Dict) -> List[str]:
        """Extract tactic IDs from APT object"""
        tactics = set()
        for technique in self._get_techniques(apt_obj):
            if 'kill_chain_phases' in technique:
                for phase in technique['kill_chain_phases']:
                    if phase.get('kill_chain_name') == 'mitre-attack':
                        tactics.add(phase.get('phase_name'))
        return list(tactics)
        
    def get_all_apts(self) -> List[Dict]:
        """Get list of all APT groups"""
        return [{'id': k, **v} for k, v in self.apt_data.items()]
        
    def get_apt(self, apt_id: str) -> Optional[Dict]:
        """Get specific APT by ID"""
        return self.apt_data.get(apt_id)
