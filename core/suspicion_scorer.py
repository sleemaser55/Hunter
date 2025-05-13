
from typing import Dict, List
import re

class SuspicionScorer:
    def __init__(self):
        self.scoring_rules = {
            'lsass_access': 80,
            'credential_access': 75,
            'powershell_encoding': 60,
            'unusual_process': 50,
            'network_connection': 40,
            'file_access': 30
        }
        
        self.indicators = {
            'lsass_access': r'(?i)lsass|dumpert|procdump',
            'credential_access': r'(?i)mimikatz|sekurlsa|wdigest',
            'powershell_encoding': r'(?i)encodedcommand|-enc|-e.*\s[A-Za-z0-9+/=]{10,}',
            'unusual_process': r'(?i)cscript|wscript|regsvr32|mshta',
            'network_connection': r'(?i)4444|8080|443.*powershell',
            'file_access': r'(?i)\.exe$|\.dll$|\.ps1$'
        }

    def score_event(self, event: Dict) -> float:
        """Calculate suspicion score for an event"""
        score = 0
        
        # Check for indicators
        event_str = str(event)
        for indicator_type, pattern in self.indicators.items():
            if re.search(pattern, event_str):
                score += self.scoring_rules[indicator_type]
        
        # Normalize score to 0-100
        score = min(100, score)
        
        # Apply modifiers
        if event.get('admin_privilege'):
            score *= 1.2
        if event.get('first_time_seen'):
            score *= 1.1
            
        return round(score, 2)

    def enrich_event(self, event: Dict) -> Dict:
        """Add enrichment data to event"""
        enrichment = {
            'suspicion_score': self.score_event(event),
            'threat_intel': self._check_threat_intel(event),
            'process_reputation': self._check_process_reputation(event),
            'historical_context': self._get_historical_context(event)
        }
        return enrichment

    def _check_threat_intel(self, event: Dict) -> Dict:
        """Check event indicators against threat intel"""
        # Implement threat intel lookups
        return {
            'matches': [],
            'risk_level': 'medium'
        }

    def _check_process_reputation(self, event: Dict) -> Dict:
        """Check process/file reputation"""
        # Implement process reputation checks
        return {
            'signed': event.get('signed', False),
            'known_software': event.get('known_software', False),
            'reputation': 'unknown'
        }

    def _get_historical_context(self, event: Dict) -> Dict:
        """Get historical context for the event"""
        # Implement historical analysis
        return {
            'frequency': 'rare',
            'first_seen': event.get('first_seen'),
            'similar_events': []
        }
