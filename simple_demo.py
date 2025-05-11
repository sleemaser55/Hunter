#!/usr/bin/env python3
"""
Security Hunter Simple Demo script.
This script demonstrates the core functionality of the Security Hunter tool.
"""

import sys
import json
import logging
from typing import Dict, List, Any, Optional

from core.mitre_parser import MitreAttackParser
from core.sigma_loader import SigmaLoader

# Configure logging
logging.basicConfig(level=logging.INFO, 
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def print_header(text: str):
    """Print a formatted header"""
    print("\n" + "=" * 80)
    print(f" {text}")
    print("=" * 80)

def print_json(data: Any):
    """Print formatted JSON data"""
    print(json.dumps(data, indent=2))

def print_table(data: List[Dict[str, Any]], columns: List[str], widths: List[int]):
    """Print a formatted table"""
    # Print header
    header = ""
    for i, col in enumerate(columns):
        header += f"{col:<{widths[i]}} "
    print(header)
    print("-" * sum(widths))
    
    # Print rows
    for row in data:
        line = ""
        for i, col in enumerate(columns):
            value = str(row.get(col, ""))
            if len(value) > widths[i] - 3:
                value = value[:widths[i] - 3] + "..."
            line += f"{value:<{widths[i]}} "
        print(line)

def demo_mitre_tactics(mitre_parser: MitreAttackParser):
    """Demonstrate MITRE tactics"""
    print_header("MITRE ATT&CK Tactics")
    
    tactics = mitre_parser.get_tactics()
    print(f"Found {len(tactics)} tactics")
    
    # Display tactics as a table
    print_table(
        tactics,
        ["id", "name"],
        [10, 70]
    )

def demo_mitre_techniques(mitre_parser: MitreAttackParser, tactic_id: Optional[str] = None):
    """Demonstrate MITRE techniques"""
    if tactic_id:
        tactic = mitre_parser.get_tactic_by_id(tactic_id)
        if tactic:
            print_header(f"MITRE ATT&CK Techniques for {tactic['name']} ({tactic_id})")
        else:
            print_header(f"MITRE ATT&CK Techniques for tactic {tactic_id}")
    else:
        print_header("MITRE ATT&CK Techniques (showing first 10)")
    
    techniques = mitre_parser.get_techniques(tactic_id)
    print(f"Found {len(techniques)} techniques")
    
    # Display techniques as a table
    print_table(
        techniques[:10],  # Limit to 10 to avoid flooding the console
        ["id", "name"],
        [15, 65]
    )

def demo_sigma_rules(sigma_loader: SigmaLoader, technique_id: Optional[str] = None):
    """Demonstrate Sigma rules"""
    if technique_id:
        technique_rules = sigma_loader.get_rules_by_technique(technique_id)
        print_header(f"Sigma Rules for Technique {technique_id}")
        rules = technique_rules
    else:
        print_header("Sigma Rules (showing first 10)")
        rules = sigma_loader.get_all_rules()[:10]
    
    print(f"Total rules: {len(sigma_loader.get_all_rules())}")
    print(f"Showing {len(rules)} rules")
    
    # Display rules as a table
    simplified_rules = []
    for rule in rules:
        simplified_rules.append({
            "id": rule.get("id", ""),
            "title": rule.get("title", ""),
            "level": rule.get("level", "")
        })
    
    print_table(
        simplified_rules,
        ["id", "title", "level"],
        [40, 40, 10]
    )

def main():
    """Main demo function"""
    print_header("Security Hunter Simple Demo")
    
    # Initialize components
    mitre_parser = MitreAttackParser()
    sigma_loader = SigmaLoader()
    
    # Demo MITRE ATT&CK
    demo_mitre_tactics(mitre_parser)
    
    # Demo techniques for a specific tactic (Initial Access)
    demo_mitre_techniques(mitre_parser, "TA0001")
    
    # Demo Sigma rules
    demo_sigma_rules(sigma_loader)
    
    # Find rules for a specific technique (PowerShell)
    powershell_technique = "T1059.001"
    demo_sigma_rules(sigma_loader, powershell_technique)
    
    print_header("Demo Complete")
    return 0

if __name__ == "__main__":
    sys.exit(main())