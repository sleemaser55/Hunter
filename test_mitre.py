#!/usr/bin/env python3
"""
Simple test script for MITRE ATT&CK parser.
"""

from core.mitre_parser import MitreAttackParser

def main():
    # Initialize MITRE parser
    parser = MitreAttackParser()
    
    # Get and print tactics
    tactics = parser.get_tactics()
    print(f"Found {len(tactics)} tactics")
    
    # Print the first 5 tactics
    for i, tactic in enumerate(tactics[:5]):
        print(f"{i+1}. {tactic['id']} - {tactic['name']}")
    
    # Get and print techniques for a specific tactic
    tactic_id = "TA0001"  # Initial Access
    techniques = parser.get_techniques(tactic_id)
    print(f"\nFound {len(techniques)} techniques for tactic {tactic_id}")
    
    # Print the first 5 techniques
    for i, technique in enumerate(techniques[:5]):
        print(f"{i+1}. {technique['id']} - {technique['name']}")

if __name__ == "__main__":
    main()