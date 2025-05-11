#!/usr/bin/env python3
"""
Simple test script for Sigma rule loader.
"""

from core.sigma_loader import SigmaLoader

def main():
    # Initialize Sigma loader
    loader = SigmaLoader()
    
    # Get and print all rules
    all_rules = loader.get_all_rules()
    print(f"Found {len(all_rules)} Sigma rules")
    
    # Print the first 5 rules
    for i, rule in enumerate(all_rules[:5]):
        print(f"{i+1}. {rule.get('id')} - {rule.get('title')}")
    
    # Get rules for a specific technique
    technique_id = "T1059.001"  # PowerShell
    technique_rules = loader.get_rules_by_technique(technique_id)
    print(f"\nFound {len(technique_rules)} rules for technique {technique_id}")
    
    # Print the first 5 technique rules
    for i, rule in enumerate(technique_rules[:5]):
        print(f"{i+1}. {rule.get('id')} - {rule.get('title')}")
    
    # Try to convert a rule to Splunk query
    if technique_rules:
        first_rule = technique_rules[0]
        rule_id = first_rule.get('id', '')
        
        if rule_id:  # Ensure rule_id is not None and not empty
            print(f"\nConverting rule {rule_id} to Splunk query:")
            query = loader.convert_rule_to_splunk(rule_id)
            if query:
                print(f"Splunk query: {query}")
            else:
                print("Failed to convert rule to Splunk query")
        else:
            print("\nNo rule ID found for conversion")

if __name__ == "__main__":
    main()