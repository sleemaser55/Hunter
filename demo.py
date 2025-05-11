#!/usr/bin/env python3
"""
Security Hunter Demo script.
This script demonstrates the core functionality of the Security Hunter tool.
"""

import sys
import json
import logging
from typing import Dict, List, Any, Optional

from core.mitre_parser import MitreAttackParser
from core.sigma_loader import SigmaLoader
from core.splunk_query import SplunkQueryExecutor
from core.field_mapper import FieldMapper

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
        ["id", "name", "description"],
        [10, 30, 40]
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
        print_header("MITRE ATT&CK Techniques")
    
    techniques = mitre_parser.get_techniques(tactic_id)
    print(f"Found {len(techniques)} techniques")
    
    # Display techniques as a table
    print_table(
        techniques[:20],  # Limit to 20 to avoid flooding the console
        ["id", "name", "is_subtechnique"],
        [15, 50, 15]
    )
    
    if len(techniques) > 20:
        print(f"... and {len(techniques) - 20} more")

def demo_sigma_rules(sigma_loader: SigmaLoader, technique_id: Optional[str] = None):
    """Demonstrate Sigma rules"""
    if technique_id:
        technique_rules = sigma_loader.get_rules_by_technique(technique_id)
        print_header(f"Sigma Rules for Technique {technique_id}")
        rules = technique_rules
    else:
        print_header("Sigma Rules")
        rules = sigma_loader.get_all_rules()
    
    print(f"Found {len(rules)} rules")
    
    # Display rules as a table
    simplified_rules = []
    for rule in rules[:20]:  # Limit to 20 to avoid flooding the console
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
    
    if len(rules) > 20:
        print(f"... and {len(rules) - 20} more")

def demo_sigma_to_splunk(sigma_loader: SigmaLoader, rule_id: str):
    """Demonstrate Sigma to Splunk conversion"""
    print_header(f"Converting Sigma Rule {rule_id} to Splunk SPL")
    
    rule = sigma_loader.get_rule_by_id(rule_id)
    if not rule:
        print(f"Rule {rule_id} not found")
        return
    
    print(f"Rule: {rule.get('title', 'Untitled')} ({rule_id})")
    
    splunk_query = sigma_loader.convert_rule_to_splunk(rule_id)
    if not splunk_query:
        print("Failed to convert rule to Splunk query")
        return
    
    print("\nGenerated Splunk Query:")
    print("-" * 80)
    print(splunk_query)

def demo_splunk_connection(splunk_query: SplunkQueryExecutor):
    """Demonstrate Splunk connection"""
    print_header("Testing Splunk Connection")
    
    connected = splunk_query.connect()
    if connected:
        print("Successfully connected to Splunk")
    else:
        print("Failed to connect to Splunk")

def demo_execute_query(splunk_query: SplunkQueryExecutor, query: str):
    """Demonstrate executing a Splunk query"""
    print_header("Executing Splunk Query")
    
    print(f"Query: {query}")
    
    result = splunk_query.execute_query(
        query=query,
        earliest_time="-1h",
        latest_time="now",
        max_count=10
    )
    
    if result["status"] == "success":
        print(f"Query executed successfully")
        print(f"Found {result['result_count']} results")
        
        if result["results"]:
            # Convert results to a list of dictionaries
            simplified_results = []
            for i, res in enumerate(result["results"]):
                if i >= 5:  # Limit to 5 results
                    break
                # Keep only a few fields to display
                simple_res = {}
                for field, value in res.items():
                    if len(simple_res) < 3:  # Limit to 3 fields per result
                        simple_res[field] = value
                simplified_results.append(simple_res)
            
            # Get column names and widths
            columns = []
            for res in simplified_results:
                for field in res.keys():
                    if field not in columns:
                        columns.append(field)
            
            widths = [min(30, max(len(col), 10)) for col in columns]
            
            print("\nResults:")
            print_table(simplified_results, columns, widths)
            
            if len(result["results"]) > 5:
                print(f"... and {len(result['results']) - 5} more")
    else:
        print(f"Query failed: {result.get('error', 'Unknown error')}")

def main():
    """Main demo function"""
    print_header("Security Hunter Demo")
    
    # Initialize components
    mitre_parser = MitreAttackParser()
    sigma_loader = SigmaLoader()
    splunk_query = SplunkQueryExecutor()
    field_mapper = FieldMapper()
    
    # Demo MITRE ATT&CK
    demo_mitre_tactics(mitre_parser)
    
    # Demo techniques for a specific tactic (Initial Access)
    demo_mitre_techniques(mitre_parser, "TA0001")
    
    # Demo Sigma rules
    demo_sigma_rules(sigma_loader)
    
    # Find rules for a specific technique (PowerShell)
    powershell_technique = "T1059.001"
    demo_sigma_rules(sigma_loader, powershell_technique)
    
    # Find a specific rule
    rule_samples = list(sigma_loader.rules.keys())
    if rule_samples:
        sample_rule_id = rule_samples[0]
        demo_sigma_to_splunk(sigma_loader, sample_rule_id)
    
    # Test Splunk connection
    demo_splunk_connection(splunk_query)
    
    # If connected, run a simple query
    if splunk_query.connected:
        demo_execute_query(splunk_query, "search index=* | head 10")
    
    print_header("Demo Complete")
    return 0

if __name__ == "__main__":
    sys.exit(main())