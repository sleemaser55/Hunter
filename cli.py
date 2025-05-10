#!/usr/bin/env python3
import argparse
import json
import logging
import os
import sys
from typing import Dict, List, Optional, Any

# Add parent directory to PATH for imports
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from core.mitre_parser import MitreAttackParser
from core.sigma_loader import SigmaLoader
from core.splunk_query import SplunkQueryExecutor
from core.field_mapper import FieldMapper
import config

logger = logging.getLogger("cli")

class SecurityHunterCLI:
    """Command-line interface for the Security Hunter tool"""
    
    def __init__(self):
        """Initialize the CLI"""
        self.mitre_parser = MitreAttackParser()
        self.sigma_loader = SigmaLoader()
        self.splunk_query = SplunkQueryExecutor()
        self.field_mapper = FieldMapper()
        
        self.parser = self._setup_parser()
    
    def _setup_parser(self) -> argparse.ArgumentParser:
        """Set up the command-line argument parser"""
        parser = argparse.ArgumentParser(
            description="Security Hunter - Threat hunting with MITRE ATT&CK, Sigma, and Splunk",
            formatter_class=argparse.RawDescriptionHelpFormatter
        )
        
        # Add subparsers for different commands
        subparsers = parser.add_subparsers(dest="command", help="Command to execute")
        
        # MITRE commands
        mitre_parser = subparsers.add_parser("mitre", help="Work with MITRE ATT&CK framework")
        mitre_subparsers = mitre_parser.add_subparsers(dest="mitre_command", help="MITRE command")
        
        # MITRE - List tactics
        tactics_parser = mitre_subparsers.add_parser("tactics", help="List all MITRE tactics")
        
        # MITRE - List techniques
        techniques_parser = mitre_subparsers.add_parser("techniques", help="List techniques")
        techniques_parser.add_argument("--tactic", "-t", help="Filter by tactic ID")
        
        # MITRE - Show technique
        technique_parser = mitre_subparsers.add_parser("technique", help="Show details for a technique")
        technique_parser.add_argument("technique_id", help="Technique ID (e.g., T1059.001)")
        
        # Sigma commands
        sigma_parser = subparsers.add_parser("sigma", help="Work with Sigma rules")
        sigma_subparsers = sigma_parser.add_subparsers(dest="sigma_command", help="Sigma command")
        
        # Sigma - List rules
        list_parser = sigma_subparsers.add_parser("list", help="List Sigma rules")
        list_parser.add_argument("--technique", "-t", help="Filter by technique ID")
        list_parser.add_argument("--search", "-s", help="Search in rule title and description")
        
        # Sigma - Show rule
        show_parser = sigma_subparsers.add_parser("show", help="Show a Sigma rule")
        show_parser.add_argument("rule_id", help="Rule ID")
        
        # Sigma - Convert rule to Splunk query
        convert_parser = sigma_subparsers.add_parser("convert", help="Convert a Sigma rule to Splunk SPL")
        convert_parser.add_argument("rule_id", help="Rule ID")
        
        # Splunk commands
        splunk_parser = subparsers.add_parser("splunk", help="Work with Splunk")
        splunk_subparsers = splunk_parser.add_subparsers(dest="splunk_command", help="Splunk command")
        
        # Splunk - Test connection
        test_parser = splunk_subparsers.add_parser("test", help="Test connection to Splunk")
        
        # Splunk - Execute query
        query_parser = splunk_subparsers.add_parser("query", help="Execute a Splunk query")
        query_parser.add_argument("query", help="Splunk SPL query")
        query_parser.add_argument("--earliest", "-e", default="-24h", 
                                  help="Earliest time for search (default: -24h)")
        query_parser.add_argument("--latest", "-l", default="now", 
                                  help="Latest time for search (default: now)")
        query_parser.add_argument("--count", "-c", type=int, default=100, 
                                  help="Maximum number of results (default: 100)")
        
        # Splunk - Execute Sigma rule
        rule_parser = splunk_subparsers.add_parser("rule", 
                                                   help="Execute a Sigma rule as a Splunk query")
        rule_parser.add_argument("rule_id", help="Sigma rule ID")
        rule_parser.add_argument("--earliest", "-e", default="-24h", 
                                 help="Earliest time for search (default: -24h)")
        rule_parser.add_argument("--latest", "-l", default="now", 
                                 help="Latest time for search (default: now)")
        rule_parser.add_argument("--count", "-c", type=int, default=100, 
                                 help="Maximum number of results (default: 100)")
        
        # Mapping commands
        mapping_parser = subparsers.add_parser("mapping", help="Work with field mappings")
        mapping_subparsers = mapping_parser.add_subparsers(dest="mapping_command", help="Mapping command")
        
        # Mapping - List mappings
        list_mappings_parser = mapping_subparsers.add_parser("list", help="List field mappings")
        list_mappings_parser.add_argument("--category", "-c", help="Filter by category")
        
        # Mapping - Add mapping
        add_mapping_parser = mapping_subparsers.add_parser("add", help="Add or update a field mapping")
        add_mapping_parser.add_argument("category", help="Field category")
        add_mapping_parser.add_argument("field", help="Generic field name")
        add_mapping_parser.add_argument("mapped_field", help="Mapped field name")
        
        # Mapping - Remove mapping
        remove_mapping_parser = mapping_subparsers.add_parser("remove", help="Remove a field mapping")
        remove_mapping_parser.add_argument("category", help="Field category")
        remove_mapping_parser.add_argument("field", help="Generic field name")
        
        # Hunt commands
        hunt_parser = subparsers.add_parser("hunt", help="Execute a hunt")
        hunt_parser.add_argument("technique_id", help="MITRE technique ID")
        hunt_parser.add_argument("--earliest", "-e", default="-24h", 
                                help="Earliest time for search (default: -24h)")
        hunt_parser.add_argument("--latest", "-l", default="now", 
                                help="Latest time for search (default: now)")
        hunt_parser.add_argument("--count", "-c", type=int, default=100, 
                                help="Maximum number of results (default: 100)")
        
        return parser
    
    def run(self):
        """Run the CLI"""
        args = self.parser.parse_args()
        
        if not args.command:
            self.parser.print_help()
            return
        
        # Handle MITRE commands
        if args.command == "mitre":
            if not args.mitre_command:
                self.parser.parse_args(["mitre", "--help"])
                return
            
            if args.mitre_command == "tactics":
                self._list_tactics()
            elif args.mitre_command == "techniques":
                self._list_techniques(args.tactic)
            elif args.mitre_command == "technique":
                self._show_technique(args.technique_id)
        
        # Handle Sigma commands
        elif args.command == "sigma":
            if not args.sigma_command:
                self.parser.parse_args(["sigma", "--help"])
                return
            
            if args.sigma_command == "list":
                self._list_sigma_rules(args.technique, args.search)
            elif args.sigma_command == "show":
                self._show_sigma_rule(args.rule_id)
            elif args.sigma_command == "convert":
                self._convert_sigma_rule(args.rule_id)
        
        # Handle Splunk commands
        elif args.command == "splunk":
            if not args.splunk_command:
                self.parser.parse_args(["splunk", "--help"])
                return
            
            if args.splunk_command == "test":
                self._test_splunk_connection()
            elif args.splunk_command == "query":
                self._execute_splunk_query(args.query, args.earliest, args.latest, args.count)
            elif args.splunk_command == "rule":
                self._execute_sigma_rule(args.rule_id, args.earliest, args.latest, args.count)
        
        # Handle Mapping commands
        elif args.command == "mapping":
            if not args.mapping_command:
                self.parser.parse_args(["mapping", "--help"])
                return
            
            if args.mapping_command == "list":
                self._list_mappings(args.category)
            elif args.mapping_command == "add":
                self._add_mapping(args.category, args.field, args.mapped_field)
            elif args.mapping_command == "remove":
                self._remove_mapping(args.category, args.field)
        
        # Handle Hunt command
        elif args.command == "hunt":
            self._execute_hunt(args.technique_id, args.earliest, args.latest, args.count)
    
    def _list_tactics(self):
        """List all MITRE tactics"""
        tactics = self.mitre_parser.get_tactics()
        
        print("\nMITRE ATT&CK Tactics:\n")
        print(f"{'ID':<10}{'Name':<30}{'Description':<50}")
        print("-" * 90)
        
        for tactic in tactics:
            description = tactic.get('description', '')
            if len(description) > 47:
                description = description[:47] + "..."
            
            print(f"{tactic['id']:<10}{tactic['name']:<30}{description:<50}")
    
    def _list_techniques(self, tactic_id: Optional[str] = None):
        """
        List MITRE techniques, optionally filtered by tactic.
        
        Args:
            tactic_id: Optional tactic ID to filter by
        """
        techniques = self.mitre_parser.get_techniques(tactic_id)
        
        if tactic_id:
            tactic = self.mitre_parser.get_tactic_by_id(tactic_id)
            if tactic:
                print(f"\nMITRE ATT&CK Techniques for Tactic: {tactic['name']} ({tactic_id})\n")
            else:
                print(f"\nMITRE ATT&CK Techniques (filtered by unknown tactic {tactic_id})\n")
        else:
            print("\nAll MITRE ATT&CK Techniques:\n")
        
        print(f"{'ID':<15}{'Name':<40}{'Sub':<5}")
        print("-" * 60)
        
        for technique in techniques:
            sub = "Yes" if technique['is_subtechnique'] else "No"
            print(f"{technique['id']:<15}{technique['name']:<40}{sub:<5}")
    
    def _show_technique(self, technique_id: str):
        """
        Show details for a specific MITRE technique.
        
        Args:
            technique_id: Technique ID
        """
        technique = self.mitre_parser.get_technique_by_id(technique_id)
        
        if not technique:
            print(f"Technique {technique_id} not found")
            return
        
        print(f"\nTechnique: {technique['name']} ({technique_id})")
        print("-" * 80)
        
        print(f"Description: {technique['description']}")
        print()
        
        if technique['detection']:
            print(f"Detection: {technique['detection']}")
            print()
        
        print(f"Tactics: {', '.join(technique['tactics'])}")
        
        if technique['is_subtechnique']:
            print(f"Parent Technique: {technique['parent_id']}")
        
        print(f"URL: {technique['url']}")
        
        # Show associated Sigma rules
        sigma_rules = self.sigma_loader.get_rules_by_technique(technique_id)
        if sigma_rules:
            print(f"\nAssociated Sigma Rules ({len(sigma_rules)}):")
            print("-" * 80)
            
            for rule in sigma_rules:
                print(f"- {rule.get('id')}: {rule.get('title')}")
    
    def _list_sigma_rules(self, technique_id: Optional[str] = None, 
                          search_query: Optional[str] = None):
        """
        List Sigma rules, optionally filtered by technique or search query.
        
        Args:
            technique_id: Optional technique ID to filter by
            search_query: Optional search query to filter by
        """
        if technique_id:
            rules = self.sigma_loader.get_rules_by_technique(technique_id)
            technique = self.mitre_parser.get_technique_by_id(technique_id)
            
            if technique:
                print(f"\nSigma Rules for Technique: {technique['name']} ({technique_id})\n")
            else:
                print(f"\nSigma Rules for Technique: {technique_id}\n")
        elif search_query:
            rules = self.sigma_loader.search_rules(search_query)
            print(f"\nSigma Rules matching '{search_query}':\n")
        else:
            rules = self.sigma_loader.get_all_rules()
            print(f"\nAll Sigma Rules ({len(rules)}):\n")
        
        print(f"{'ID':<40}{'Title':<60}")
        print("-" * 100)
        
        for rule in rules:
            title = rule.get('title', '')
            if len(title) > 57:
                title = title[:57] + "..."
            
            print(f"{rule.get('id', ''):<40}{title:<60}")
    
    def _show_sigma_rule(self, rule_id: str):
        """
        Show details for a specific Sigma rule.
        
        Args:
            rule_id: Rule ID
        """
        rule = self.sigma_loader.get_rule_by_id(rule_id)
        
        if not rule:
            print(f"Rule {rule_id} not found")
            return
        
        print(f"\nSigma Rule: {rule.get('title')} ({rule_id})")
        print("-" * 80)
        
        if 'description' in rule:
            print(f"Description: {rule['description']}")
            print()
        
        if 'author' in rule:
            print(f"Author: {rule['author']}")
        
        if 'status' in rule:
            print(f"Status: {rule['status']}")
        
        if 'level' in rule:
            print(f"Level: {rule['level']}")
        
        if 'tags' in rule:
            tags = rule['tags']
            if not isinstance(tags, list):
                tags = [tags]
            
            print(f"Tags: {', '.join(tags)}")
        
        print(f"\nDetection:")
        print(json.dumps(rule.get('detection', {}), indent=2))
        
        # Try to convert to Splunk query
        splunk_query = self.sigma_loader.convert_rule_to_splunk(rule_id)
        if splunk_query:
            print(f"\nSplunk Query:")
            print(splunk_query)
    
    def _convert_sigma_rule(self, rule_id: str):
        """
        Convert a Sigma rule to Splunk SPL.
        
        Args:
            rule_id: Rule ID
        """
        splunk_query = self.sigma_loader.convert_rule_to_splunk(rule_id)
        
        if not splunk_query:
            print(f"Failed to convert rule {rule_id} to Splunk query")
            return
        
        print(f"\nSplunk Query for Rule {rule_id}:")
        print("-" * 80)
        print(splunk_query)
    
    def _test_splunk_connection(self):
        """Test the connection to Splunk"""
        print(f"Testing connection to Splunk at {config.SPLUNK_HOST}:{config.SPLUNK_PORT}...")
        
        success = self.splunk_query.connect()
        
        if success:
            print(f"Successfully connected to Splunk")
        else:
            print(f"Failed to connect to Splunk")
    
    def _execute_splunk_query(self, query: str, earliest: str, latest: str, count: int):
        """
        Execute a Splunk query.
        
        Args:
            query: Splunk SPL query
            earliest: Earliest time for search
            latest: Latest time for search
            count: Maximum number of results
        """
        print(f"Executing Splunk query: {query}")
        print(f"Time range: {earliest} to {latest}")
        
        result = self.splunk_query.execute_query(
            query=query,
            earliest_time=earliest,
            latest_time=latest,
            max_count=count
        )
        
        if result["status"] == "error":
            print(f"Error: {result['error']}")
            return
        elif result["status"] == "timeout":
            print(f"Timeout: {result['error']}")
            return
        
        print(f"\nResults: {result['result_count']} (out of {result.get('total_result_count', 'unknown')})")
        print(f"Execution time: {result['execution_time']:.2f} seconds")
        
        if result["result_count"] == 0:
            print("No results found")
            return
        
        # Get field names from first result
        fields = list(result["results"][0].keys())
        
        # Print results as a table
        self._print_results_table(result["results"], fields)
    
    def _execute_sigma_rule(self, rule_id: str, earliest: str, latest: str, count: int):
        """
        Execute a Sigma rule as a Splunk query.
        
        Args:
            rule_id: Sigma rule ID
            earliest: Earliest time for search
            latest: Latest time for search
            count: Maximum number of results
        """
        splunk_query = self.sigma_loader.convert_rule_to_splunk(rule_id)
        
        if not splunk_query:
            print(f"Failed to convert rule {rule_id} to Splunk query")
            return
        
        rule = self.sigma_loader.get_rule_by_id(rule_id)
        
        print(f"Executing Sigma rule: {rule.get('title')} ({rule_id})")
        print(f"Splunk query: {splunk_query}")
        print(f"Time range: {earliest} to {latest}")
        
        result = self.splunk_query.execute_query(
            query=splunk_query,
            earliest_time=earliest,
            latest_time=latest,
            max_count=count
        )
        
        if result["status"] == "error":
            print(f"Error: {result['error']}")
            return
        elif result["status"] == "timeout":
            print(f"Timeout: {result['error']}")
            return
        
        print(f"\nResults: {result['result_count']} (out of {result.get('total_result_count', 'unknown')})")
        print(f"Execution time: {result['execution_time']:.2f} seconds")
        
        if result["result_count"] == 0:
            print("No results found")
            return
        
        # Get field names from first result
        fields = list(result["results"][0].keys())
        
        # Print results as a table
        self._print_results_table(result["results"], fields)
    
    def _print_results_table(self, results: List[Dict[str, Any]], fields: List[str]):
        """
        Print results as a table.
        
        Args:
            results: List of result dictionaries
            fields: List of field names to include
        """
        # Limit fields if there are too many
        max_fields = 5
        if len(fields) > max_fields:
            print(f"\nShowing {max_fields} fields out of {len(fields)}")
            fields = fields[:max_fields]
        
        # Determine column widths
        col_widths = {}
        for field in fields:
            col_widths[field] = max(len(field), max(len(str(r.get(field, ''))) for r in results[:10]))
            col_widths[field] = min(col_widths[field], 50)  # Cap width at 50 chars
        
        # Print header
        header = " | ".join(f"{field:{col_widths[field]}}" for field in fields)
        print("\n" + header)
        print("-" * len(header))
        
        # Print rows
        for result in results:
            row = []
            for field in fields:
                value = str(result.get(field, ''))
                if len(value) > col_widths[field]:
                    value = value[:col_widths[field]-3] + "..."
                row.append(f"{value:{col_widths[field]}}")
            
            print(" | ".join(row))
    
    def _list_mappings(self, category: Optional[str] = None):
        """
        List field mappings.
        
        Args:
            category: Optional category to filter by
        """
        if category:
            if category not in self.field_mapper.get_categories():
                print(f"Category {category} not found")
                print(f"Available categories: {', '.join(self.field_mapper.get_categories())}")
                return
            
            mappings = {category: self.field_mapper.get_fields_for_category(category)}
        else:
            mappings = self.field_mapper.get_all_mappings()
        
        print("\nField Mappings:")
        
        for cat, cat_mappings in mappings.items():
            print(f"\n{cat}:")
            print("-" * 80)
            
            print(f"{'Generic Field':<30}{'Mapped Field':<30}")
            print("-" * 60)
            
            for field, mapped_field in cat_mappings.items():
                print(f"{field:<30}{mapped_field:<30}")
    
    def _add_mapping(self, category: str, field: str, mapped_field: str):
        """
        Add or update a field mapping.
        
        Args:
            category: Field category
            field: Generic field name
            mapped_field: Mapped field name
        """
        success = self.field_mapper.add_mapping(category, field, mapped_field)
        
        if success:
            print(f"Added mapping: {category}.{field} -> {mapped_field}")
        else:
            print(f"Failed to add mapping")
    
    def _remove_mapping(self, category: str, field: str):
        """
        Remove a field mapping.
        
        Args:
            category: Field category
            field: Generic field name
        """
        success = self.field_mapper.remove_mapping(category, field)
        
        if success:
            print(f"Removed mapping: {category}.{field}")
        else:
            print(f"Mapping not found: {category}.{field}")
    
    def _execute_hunt(self, technique_id: str, earliest: str, latest: str, count: int):
        """
        Execute a hunt for a MITRE technique.
        
        Args:
            technique_id: MITRE technique ID
            earliest: Earliest time for search
            latest: Latest time for search
            count: Maximum number of results
        """
        # Check if technique exists
        technique = self.mitre_parser.get_technique_by_id(technique_id)
        if not technique:
            print(f"Technique {technique_id} not found")
            return
        
        print(f"Starting hunt for technique: {technique['name']} ({technique_id})")
        
        # Get Sigma rules for the technique
        sigma_rules = self.sigma_loader.get_rules_by_technique(technique_id)
        
        if not sigma_rules:
            print(f"No Sigma rules found for technique {technique_id}")
            return
        
        print(f"Found {len(sigma_rules)} Sigma rules for this technique")
        
        # Execute each rule
        results = []
        
        for rule in sigma_rules:
            rule_id = rule.get('id')
            
            print(f"\nExecuting rule: {rule.get('title')} ({rule_id})")
            
            # Convert to Splunk query
            splunk_query = self.sigma_loader.convert_rule_to_splunk(rule_id)
            
            if not splunk_query:
                print(f"Failed to convert rule {rule_id} to Splunk query")
                continue
            
            print(f"Splunk query: {splunk_query}")
            
            # Execute query
            result = self.splunk_query.execute_query(
                query=splunk_query,
                earliest_time=earliest,
                latest_time=latest,
                max_count=count
            )
            
            if result["status"] == "error":
                print(f"Error: {result['error']}")
                continue
            elif result["status"] == "timeout":
                print(f"Timeout: {result['error']}")
                continue
            
            print(f"Results: {result['result_count']} (out of {result.get('total_result_count', 'unknown')})")
            
            # Store results for summary
            results.append({
                "rule_id": rule_id,
                "rule_title": rule.get('title'),
                "query": splunk_query,
                "result_count": result["result_count"],
                "total_result_count": result.get("total_result_count", 0),
                "status": result["status"],
                "execution_time": result["execution_time"]
            })
        
        # Print summary
        print("\nHunt Summary:")
        print("-" * 80)
        
        print(f"Technique: {technique['name']} ({technique_id})")
        print(f"Time range: {earliest} to {latest}")
        print(f"Rules executed: {len(results)}")
        
        total_findings = sum(r["result_count"] for r in results)
        print(f"Total findings: {total_findings}")
        
        # Print results for each rule
        if results:
            print("\nFindings by rule:")
            print("-" * 80)
            
            for result in results:
                print(f"{result['rule_title']} ({result['rule_id']}): {result['result_count']} findings")

if __name__ == "__main__":
    cli = SecurityHunterCLI()
    cli.run()
