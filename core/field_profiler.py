import logging
import re
import json
from typing import Dict, List, Any, Optional, Set, Tuple
import yaml

from core.sigma_loader import SigmaLoader
from core.splunk_query import SplunkQueryExecutor
from core.field_mapper import FieldMapper

logger = logging.getLogger(__name__)

class FieldProfiler:
    """
    Performs statistical profiling of fields in Splunk data related to MITRE techniques
    and Sigma rules to enable faster, more targeted hunting.
    """
    
    def __init__(self, sigma_loader: SigmaLoader, field_mapper: FieldMapper, splunk_query: SplunkQueryExecutor):
        """
        Initialize the field profiler.
        
        Args:
            sigma_loader: Initialized SigmaLoader instance
            field_mapper: Initialized FieldMapper instance
            splunk_query: Initialized SplunkQueryExecutor instance
        """
        self.sigma_loader = sigma_loader
        self.field_mapper = field_mapper
        self.splunk_query = splunk_query
        
        # Cache for extracted fields from Sigma rules
        self.field_cache = {}
        
    def extract_fields_from_rule(self, rule_id: str) -> Set[str]:
        """
        Extract field names from a Sigma rule's detection section.
        
        Args:
            rule_id: The ID of the Sigma rule
            
        Returns:
            Set of field names used in the rule
        """
        # Check cache first
        if rule_id in self.field_cache:
            return self.field_cache[rule_id]
            
        rule = self.sigma_loader.get_rule_by_id(rule_id)
        if not rule:
            logger.warning(f"Rule {rule_id} not found")
            return set()
            
        # Extract fields from detection section
        fields = set()
        detection = rule.get('detection', {})
        
        # Process all detection sections
        for section_name, section_content in detection.items():
            # Skip condition sections which contain the logical operators
            if section_name == 'condition':
                continue
                
            # Process selection sections
            if isinstance(section_content, dict):
                fields.update(section_content.keys())
            elif isinstance(section_content, list):
                # Handle list of dicts
                for item in section_content:
                    if isinstance(item, dict):
                        fields.update(item.keys())
        
        # Apply field mappings to convert generic fields to Splunk-specific fields
        mapped_fields = set()
        for field in fields:
            # Check if this is a negated field (e.g., NOT fieldname)
            is_negated = False
            if field.startswith('NOT '):
                is_negated = True
                field = field[4:]  # Remove the 'NOT ' prefix
                
            # Try to find a mapping category that contains this field
            mapped_field = None
            for category in self.field_mapper.get_categories():
                category_fields = self.field_mapper.get_fields_for_category(category)
                if field in category_fields:
                    mapped_field = category_fields[field]
                    break
                    
            # Add the mapped field (or original if no mapping found)
            if mapped_field:
                if is_negated:
                    mapped_fields.add(f"NOT {mapped_field}")
                else:
                    mapped_fields.add(mapped_field)
            else:
                if is_negated:
                    mapped_fields.add(f"NOT {field}")
                else:
                    mapped_fields.add(field)
        
        # Cache the result
        self.field_cache[rule_id] = mapped_fields
        return mapped_fields
        
    def extract_fields_from_technique(self, technique_id: str) -> Dict[str, Set[str]]:
        """
        Extract all fields from Sigma rules associated with a MITRE technique.
        
        Args:
            technique_id: The MITRE ATT&CK technique ID
            
        Returns:
            Dictionary mapping rule IDs to sets of field names
        """
        # Get Sigma rules for the technique
        sigma_rules = self.sigma_loader.get_rules_by_technique(technique_id)
        
        # Extract fields from each rule
        rule_fields = {}
        for rule in sigma_rules:
            rule_id = rule.get('id')
            if rule_id:
                fields = self.extract_fields_from_rule(rule_id)
                if fields:
                    rule_fields[rule_id] = fields
        
        return rule_fields
        
    def get_common_fields(self, technique_id: str, min_occurrence: int = 2) -> Dict[str, int]:
        """
        Get fields that appear frequently across Sigma rules for a technique.
        
        Args:
            technique_id: The MITRE ATT&CK technique ID
            min_occurrence: Minimum number of rules a field must appear in
            
        Returns:
            Dictionary mapping field names to occurrence counts
        """
        rule_fields = self.extract_fields_from_technique(technique_id)
        
        # Count field occurrences across rules
        field_counts = {}
        for fields in rule_fields.values():
            for field in fields:
                field_counts[field] = field_counts.get(field, 0) + 1
        
        # Filter to fields that meet the minimum occurrence threshold
        common_fields = {field: count for field, count in field_counts.items() 
                        if count >= min_occurrence}
        
        # Sort by occurrence count (descending)
        return dict(sorted(common_fields.items(), key=lambda x: x[1], reverse=True))
    
    def generate_profiling_queries(self, fields: List[str], 
                                 index: str = "*", 
                                 top_values_limit: int = 10, 
                                 rare_values_limit: int = 10) -> Dict[str, str]:
        """
        Generate statistical Splunk queries for profiling fields.
        
        Args:
            fields: List of field names to profile
            index: Splunk index to search
            top_values_limit: Number of most frequent values to retrieve
            rare_values_limit: Number of least frequent values to retrieve
            
        Returns:
            Dictionary mapping query types to Splunk SPL queries
        """
        queries = {}
        
        # For each field, generate top and rare value queries
        for field in fields:
            # Clean the field name to handle negations
            clean_field = field.replace('NOT ', '')
            
            # Top values query
            top_query = f'search index={index} | stats count by {clean_field} | sort -count | head {top_values_limit}'
            queries[f"top_{clean_field}"] = top_query
            
            # Rare values query
            rare_query = f'search index={index} | stats count by {clean_field} | sort count | head {rare_values_limit}'
            queries[f"rare_{clean_field}"] = rare_query
            
            # Field value entropy query (for command lines and other text fields)
            # This helps identify obfuscation or unusual patterns
            if clean_field in ['CommandLine', 'command_line', 'process_command_line', 'cmd_line', 
                           'process_cmdline', 'powershell_command', 'script_text']:
                entropy_query = (
                    f'search index={index} {clean_field}=* | '
                    f'eval len=len({clean_field}), '
                    f'entropy=round(entropy({clean_field}),2), '
                    f'entropy_per_char=round(entropy({clean_field})/len({clean_field}),4) | '
                    f'where len>10 AND entropy_per_char>0.6 | '
                    f'sort -entropy_per_char | head 10'
                )
                queries[f"entropy_{clean_field}"] = entropy_query
        
        return queries
    
    def execute_profiling_queries(self, 
                                queries: Dict[str, str], 
                                earliest_time: str = "-24h", 
                                latest_time: str = "now", 
                                max_count: int = 100) -> Dict[str, Any]:
        """
        Execute statistical profiling queries and return the results.
        
        Args:
            queries: Dictionary mapping query types to Splunk SPL queries
            earliest_time: Search time range start
            latest_time: Search time range end
            max_count: Maximum number of results to return
            
        Returns:
            Dictionary with query results for each query type
        """
        results = {}
        
        for query_type, query in queries.items():
            logger.info(f"Executing profiling query: {query_type}")
            result = self.splunk_query.execute_query(
                query=query,
                earliest_time=earliest_time,
                latest_time=latest_time,
                max_count=max_count
            )
            
            results[query_type] = result
        
        return results
    
    def generate_fast_pass_queries(self, profiling_results: Dict[str, Any], 
                                index: str = "*") -> Dict[str, Dict[str, Any]]:
        """
        Generate targeted exact-match queries based on profiling results.
        
        Args:
            profiling_results: Results from execute_profiling_queries
            index: Splunk index to search
            
        Returns:
            Dictionary mapping query types to query details
        """
        fast_pass_queries = {}
        
        for query_type, result in profiling_results.items():
            # Skip if no results or query failed
            if not result.get('success') or not result.get('results'):
                continue
                
            # Parse query type to extract field name and query category
            parts = query_type.split('_', 1)
            if len(parts) != 2:
                continue
                
            category, field = parts
            
            # Generate different types of fast pass queries based on category
            if category == 'rare':
                # Create exact match queries for rare values
                for i, item in enumerate(result['results']):
                    if field in item:
                        value = item[field]
                        exact_query = f'search index={index} {field}="{value}"'
                        
                        fast_pass_queries[f"exact_rare_{field}_{i}"] = {
                            'query': exact_query,
                            'field': field,
                            'value': value,
                            'priority': 'high',  # Rare values get high priority
                            'reason': f'Rare value for {field}'
                        }
            
            elif category == 'top':
                # For top values, only create queries for suspicious items
                # This requires domain knowledge about which fields/values are suspicious
                for i, item in enumerate(result['results']):
                    if field in item:
                        value = item[field]
                        
                        # Check if this is a potentially suspicious value based on heuristics
                        is_suspicious = False
                        suspicious_reason = None
                        
                        # Example heuristics (expand based on your threat intelligence)
                        if field in ['process_name', 'Image', 'process'] and value.lower() in [
                            'powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe', 'regsvr32.exe',
                            'rundll32.exe', 'mshta.exe', 'certutil.exe', 'bitsadmin.exe'
                        ]:
                            is_suspicious = True
                            suspicious_reason = f'Common tool used in attacks: {value}'
                        
                        if is_suspicious:
                            exact_query = f'search index={index} {field}="{value}"'
                            
                            fast_pass_queries[f"exact_suspicious_{field}_{i}"] = {
                                'query': exact_query,
                                'field': field,
                                'value': value,
                                'priority': 'medium',
                                'reason': suspicious_reason
                            }
            
            elif category == 'entropy':
                # Create queries for high-entropy command lines
                for i, item in enumerate(result['results']):
                    if field in item and 'entropy_per_char' in item:
                        value = item[field]
                        entropy = float(item['entropy_per_char'])
                        
                        # Only query for very high entropy values
                        if entropy > 0.8:
                            exact_query = f'search index={index} {field}="{value}"'
                            
                            fast_pass_queries[f"exact_entropy_{field}_{i}"] = {
                                'query': exact_query,
                                'field': field,
                                'value': value[:50] + '...' if len(value) > 50 else value,  # Truncate long values
                                'priority': 'high',
                                'reason': f'High entropy text (possible obfuscation): {entropy}'
                            }
        
        return fast_pass_queries
    
    def execute_fast_pass_queries(self, 
                               fast_pass_queries: Dict[str, Dict[str, Any]],
                               earliest_time: str = "-24h", 
                               latest_time: str = "now", 
                               max_count: int = 100) -> Dict[str, Any]:
        """
        Execute fast pass queries and return the results.
        
        Args:
            fast_pass_queries: Dictionary mapping query types to query details
            earliest_time: Search time range start
            latest_time: Search time range end
            max_count: Maximum number of results to return
            
        Returns:
            Dictionary with query results for each query type
        """
        results = {}
        
        # Sort queries by priority
        priority_order = {'high': 0, 'medium': 1, 'low': 2}
        sorted_queries = sorted(
            fast_pass_queries.items(), 
            key=lambda x: priority_order.get(x[1].get('priority', 'low'), 3)
        )
        
        for query_type, query_details in sorted_queries:
            logger.info(f"Executing fast pass query: {query_type}")
            result = self.splunk_query.execute_query(
                query=query_details['query'],
                earliest_time=earliest_time,
                latest_time=latest_time,
                max_count=max_count
            )
            
            # Add query details to result
            result['query_details'] = {
                'field': query_details.get('field'),
                'value': query_details.get('value'),
                'priority': query_details.get('priority'),
                'reason': query_details.get('reason')
            }
            
            results[query_type] = result
        
        return results
    
    def profile_technique(self, 
                        technique_id: str, 
                        index: str = "*", 
                        earliest_time: str = "-24h", 
                        latest_time: str = "now",
                        max_field_count: int = 5,
                        max_count: int = 100) -> Dict[str, Any]:
        """
        Perform complete field profiling for a MITRE technique.
        
        Args:
            technique_id: The MITRE ATT&CK technique ID
            index: Splunk index to search
            earliest_time: Search time range start
            latest_time: Search time range end
            max_field_count: Maximum number of fields to profile
            max_count: Maximum number of results to return
            
        Returns:
            Dictionary with profiling results
        """
        # Step 1: Extract common fields from Sigma rules for this technique
        common_fields = self.get_common_fields(technique_id)
        logger.info(f"Found {len(common_fields)} common fields for technique {technique_id}")
        
        # Step 2: Select the most relevant fields to profile (limited to max_field_count)
        selected_fields = list(common_fields.keys())[:max_field_count]
        
        # Step 3: Generate profiling queries
        profiling_queries = self.generate_profiling_queries(
            fields=selected_fields,
            index=index
        )
        
        # Step 4: Execute profiling queries
        profiling_results = self.execute_profiling_queries(
            queries=profiling_queries,
            earliest_time=earliest_time,
            latest_time=latest_time,
            max_count=max_count
        )
        
        # Step 5: Generate fast pass queries
        fast_pass_queries = self.generate_fast_pass_queries(
            profiling_results=profiling_results,
            index=index
        )
        
        # Step 6: Execute fast pass queries
        fast_pass_results = self.execute_fast_pass_queries(
            fast_pass_queries=fast_pass_queries,
            earliest_time=earliest_time,
            latest_time=latest_time,
            max_count=max_count
        )
        
        # Step 7: Compile and return complete results
        return {
            'technique_id': technique_id,
            'profiled_fields': {field: count for field, count in common_fields.items() if field in selected_fields},
            'profiling_results': profiling_results,
            'fast_pass_queries': fast_pass_queries,
            'fast_pass_results': fast_pass_results,
            'timerange': {
                'earliest': earliest_time,
                'latest': latest_time
            }
        }