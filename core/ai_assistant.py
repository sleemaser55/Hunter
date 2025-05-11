"""
AI Assistant for Security Hunter
Uses OpenAI to generate insights, queries, and analysis based on security data
"""
import os
import json
import logging
from typing import Dict, List, Any, Optional, Union

# the newest OpenAI model is "gpt-4o" which was released May 13, 2024.
# do not change this unless explicitly requested by the user
from openai import OpenAI

logger = logging.getLogger(__name__)

class AIAssistant:
    """
    AI Assistant for Security Hunter
    Provides AI-powered analysis and query generation using OpenAI
    """
    
    def __init__(self):
        """Initialize the AI Assistant"""
        self.openai_api_key = os.environ.get("OPENAI_API_KEY")
        self.openai_endpoint = os.environ.get("OPENAI_ENDPOINT")
        
        if not self.openai_api_key:
            logger.warning("OPENAI_API_KEY environment variable not set")
            self.client = None
        else:
            self.client = OpenAI(
                api_key=self.openai_api_key,
                base_url=self.openai_endpoint
            )
    
    def is_available(self) -> bool:
        """Check if the AI Assistant is available"""
        return self.client is not None
    
    def analyze_ttp(self, 
                  technique_id: str, 
                  technique_data: Dict[str, Any],
                  sigma_rules: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze a MITRE ATT&CK technique and related Sigma rules
        
        Args:
            technique_id: MITRE ATT&CK technique ID
            technique_data: Technique data dictionary
            sigma_rules: List of Sigma rules related to the technique
            
        Returns:
            Dictionary with analysis results
        """
        if not self.is_available():
            return {"error": "AI Assistant not available"}
        
        try:
            # Prepare input for OpenAI
            system_prompt = """You are an expert security analyst specialized in MITRE ATT&CK and threat hunting.
            Analyze the provided technique and Sigma rules to provide insights for security analysts.
            Focus on practical advice for detection, common evasion tactics, and key indicators to look for.
            Format your response as JSON with the following structure:
            {
                "summary": "Brief summary of the technique and how it's typically used by attackers",
                "key_indicators": ["List of important indicators to look for"],
                "common_artifacts": ["Common artifacts left behind"],
                "evasion_tactics": ["Common evasion methods used by attackers"],
                "hunting_tips": ["Practical tips for hunting this technique"],
                "suggested_data_sources": ["Data sources that are useful for detection"],
                "additional_queries": ["Additional queries that might be helpful"]
            }
            Be specific, technical, and actionable in your advice."""
            
            # Prepare technique data
            technique_summary = {
                "id": technique_id,
                "name": technique_data.get("name", ""),
                "description": technique_data.get("description", ""),
                "tactics": technique_data.get("tactics", []),
                "platforms": technique_data.get("platforms", []),
                "data_sources": technique_data.get("data_sources", []),
                "detection": technique_data.get("detection", ""),
                "sigma_rule_count": len(sigma_rules),
                "sigma_rule_examples": [
                    {
                        "title": rule.get("title", ""),
                        "description": rule.get("description", ""),
                        "detection": rule.get("detection", {})
                    } 
                    for rule in sigma_rules[:3]  # Include up to 3 examples
                ]
            }
            
            # Default result in case of failure
            result = {
                "summary": f"Analysis of {technique_id}: {technique_data.get('name', '')}",
                "key_indicators": [],
                "common_artifacts": [],
                "evasion_tactics": [],
                "hunting_tips": [],
                "suggested_data_sources": [],
                "additional_queries": []
            }
            
            # Make API call to OpenAI if available
            if self.client:
                response = self.client.chat.completions.create(
                    model="gpt-4o",
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": f"Analyze this MITRE ATT&CK technique and related Sigma rules: {json.dumps(technique_summary)}"}
                    ],
                    response_format={"type": "json_object"},
                    temperature=0.1  # Keep it factual
                )
                
                # Parse response if valid
                if response.choices and response.choices[0].message.content:
                    content = response.choices[0].message.content
                    if content:
                        try:
                            result = json.loads(content)
                        except json.JSONDecodeError:
                            logger.error("Error parsing JSON response from OpenAI")
            
            return result
        
        except Exception as e:
            logger.error(f"Error analyzing TTP with OpenAI: {str(e)}")
            return {
                "error": str(e),
                "summary": "Unable to generate AI analysis at this time."
            }
    
    def enhance_query(self, 
                    original_query: str, 
                    technique_id: Optional[str] = None,
                    field_values: Optional[Dict[str, List[str]]] = None) -> Dict[str, Any]:
        """
        Enhance a Splunk query using AI
        
        Args:
            original_query: Original Splunk query
            technique_id: Optional MITRE ATT&CK technique ID for context
            field_values: Optional dictionary of field values from results
            
        Returns:
            Dictionary with enhanced query options
        """
        if not self.is_available():
            return {"error": "AI Assistant not available"}
        
        try:
            # Prepare input for OpenAI
            system_prompt = """You are an expert in Splunk SPL (Search Processing Language) and security analytics.
            Analyze the provided query and suggest improvements or variations that might yield better results.
            Focus on practical improvements such as:
            1. Adding useful fields or conditions
            2. Improving performance
            3. Adding statistical commands that might reveal patterns
            4. Variations that might catch evasion attempts
            
            Format your response as JSON with the following structure:
            {
                "analysis": "Brief analysis of the original query",
                "suggested_improvements": ["List of specific improvements that could be made"],
                "enhanced_queries": [
                    {
                        "name": "Name of the enhanced query",
                        "description": "What this variation aims to accomplish",
                        "query": "The actual enhanced SPL query"
                    }
                ]
            }
            Ensure all queries are valid Splunk SPL syntax. Be specific and practical in your suggestions."""
            
            # Prepare context
            context = {
                "original_query": original_query,
                "technique_id": technique_id,
                "field_values": field_values
            }
            
            # Default result
            result = {
                "analysis": f"Analysis of query: {original_query}",
                "suggested_improvements": [],
                "enhanced_queries": []
            }
            
            # Make API call to OpenAI if available
            if self.client:
                response = self.client.chat.completions.create(
                    model="gpt-4o",
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": f"Enhance this Splunk query with the following context: {json.dumps(context)}"}
                    ],
                    response_format={"type": "json_object"},
                    temperature=0.2
                )
                
                # Parse response if valid
                if response.choices and response.choices[0].message.content:
                    content = response.choices[0].message.content
                    if content:
                        try:
                            result = json.loads(content)
                        except json.JSONDecodeError:
                            logger.error("Error parsing JSON response from OpenAI")
            
            return result
        
        except Exception as e:
            logger.error(f"Error enhancing query with OpenAI: {str(e)}")
            return {
                "error": str(e),
                "analysis": "Unable to generate AI-enhanced queries at this time."
            }
    
    def generate_pivot_queries(self, 
                             result_fields: Dict[str, Any],
                             original_query: str,
                             technique_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Generate pivot queries based on results
        
        Args:
            result_fields: Dictionary of fields and values from results
            original_query: Original query that produced the results
            technique_id: Optional MITRE ATT&CK technique ID for context
            
        Returns:
            Dictionary with pivot query suggestions
        """
        if not self.is_available():
            return {"error": "AI Assistant not available"}
        
        try:
            # Prepare input for OpenAI
            system_prompt = """You are an expert in threat hunting and Splunk SPL (Search Processing Language).
            Analyze the provided result fields and suggest pivot queries that might reveal related malicious activity.
            Focus on practical pivot points such as:
            1. User accounts that might be compromised
            2. Systems that might be affected
            3. Network connections that might be malicious
            4. File artifacts that might be related
            5. Time ranges that might be of interest
            
            Format your response as JSON with the following structure:
            {
                "analysis": "Brief analysis of the result fields",
                "pivot_categories": [
                    {
                        "category": "Category name (e.g., Users, Systems, Network)",
                        "description": "Why this category is relevant",
                        "pivot_queries": [
                            {
                                "name": "Name of the pivot query",
                                "description": "What this pivot aims to investigate",
                                "field": "The field being pivoted on",
                                "value": "The value being used (if applicable)",
                                "query": "The actual Splunk SPL query"
                            }
                        ]
                    }
                ]
            }
            Ensure all queries are valid Splunk SPL syntax. Be specific and practical in your suggestions."""
            
            # Prepare context
            context = {
                "result_fields": result_fields,
                "original_query": original_query,
                "technique_id": technique_id
            }
            
            # Default result
            result = {
                "analysis": "Analysis of result fields",
                "pivot_categories": []
            }
            
            # Make API call to OpenAI if available
            if self.client:
                response = self.client.chat.completions.create(
                    model="gpt-4o",
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": f"Generate pivot queries for these result fields: {json.dumps(context)}"}
                    ],
                    response_format={"type": "json_object"},
                    temperature=0.2
                )
                
                # Parse response if valid
                if response.choices and response.choices[0].message.content:
                    content = response.choices[0].message.content
                    if content:
                        try:
                            result = json.loads(content)
                        except json.JSONDecodeError:
                            logger.error("Error parsing JSON response from OpenAI")
            
            return result
        
        except Exception as e:
            logger.error(f"Error generating pivot queries with OpenAI: {str(e)}")
            return {
                "error": str(e),
                "analysis": "Unable to generate AI pivot suggestions at this time."
            }