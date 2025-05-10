import json
import logging
import time
from typing import Dict, List, Optional, Union, Any

import splunklib.client as client
import splunklib.results as results

import config

logger = logging.getLogger(__name__)

class SplunkQueryExecutor:
    """Execute queries against Splunk and retrieve results"""
    
    def __init__(self):
        """Initialize the Splunk query executor"""
        self.service = None
        self.connected = False
    
    def connect(self, host: str = config.SPLUNK_HOST, 
               port: int = config.SPLUNK_PORT,
               username: str = config.SPLUNK_USERNAME,
               password: str = config.SPLUNK_PASSWORD,
               scheme: str = config.SPLUNK_SCHEME,
               app: str = config.SPLUNK_APP,
               owner: str = config.SPLUNK_OWNER) -> bool:
        """
        Connect to Splunk.
        
        Args:
            host: Splunk host
            port: Splunk management port
            username: Splunk username
            password: Splunk password
            scheme: Connection scheme (http/https)
            app: Splunk app context
            owner: Splunk owner context
        
        Returns:
            True if connection successful, False otherwise
        """
        try:
            self.service = client.connect(
                host=host,
                port=port,
                username=username,
                password=password,
                scheme=scheme,
                app=app,
                owner=owner
            )
            self.connected = True
            logger.info(f"Successfully connected to Splunk at {host}:{port}")
            return True
        except Exception as e:
            logger.error(f"Failed to connect to Splunk: {str(e)}")
            self.connected = False
            return False
    
    def execute_query(self, query: str, earliest_time: str = "-24h", 
                      latest_time: str = "now", 
                      exec_mode: str = "normal",
                      index: str = config.SPLUNK_INDEX,
                      max_count: int = 1000,
                      timeout: int = 300) -> Dict[str, Any]:
        """
        Execute a Splunk search query.
        
        Args:
            query: Splunk SPL query string
            earliest_time: Search time range start
            latest_time: Search time range end
            exec_mode: Execution mode (normal/blocking)
            index: Splunk index to search
            max_count: Maximum number of results to return
            timeout: Query timeout in seconds
        
        Returns:
            Dictionary with query results and metadata
        """
        if not self.connected:
            success = self.connect()
            if not success:
                return {
                    "status": "error",
                    "error": "Not connected to Splunk",
                    "query": query,
                    "results": []
                }
        
        # Add index if not already in query
        if "index=" not in query:
            query = f"index={index} " + query
        
        logger.info(f"Executing Splunk query: {query}")
        start_time = time.time()
        
        try:
            # Create the job
            job = self.service.jobs.create(
                query,
                earliest_time=earliest_time,
                latest_time=latest_time,
                exec_mode=exec_mode
            )
            
            # Wait for the job to complete or timeout
            elapsed_time = 0
            while not job.is_done() and elapsed_time < timeout:
                time.sleep(2)
                elapsed_time = time.time() - start_time
                job.refresh()
            
            if not job.is_done():
                job.cancel()
                return {
                    "status": "timeout",
                    "error": f"Query timed out after {timeout} seconds",
                    "query": query,
                    "results": []
                }
            
            # Check if the job has results
            if int(job["resultCount"]) == 0:
                return {
                    "status": "success",
                    "message": "Query completed successfully but returned no results",
                    "query": query,
                    "results": [],
                    "result_count": 0,
                    "execution_time": time.time() - start_time
                }
            
            # Get the results
            result_count = int(job["resultCount"])
            query_results = []
            
            # Limit result count
            if result_count > max_count:
                logger.warning(f"Query returned {result_count} results, limiting to {max_count}")
                result_count = max_count
            
            # Get the results
            result_stream = job.results(count=result_count)
            reader = results.ResultsReader(result_stream)
            
            for result in reader:
                if isinstance(result, dict):
                    query_results.append(result)
                
                # Check if we've reached the maximum result count
                if len(query_results) >= max_count:
                    break
            
            return {
                "status": "success",
                "message": "Query completed successfully",
                "query": query,
                "results": query_results,
                "result_count": len(query_results),
                "total_result_count": int(job["resultCount"]),
                "execution_time": time.time() - start_time,
                "scan_count": int(job["scanCount"]) if "scanCount" in job else 0,
                "event_count": int(job["eventCount"]) if "eventCount" in job else 0,
                "field_summary": self._get_field_summary(job) if query_results else {}
            }
        
        except Exception as e:
            logger.error(f"Error executing Splunk query: {str(e)}")
            return {
                "status": "error",
                "error": str(e),
                "query": query,
                "results": []
            }
    
    def _get_field_summary(self, job) -> Dict[str, Any]:
        """
        Get summary of fields present in the results.
        
        Args:
            job: Splunk job object
        
        Returns:
            Dictionary with field summary information
        """
        try:
            summary = {}
            field_summary = job.results(path="summary")
            reader = results.ResultsReader(field_summary)
            
            for result in reader:
                if isinstance(result, dict):
                    name = result.get("name")
                    if name:
                        summary[name] = {
                            "count": result.get("count", 0),
                            "distinct_count": result.get("distinct_count", 0),
                            "is_exact": result.get("is_exact", "0") == "1",
                            "min": result.get("min"),
                            "max": result.get("max"),
                            "mean": result.get("mean"),
                            "stdev": result.get("stdev")
                        }
            
            return summary
        except Exception as e:
            logger.error(f"Error getting field summary: {str(e)}")
            return {}
    
    def get_field_values(self, index: str, field: str, 
                        earliest_time: str = "-24h", 
                        latest_time: str = "now") -> List[str]:
        """
        Get unique values for a field in the given index.
        
        Args:
            index: Splunk index to search
            field: Field name
            earliest_time: Search time range start
            latest_time: Search time range end
        
        Returns:
            List of unique values for the field
        """
        if not self.connected:
            success = self.connect()
            if not success:
                return []
        
        try:
            # Build a query to get distinct values for the field
            query = f'search index={index} | stats count by "{field}" | sort -count'
            
            # Execute the query
            result = self.execute_query(
                query=query,
                earliest_time=earliest_time, 
                latest_time=latest_time,
                exec_mode="blocking"
            )
            
            # Extract the field values
            if result["status"] == "success":
                values = [r.get(field, "") for r in result["results"]]
                return [v for v in values if v]  # Filter out empty values
            
            return []
        
        except Exception as e:
            logger.error(f"Error getting field values for {field}: {str(e)}")
            return []
