#!/usr/bin/env python3
"""
Simple test script for Splunk connection.
"""

import config
from core.splunk_query import SplunkQueryExecutor

def main():
    print(f"Splunk connection details:")
    print(f"Host: {config.SPLUNK_HOST}")
    print(f"Port: {config.SPLUNK_PORT}")
    print(f"Username: {config.SPLUNK_USERNAME}")
    print(f"Scheme: {config.SPLUNK_SCHEME}")
    
    # Initialize Splunk query executor
    executor = SplunkQueryExecutor()
    
    # Test connection
    print("\nTesting connection...")
    connected = executor.connect()
    
    if connected:
        print("Successfully connected to Splunk")
    else:
        print("Failed to connect to Splunk")

if __name__ == "__main__":
    main()