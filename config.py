import os
import logging

# Logging configuration
logging.basicConfig(level=logging.DEBUG, 
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# Splunk configuration
SPLUNK_HOST = os.environ.get("SPLUNK_HOST", "192.168.244.128")
SPLUNK_PORT = int(os.environ.get("SPLUNK_PORT", 8089))
SPLUNK_USERNAME = os.environ.get("SPLUNK_USERNAME", "salah")
SPLUNK_PASSWORD = os.environ.get("SPLUNK_PASSWORD", "asd@12345")
SPLUNK_APP = os.environ.get("SPLUNK_APP", "search")
SPLUNK_OWNER = os.environ.get("SPLUNK_OWNER", "nobody")
SPLUNK_SCHEME = os.environ.get("SPLUNK_SCHEME", "https")  # Changed to https for security
SPLUNK_INDEX = os.environ.get("SPLUNK_INDEX", "botsv2")

# MITRE ATT&CK configuration
MITRE_ENTERPRISE_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
MITRE_LOCAL_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mitre", "attack.json")
MITRE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mitre")

# Sigma configuration
SIGMA_RULES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sigma_rules")

# Field mapping configuration
FIELD_MAPPING_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mappings", "fieldmap.json")

# Ensure directories exist
os.makedirs(MITRE_DIR, exist_ok=True)
os.makedirs(SIGMA_RULES_DIR, exist_ok=True)
os.makedirs(os.path.dirname(FIELD_MAPPING_FILE), exist_ok=True)

# Default field mappings if file doesn't exist
DEFAULT_FIELD_MAPPINGS = {
    "process": {
        "process_name": "Image",
        "process_id": "ProcessId",
        "command_line": "CommandLine",
        "parent_process_name": "ParentImage",
        "parent_process_id": "ParentProcessId",
        "parent_command_line": "ParentCommandLine",
        "current_directory": "CurrentDirectory",
        "user": "User"
    },
    "network": {
        "source_ip": "src_ip",
        "destination_ip": "dest_ip",
        "source_port": "src_port",
        "destination_port": "dest_port",
        "protocol": "protocol"
    },
    "file": {
        "file_path": "TargetFilename",
        "file_name": "TargetFilename",
        "file_extension": "TargetExtension"
    },
    "registry": {
        "registry_key": "TargetObject",
        "registry_value": "Details",
        "registry_details": "Details"
    },
    "authentication": {
        "user_name": "user",
        "domain": "domain",
        "logon_type": "logon_type",
        "status": "status"
    }
}
