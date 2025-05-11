#!/usr/bin/env python3
"""
Import Sigma rules from the official SigmaHQ repository.
This script clones the repository and copies relevant rules to the local sigma_rules directory.
"""

import os
import shutil
import logging
import subprocess
import glob
from typing import List, Optional

# Configure logging
logging.basicConfig(level=logging.INFO, 
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Configuration
SIGMA_REPO_URL = "https://github.com/SigmaHQ/sigma.git"
SIGMA_REPO_DIR = "sigma_repo"
SIGMA_RULES_DIR = "sigma_rules"
RULES_SUBDIRS = [
    "rules/windows",
    "rules/linux",
    "rules/network",
    "rules/cloud",
    "rules/web",
    "rules/application"
]

def clone_sigma_repo(target_dir: str = SIGMA_REPO_DIR) -> bool:
    """
    Clone the Sigma repository.
    
    Args:
        target_dir: Directory to clone the repository into
        
    Returns:
        Success status
    """
    try:
        if os.path.exists(target_dir):
            logger.info(f"Removing existing Sigma repo directory: {target_dir}")
            shutil.rmtree(target_dir)
        
        logger.info(f"Cloning Sigma repository from {SIGMA_REPO_URL}")
        result = subprocess.run(
            ["git", "clone", "--depth", "1", SIGMA_REPO_URL, target_dir],
            check=True,
            capture_output=True,
            text=True
        )
        logger.info(f"Successfully cloned Sigma repository to {target_dir}")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to clone Sigma repository: {e}")
        logger.error(f"Command output: {e.stdout} {e.stderr}")
        return False
    except Exception as e:
        logger.error(f"Error cloning Sigma repository: {e}")
        return False

def copy_rules(repo_dir: str = SIGMA_REPO_DIR, rules_dir: str = SIGMA_RULES_DIR, 
               subdirs: List[str] = RULES_SUBDIRS) -> int:
    """
    Copy Sigma rules from the cloned repository to the local rules directory.
    
    Args:
        repo_dir: Directory containing the cloned Sigma repository
        rules_dir: Target directory for the rules
        subdirs: List of subdirectories in the repository containing rules
        
    Returns:
        Number of rules copied
    """
    # Ensure target directory exists
    os.makedirs(rules_dir, exist_ok=True)
    
    # Track count of copied rules
    rules_count = 0
    
    try:
        for subdir in subdirs:
            # Construct source path
            source_path = os.path.join(repo_dir, subdir)
            if not os.path.exists(source_path):
                logger.warning(f"Source path does not exist: {source_path}")
                continue
            
            # Find all YAML/YML files
            rule_files = glob.glob(os.path.join(source_path, "**/*.yml"), recursive=True)
            rule_files.extend(glob.glob(os.path.join(source_path, "**/*.yaml"), recursive=True))
            
            for rule_file in rule_files:
                # Get the relative path within the subdir
                rel_path = os.path.relpath(rule_file, source_path)
                
                # Construct destination path
                dest_path = os.path.join(rules_dir, os.path.basename(subdir), rel_path)
                
                # Ensure destination directory exists
                os.makedirs(os.path.dirname(dest_path), exist_ok=True)
                
                # Copy the file
                shutil.copy2(rule_file, dest_path)
                rules_count += 1
        
        logger.info(f"Copied {rules_count} Sigma rules to {rules_dir}")
        return rules_count
    except Exception as e:
        logger.error(f"Error copying rules: {e}")
        return rules_count

def cleanup(repo_dir: str = SIGMA_REPO_DIR) -> None:
    """
    Clean up the cloned repository directory.
    
    Args:
        repo_dir: Directory containing the cloned repository
    """
    try:
        if os.path.exists(repo_dir):
            logger.info(f"Removing Sigma repo directory: {repo_dir}")
            shutil.rmtree(repo_dir)
    except Exception as e:
        logger.error(f"Error cleaning up: {e}")

def main() -> int:
    """
    Main function to import Sigma rules.
    
    Returns:
        Exit code
    """
    logger.info("Starting Sigma rules import")
    
    # Clone the repository
    if not clone_sigma_repo():
        logger.error("Failed to clone Sigma repository")
        return 1
    
    # Copy the rules
    rule_count = copy_rules()
    
    # Clean up
    cleanup()
    
    if rule_count > 0:
        logger.info(f"Successfully imported {rule_count} Sigma rules")
        return 0
    else:
        logger.error("No rules were imported")
        return 1

if __name__ == "__main__":
    exit(main())