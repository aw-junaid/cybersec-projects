"""
Configuration Loader
Loads and manages tool configuration
"""

import yaml
import json
import logging
from typing import Dict, Any


class ConfigLoader:
    """Configuration loader for CSPM tool"""
    
    @staticmethod
    def load_config(config_path: str) -> Dict[str, Any]:
        """Load configuration from YAML/JSON files"""
        config = {
            'rules': {},
            'compliance': {},
            'scan_settings': {}
        }
        
        try:
            # Load AWS rules
            aws_rules_path = f"{config_path}/aws_rules.yaml"
            config['rules']['aws'] = ConfigLoader._load_yaml_file(aws_rules_path)
            
            # Load Azure rules
            azure_rules_path = f"{config_path}/azure_rules.yaml"
            config['rules']['azure'] = ConfigLoader._load_yaml_file(azure_rules_path)
            
            # Load GCP rules
            gcp_rules_path = f"{config_path}/gcp_rules.yaml"
            config['rules']['gcp'] = ConfigLoader._load_yaml_file(gcp_rules_path)
            
            # Load compliance frameworks
            cis_path = f"{config_path}/../compliance/cis_benchmarks.yaml"
            config['compliance']['cis'] = ConfigLoader._load_yaml_file(cis_path)
            
        except Exception as e:
            logging.warning(f"Configuration loading failed: {str(e)}. Using default configuration.")
            
        return config
    
    @staticmethod
    def _load_yaml_file(file_path: str) -> Dict[str, Any]:
        """Load YAML configuration file"""
        try:
            with open(file_path, 'r') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            logging.warning(f"Configuration file not found: {file_path}")
            return {}
        except yaml.YAMLError as e:
            logging.error(f"YAML parsing error in {file_path}: {str(e)}")
            return {}
