"""
Base Scanner Class
Abstract base class for all security scanners
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Any


class BaseScanner(ABC):
    """Abstract base class for security scanners"""
    
    def __init__(self, connectors: Dict[str, Any]):
        self.connectors = connectors
        self.scanner_name = "Base Scanner"
        
    @abstractmethod
    def scan(self) -> List[Dict[str, Any]]:
        """Perform security scan - must be implemented by subclasses"""
        pass
    
    def get_scanner_name(self) -> str:
        """Get scanner name"""
        return self.scanner_name
