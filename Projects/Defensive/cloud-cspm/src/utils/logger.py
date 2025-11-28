"""
Logging Configuration
Sets up logging for the CSPM tool
"""

import logging
import sys
from typing import Optional


def setup_logging(level: int = logging.INFO, log_file: Optional[str] = None):
    """Setup logging configuration"""
    handlers = [logging.StreamHandler(sys.stdout)]
    
    if log_file:
        handlers.append(logging.FileHandler(log_file))
    
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=handlers
    )
