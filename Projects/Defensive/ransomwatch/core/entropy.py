"""
Entropy Calculation Module
Calculate Shannon entropy for file encryption detection
"""

import os
import math
import logging
from ctypes import CDLL, c_char_p, c_double
import ctypes.util

class EntropyCalculator:
    def __init__(self):
        self.logger = logging.getLogger("EntropyCalculator")
        self.fast_entropy_lib = None
        self._load_fast_entropy()
    
    def _load_fast_entropy(self):
        """Load C extension for fast entropy calculation"""
        try:
            lib_path = os.path.join(os.path.dirname(__file__), '../c_extensions/entropy_fast.so')
            if os.path.exists(lib_path):
                self.fast_entropy_lib = CDLL(lib_path)
                self.fast_entropy_lib.calculate_file_entropy.argtypes = [c_char_p]
                self.fast_entropy_lib.calculate_file_entropy.restype = c_double
                self.logger.info("Fast entropy C extension loaded")
            else:
                self.logger.warning("Fast entropy C extension not found, using Python version")
        except Exception as e:
            self.logger.warning(f"Could not load fast entropy library: {e}")

def calculate_entropy(file_path, chunk_size=8192):
    """
    Calculate Shannon entropy of a file using Python
    Higher entropy suggests encrypted/compressed content
    """
    try:
        if not os.path.exists(file_path):
            return 0.0
        
        file_size = os.path.getsize(file_path)
        if file_size == 0:
            return 0.0
        
        byte_counts = [0] * 256
        total_bytes = 0
        
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                
                for byte in chunk:
                    byte_counts[byte] += 1
                total_bytes += len(chunk)
        
        # Calculate entropy
        entropy = 0.0
        for count in byte_counts:
            if count > 0:
                probability = count / total_bytes
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    except (IOError, OSError) as e:
        logging.getLogger("EntropyCalculator").error(f"Error calculating entropy for {file_path}: {e}")
        return 0.0

def calculate_entropy_fast(file_path):
    """
    Calculate entropy using C extension for performance
    """
    calculator = EntropyCalculator()
    if calculator.fast_entropy_lib:
        try:
            file_path_bytes = file_path.encode('utf-8')
            entropy = calculator.fast_entropy_lib.calculate_file_entropy(file_path_bytes)
            return entropy
        except Exception as e:
            logging.getLogger("EntropyCalculator").warning(f"Fast entropy failed, falling back to Python: {e}")
    
    return calculate_entropy(file_path)

def is_suspicious_entropy(entropy, file_extension):
    """
    Determine if entropy level is suspicious for given file type
    """
    # Different file types have different baseline entropy
    baseline_entropy = {
        '.txt': 4.5, '.doc': 5.0, '.pdf': 6.0, 
        '.jpg': 7.0, '.png': 7.2, '.zip': 7.8
    }
    
    expected = baseline_entropy.get(file_extension.lower(), 5.0)
    return entropy > expected + 1.0  # Significant deviation
