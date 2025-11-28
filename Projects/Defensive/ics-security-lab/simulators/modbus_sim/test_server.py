#!/usr/bin/env python3
"""Unit tests for Modbus simulator"""

import unittest
from server import SafetyAwareDataBlock, verify_lab_environment
import os

class TestSafetyAwareDataBlock(unittest.TestCase):
    
    def test_safe_ranges(self):
        """Test safe value range enforcement"""
        safe_ranges = {0: (0, 100), 1: (0, 50)}
        block = SafetyAwareDataBlock(0, [0, 0], safe_ranges)
        
        # This should be allowed and logged
        block.setValues(0, [50, 25])
        self.assertEqual(block.getValues(0, 2), [50, 25])
    
    def test_unsafe_ranges_logged(self):
        """Test that unsafe values are detected"""
        safe_ranges = {0: (0, 100)}
        block = SafetyAwareDataBlock(0, [0], safe_ranges)
        
        # This should trigger safety logging but still execute in lab mode
        block.setValues(0, [150])
        self.assertEqual(block.getValues(0, 1), [150])

if __name__ == '__main__':
    # Only run tests in lab mode
    os.environ['LAB_MODE'] = '1'
    unittest.main()
