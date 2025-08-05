# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.  

# SPDX-License-Identifier: CC-BY-NC-4.0


#
"""
Basic tests for EnIGMA+
"""

import unittest


class TestBasic(unittest.TestCase):
    """Basic test cases for EnIGMA+"""
    
    def test_import(self):
        """Test that main modules can be imported"""
        try:
            import run
            self.assertTrue(True)
        except ImportError as e:
            self.fail(f"Failed to import run module: {e}")
    
    def test_config_files_exist(self):
        """Test that required config files exist"""
        import os
        
        required_files = [
            "requirements.txt",
            "LICENSE",
            "README.md",
            "CONTRIBUTING.md"
        ]
        
        for file_path in required_files:
            with self.subTest(file_path=file_path):
                self.assertTrue(
                    os.path.exists(file_path),
                    f"Required file {file_path} does not exist"
                )


if __name__ == "__main__":
    unittest.main() 