#!/usr/bin/env python3
"""
Test suite for SentinelScope application
"""

import unittest
import tempfile
import os
import sys
import yara
from unittest.mock import patch, MagicMock

# Add the current directory to Python path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import the application (without running the GUI)
import sentinelscope_app

class TestSentinelScope(unittest.TestCase):
    """Test cases for SentinelScope functionality"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
        self.rules_path = os.path.join(os.path.dirname(__file__), 'rules.yar')
        
    def tearDown(self):
        """Clean up test fixtures"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_yara_rules_exist(self):
        """Test that YARA rules file exists"""
        self.assertTrue(os.path.exists(self.rules_path), 
                       "rules.yar file should exist")
    
    def test_yara_rules_valid(self):
        """Test that YARA rules compile correctly"""
        try:
            rules = yara.compile(filepath=self.rules_path)
            self.assertIsNotNone(rules, "YARA rules should compile successfully")
        except Exception as e:
            self.fail(f"YARA rules compilation failed: {str(e)}")
    
    def test_yara_rules_content(self):
        """Test that YARA rules contain expected rule names"""
        with open(self.rules_path, 'r') as f:
            content = f.read()
        
        expected_rules = [
            'SuspiciousExecutable',
            'PotentialMalware', 
            'SuspiciousScript',
            'NetworkActivity',
            'PasswordHarvesting',
            'CryptocurrencyMiner',
            'RansomwarePatterns'
        ]
        
        for rule_name in expected_rules:
            self.assertIn(f'rule {rule_name}', content, 
                         f"Rule '{rule_name}' should be present in rules.yar")
    
    def test_app_class_exists(self):
        """Test that SentinelScopeApp class exists and can be imported"""
        self.assertTrue(hasattr(sentinelscope_app, 'SentinelScopeApp'),
                       "SentinelScopeApp class should exist")
    
    @patch('tkinter.Tk')
    def test_app_initialization(self, mock_tk):
        """Test that the app can be initialized without errors"""
        mock_root = MagicMock()
        mock_tk.return_value = mock_root
        
        try:
            with patch.object(sentinelscope_app.SentinelScopeApp, 'load_yara_rules'):
                with patch.object(sentinelscope_app.SentinelScopeApp, 'setup_ui'):
                    app = sentinelscope_app.SentinelScopeApp(mock_root)
                    self.assertIsNotNone(app)
        except Exception as e:
            self.fail(f"App initialization failed: {str(e)}")
    
    def test_malware_detection_logic(self):
        """Test malware detection with sample content"""
        # Load rules
        rules = yara.compile(filepath=self.rules_path)
        
        # Test with suspicious content
        suspicious_content = b"cmd.exe powershell regedit system32"
        test_file = os.path.join(self.temp_dir, 'suspicious.txt')
        
        with open(test_file, 'wb') as f:
            f.write(suspicious_content)
        
        matches = rules.match(test_file)
        
        # Should detect PotentialMalware rule
        rule_names = [match.rule for match in matches]
        self.assertIn('PotentialMalware', rule_names, 
                     "Should detect suspicious executable patterns")
    
    def test_clean_file_detection(self):
        """Test that clean files don't trigger false positives"""
        # Load rules
        rules = yara.compile(filepath=self.rules_path)
        
        # Test with clean content
        clean_content = b"Hello world! This is a clean text file."
        test_file = os.path.join(self.temp_dir, 'clean.txt')
        
        with open(test_file, 'wb') as f:
            f.write(clean_content)
        
        matches = rules.match(test_file)
        
        # Should not detect any threats
        self.assertEqual(len(matches), 0, 
                        "Clean file should not trigger any detections")
    
    def test_ransomware_pattern_detection(self):
        """Test ransomware pattern detection"""
        rules = yara.compile(filepath=self.rules_path)
        
        # Test with ransomware-like content
        ransomware_content = b"Your files have been encrypted! Send bitcoin payment to decrypt README"
        test_file = os.path.join(self.temp_dir, 'ransomware.txt')
        
        with open(test_file, 'wb') as f:
            f.write(ransomware_content)
        
        matches = rules.match(test_file)
        rule_names = [match.rule for match in matches]
        
        self.assertIn('RansomwarePatterns', rule_names,
                     "Should detect ransomware patterns")
    
    def test_script_detection(self):
        """Test suspicious script detection"""
        rules = yara.compile(filepath=self.rules_path)
        
        # Test with suspicious JavaScript-like content
        script_content = b"eval(unescape('%75%6E%65%73%63%61%70%65'))"
        test_file = os.path.join(self.temp_dir, 'script.js')
        
        with open(test_file, 'wb') as f:
            f.write(script_content)
        
        matches = rules.match(test_file)
        rule_names = [match.rule for match in matches]
        
        self.assertIn('SuspiciousScript', rule_names,
                     "Should detect suspicious script patterns")
    
    def test_file_validation(self):
        """Test file path validation"""
        # Test with non-existent file
        non_existent = "/path/that/does/not/exist"
        self.assertFalse(os.path.exists(non_existent),
                        "Test file should not exist for validation test")
    
    def test_main_function_exists(self):
        """Test that main function exists"""
        self.assertTrue(hasattr(sentinelscope_app, 'main'),
                       "main() function should exist")

class TestYARARulesIntegrity(unittest.TestCase):
    """Test YARA rules integrity and syntax"""
    
    def setUp(self):
        self.rules_path = os.path.join(os.path.dirname(__file__), 'rules.yar')
    
    def test_rules_syntax_valid(self):
        """Test that all rules have valid syntax"""
        try:
            yara.compile(filepath=self.rules_path)
        except yara.SyntaxError as e:
            self.fail(f"YARA rules syntax error: {str(e)}")
        except Exception as e:
            self.fail(f"YARA rules compilation error: {str(e)}")
    
    def test_rules_have_metadata(self):
        """Test that rules contain proper metadata"""
        with open(self.rules_path, 'r') as f:
            content = f.read()
        
        # Check for metadata sections
        self.assertIn('meta:', content, "Rules should contain metadata")
        self.assertIn('description =', content, "Rules should have descriptions")
        self.assertIn('author =', content, "Rules should have authors")
        self.assertIn('severity =', content, "Rules should have severity levels")
    
    def test_rules_have_conditions(self):
        """Test that all rules have condition sections"""
        with open(self.rules_path, 'r') as f:
            content = f.read()
        
        # Count rule definitions and condition statements
        rule_count = content.count('rule ')
        condition_count = content.count('condition:')
        
        self.assertEqual(rule_count, condition_count,
                        "Each rule should have exactly one condition")

def run_tests():
    """Run all tests and return success status"""
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add all test cases
    test_suite.addTest(unittest.makeSuite(TestSentinelScope))
    test_suite.addTest(unittest.makeSuite(TestYARARulesIntegrity))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    # Return True if all tests passed
    return result.wasSuccessful()

if __name__ == '__main__':
    success = run_tests()
    sys.exit(0 if success else 1)
