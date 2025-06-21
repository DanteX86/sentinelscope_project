#!/usr/bin/env python3
"""
Core functionality tests for SentinelScope (without GUI dependencies)
"""

import unittest
import tempfile
import os
import sys
import yara

class TestYARARules(unittest.TestCase):
    """Test YARA rules functionality"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
        self.rules_path = os.path.join(os.path.dirname(__file__), 'rules.yar')
        
    def tearDown(self):
        """Clean up test fixtures"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_rules_file_exists(self):
        """Test that YARA rules file exists"""
        self.assertTrue(os.path.exists(self.rules_path), 
                       "rules.yar file should exist")
    
    def test_rules_compile(self):
        """Test that YARA rules compile without errors"""
        try:
            rules = yara.compile(filepath=self.rules_path)
            self.assertIsNotNone(rules, "YARA rules should compile successfully")
        except Exception as e:
            self.fail(f"YARA rules compilation failed: {str(e)}")
    
    def test_malware_detection(self):
        """Test malware detection with suspicious content"""
        rules = yara.compile(filepath=self.rules_path)
        
        # Create test file with suspicious content
        suspicious_content = b"cmd.exe powershell regedit system32 %temp%"
        test_file = os.path.join(self.temp_dir, 'suspicious.txt')
        
        with open(test_file, 'wb') as f:
            f.write(suspicious_content)
        
        matches = rules.match(test_file)
        
        # Should detect PotentialMalware rule (needs 3 of the strings)
        rule_names = [match.rule for match in matches]
        self.assertIn('PotentialMalware', rule_names, 
                     "Should detect PotentialMalware pattern")
    
    def test_clean_file(self):
        """Test that clean files don't trigger false positives"""
        rules = yara.compile(filepath=self.rules_path)
        
        # Create clean test file
        clean_content = b"This is a perfectly normal text file with no threats."
        test_file = os.path.join(self.temp_dir, 'clean.txt')
        
        with open(test_file, 'wb') as f:
            f.write(clean_content)
        
        matches = rules.match(test_file)
        
        # Should not detect any threats
        self.assertEqual(len(matches), 0, 
                        "Clean file should not trigger any detections")
    
    def test_ransomware_detection(self):
        """Test ransomware pattern detection"""
        rules = yara.compile(filepath=self.rules_path)
        
        # Create test file with ransomware patterns
        ransomware_content = b"Files encrypted! Send bitcoin payment to decrypt your files. README.txt"
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
        
        # Create test file with script patterns
        script_content = b"eval(document.write('malicious script'))"
        test_file = os.path.join(self.temp_dir, 'script.js')
        
        with open(test_file, 'wb') as f:
            f.write(script_content)
        
        matches = rules.match(test_file)
        rule_names = [match.rule for match in matches]
        
        self.assertIn('SuspiciousScript', rule_names,
                     "Should detect suspicious script patterns")
    
    def test_network_activity_detection(self):
        """Test network activity detection"""
        rules = yara.compile(filepath=self.rules_path)
        
        # Create test file with network activity patterns
        network_content = b"https://malicious.com/download.exe"
        test_file = os.path.join(self.temp_dir, 'network.txt')
        
        with open(test_file, 'wb') as f:
            f.write(network_content)
        
        matches = rules.match(test_file)
        rule_names = [match.rule for match in matches]
        
        self.assertIn('NetworkActivity', rule_names,
                     "Should detect network activity patterns")

class TestRulesIntegrity(unittest.TestCase):
    """Test YARA rules integrity"""
    
    def setUp(self):
        self.rules_path = os.path.join(os.path.dirname(__file__), 'rules.yar')
    
    def test_rules_syntax(self):
        """Test that all rules have valid syntax"""
        try:
            yara.compile(filepath=self.rules_path)
        except yara.SyntaxError as e:
            self.fail(f"YARA rules syntax error: {str(e)}")
        except Exception as e:
            self.fail(f"YARA rules error: {str(e)}")
    
    def test_expected_rules_present(self):
        """Test that expected rules are present"""
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
                         f"Rule '{rule_name}' should be present")
    
    def test_rules_have_metadata(self):
        """Test that rules contain proper metadata"""
        with open(self.rules_path, 'r') as f:
            content = f.read()
        
        self.assertIn('meta:', content, "Rules should contain metadata")
        self.assertIn('description =', content, "Rules should have descriptions")
        self.assertIn('author =', content, "Rules should have authors")
        self.assertIn('severity =', content, "Rules should have severity")

class TestApplicationFiles(unittest.TestCase):
    """Test application file integrity"""
    
    def test_main_script_exists(self):
        """Test that main application script exists"""
        app_path = os.path.join(os.path.dirname(__file__), 'sentinelscope_app.py')
        self.assertTrue(os.path.exists(app_path), 
                       "sentinelscope_app.py should exist")
    
    def test_main_script_has_required_components(self):
        """Test that main script contains required components"""
        app_path = os.path.join(os.path.dirname(__file__), 'sentinelscope_app.py')
        
        with open(app_path, 'r') as f:
            content = f.read()
        
        required_components = [
            'class SentinelScopeApp',
            'def main(',
            'import yara',
            'def scan_file',
            'def load_yara_rules'
        ]
        
        for component in required_components:
            self.assertIn(component, content, 
                         f"Script should contain: {component}")

def main():
    """Run all tests"""
    unittest.main(verbosity=2)

if __name__ == '__main__':
    main()
