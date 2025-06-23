#!/usr/bin/env python3
"""
Test suite for Hash Analyzer module
Tests all hash analysis functionality
"""

import unittest
import tempfile
import os
import sys
import json
from hash_analyzer import HashAnalyzer

class TestHashAnalyzer(unittest.TestCase):
    """Test hash analyzer functionality"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
        self.analyzer = HashAnalyzer(cache_dir=os.path.join(self.temp_dir, "test_cache"))
        
    def tearDown(self):
        """Clean up test fixtures"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_analyzer_initialization(self):
        """Test that hash analyzer initializes correctly"""
        self.assertIsNotNone(self.analyzer)
        self.assertIsInstance(self.analyzer.malware_hashes, dict)
        self.assertIsInstance(self.analyzer.whitelist_hashes, dict)
        self.assertIsInstance(self.analyzer.hash_cache, dict)
    
    def test_hash_calculation(self):
        """Test hash calculation methods"""
        # Create test file
        test_content = b"Hello, SentinelScope!"
        test_file = os.path.join(self.temp_dir, 'test.txt')
        
        with open(test_file, 'wb') as f:
            f.write(test_content)
        
        # Test individual hash methods
        md5_hash = self.analyzer.calculate_md5(test_file)
        sha1_hash = self.analyzer.calculate_sha1(test_file)
        sha256_hash = self.analyzer.calculate_sha256(test_file)
        
        # Verify hashes are calculated
        self.assertEqual(len(md5_hash), 32)  # MD5 is 32 hex chars
        self.assertEqual(len(sha1_hash), 40)  # SHA1 is 40 hex chars
        self.assertEqual(len(sha256_hash), 64)  # SHA256 is 64 hex chars
        
        # Test all hashes method
        all_hashes = self.analyzer.calculate_all_hashes(test_file)
        self.assertEqual(all_hashes['md5'], md5_hash)
        self.assertEqual(all_hashes['sha1'], sha1_hash)
        self.assertEqual(all_hashes['sha256'], sha256_hash)
        self.assertEqual(all_hashes['file_size'], len(test_content))
    
    def test_eicar_detection(self):
        """Test EICAR test file detection"""
        # Create EICAR test file
        eicar_content = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        test_file = os.path.join(self.temp_dir, 'eicar.txt')
        
        with open(test_file, 'wb') as f:
            f.write(eicar_content)
        
        # Analyze file
        result = self.analyzer.analyze_file(test_file)
        
        # Verify detection
        self.assertEqual(result['status'], 'analyzed')
        self.assertTrue(result['threat_analysis']['is_malware'])
        self.assertEqual(result['threat_analysis']['malware_family'], 'EICAR Test File')
        self.assertEqual(result['reputation']['classification'], 'malicious')
        self.assertEqual(result['reputation']['score'], 0)
    
    def test_clean_file_analysis(self):
        """Test analysis of clean files"""
        # Create clean file
        clean_content = b"This is a completely harmless text file."
        test_file = os.path.join(self.temp_dir, 'clean.txt')
        
        with open(test_file, 'wb') as f:
            f.write(clean_content)
        
        # Analyze file
        result = self.analyzer.analyze_file(test_file)
        
        # Verify result
        self.assertEqual(result['status'], 'analyzed')
        self.assertFalse(result['threat_analysis']['is_malware'])
        self.assertFalse(result['threat_analysis']['is_trusted'])
        self.assertEqual(result['threat_analysis']['threat_level'], 'unknown')
        self.assertEqual(result['reputation']['classification'], 'unknown')
        self.assertEqual(result['reputation']['score'], 50)
    
    def test_database_management(self):
        """Test hash database management"""
        # Add malware hash
        test_hash = "deadbeef" * 8
        self.analyzer.add_malware_hash(
            hash_value=test_hash,
            family="Test Malware",
            severity="high",
            description="Test hash"
        )
        
        # Verify addition
        self.assertIn(test_hash.lower(), self.analyzer.malware_hashes)
        self.assertEqual(self.analyzer.malware_hashes[test_hash.lower()]['family'], "Test Malware")
        
        # Add trusted hash
        trusted_hash = "cafebabe" * 8
        self.analyzer.add_trusted_hash(
            hash_value=trusted_hash,
            vendor="Test Vendor",
            description="Test trusted file"
        )
        
        # Verify addition
        self.assertIn(trusted_hash.lower(), self.analyzer.whitelist_hashes)
        self.assertEqual(self.analyzer.whitelist_hashes[trusted_hash.lower()]['vendor'], "Test Vendor")
    
    def test_caching_functionality(self):
        """Test hash caching system"""
        # Create test file
        test_content = b"Cache test content"
        test_file = os.path.join(self.temp_dir, 'cache_test.txt')
        
        with open(test_file, 'wb') as f:
            f.write(test_content)
        
        # First analysis
        result1 = self.analyzer.analyze_file(test_file)
        cache_size_after_first = len(self.analyzer.hash_cache)
        
        # Second analysis (should use cache)
        result2 = self.analyzer.analyze_file(test_file)
        cache_size_after_second = len(self.analyzer.hash_cache)
        
        # Verify caching
        self.assertEqual(cache_size_after_first, cache_size_after_second)
        self.assertEqual(result1['hashes'], result2['hashes'])
    
    def test_error_handling(self):
        """Test error handling for non-existent files"""
        non_existent_file = "/path/that/does/not/exist"
        
        # Test individual hash methods
        md5_result = self.analyzer.calculate_md5(non_existent_file)
        self.assertTrue(md5_result.startswith("ERROR:"))
        
        sha256_result = self.analyzer.calculate_sha256(non_existent_file)
        self.assertTrue(sha256_result.startswith("ERROR:"))
        
        # Test full analysis
        result = self.analyzer.analyze_file(non_existent_file)
        self.assertEqual(result['status'], 'error')
        self.assertIn('error', result)
    
    def test_statistics(self):
        """Test statistics reporting"""
        stats = self.analyzer.get_statistics()
        
        self.assertIn('malware_database_size', stats)
        self.assertIn('whitelist_database_size', stats)
        self.assertIn('cache_entries', stats)
        self.assertIn('cache_directory', stats)
        
        self.assertIsInstance(stats['malware_database_size'], int)
        self.assertIsInstance(stats['whitelist_database_size'], int)
        self.assertIsInstance(stats['cache_entries'], int)
    
    def test_reputation_scoring(self):
        """Test reputation scoring system"""
        # Test malware reputation
        malware_hashes = {'md5': '44d88612fea8a8f36de82e1278abb02f'}  # EICAR MD5
        malware_rep = self.analyzer.get_file_reputation(malware_hashes)
        
        self.assertEqual(malware_rep['score'], 0)
        self.assertEqual(malware_rep['classification'], 'malicious')
        self.assertIn('Quarantine', malware_rep['recommendations'][0])
        
        # Test unknown file reputation
        unknown_hashes = {'md5': 'unknown_hash_value_12345'}
        unknown_rep = self.analyzer.get_file_reputation(unknown_hashes)
        
        self.assertEqual(unknown_rep['score'], 50)
        self.assertEqual(unknown_rep['classification'], 'unknown')
        self.assertIn('proceed with caution', unknown_rep['recommendations'][0])

class TestHashDatabases(unittest.TestCase):
    """Test hash database functionality"""
    
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.analyzer = HashAnalyzer(cache_dir=os.path.join(self.temp_dir, "db_test"))
    
    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_database_persistence(self):
        """Test that databases are saved and loaded correctly"""
        # Add entries
        self.analyzer.add_malware_hash("testmalhash123", "TestFamily", "high")
        self.analyzer.add_trusted_hash("testtrusthash123", "TestVendor")
        
        # Create new analyzer with same cache dir (should load existing databases)
        analyzer2 = HashAnalyzer(cache_dir=os.path.join(self.temp_dir, "db_test"))
        
        # Verify data was loaded
        self.assertIn("testmalhash123", analyzer2.malware_hashes)
        self.assertIn("testtrusthash123", analyzer2.whitelist_hashes)
    
    def test_default_databases(self):
        """Test that default databases are created with sample data"""
        # Check that EICAR is in default malware database
        self.assertIn("44d88612fea8a8f36de82e1278abb02f", self.analyzer.malware_hashes)
        
        # Check database structure
        eicar_entry = self.analyzer.malware_hashes["44d88612fea8a8f36de82e1278abb02f"]
        self.assertIn('family', eicar_entry)
        self.assertIn('severity', eicar_entry)
        self.assertIn('description', eicar_entry)

def main():
    """Run all hash analyzer tests"""
    unittest.main(verbosity=2)

if __name__ == '__main__':
    main()
