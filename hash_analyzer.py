#!/usr/bin/env python3
"""
Hash Analysis Module for SentinelScope
Detects known malware and trusted files through hash matching
"""

import hashlib
import json
import os
import time
from typing import Dict, List, Optional, Tuple

class HashAnalyzer:
    def __init__(self, cache_dir="hash_cache"):
        self.cache_dir = cache_dir
        self.malware_hashes = {}
        self.whitelist_hashes = {}
        self.hash_cache = {}
        
        # Create cache directory
        os.makedirs(self.cache_dir, exist_ok=True)
        
        # Load hash databases
        self.load_malware_database()
        self.load_whitelist_database()
        self.load_hash_cache()
    
    def calculate_md5(self, filepath: str) -> str:
        """Calculate MD5 hash of a file"""
        try:
            hash_md5 = hashlib.md5()
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
            return hash_md5.hexdigest()
        except Exception as e:
            return f"ERROR: {str(e)}"
    
    def calculate_sha256(self, filepath: str) -> str:
        """Calculate SHA256 hash of a file"""
        try:
            hash_sha256 = hashlib.sha256()
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except Exception as e:
            return f"ERROR: {str(e)}"
    
    def calculate_sha1(self, filepath: str) -> str:
        """Calculate SHA1 hash of a file"""
        try:
            hash_sha1 = hashlib.sha1()
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha1.update(chunk)
            return hash_sha1.hexdigest()
        except Exception as e:
            return f"ERROR: {str(e)}"
    
    def calculate_all_hashes(self, filepath: str) -> Dict[str, str]:
        """Calculate MD5, SHA1, and SHA256 hashes for a file"""
        hashes = {
            'md5': '',
            'sha1': '',
            'sha256': '',
            'file_size': 0,
            'calculation_time': 0
        }
        
        start_time = time.time()
        
        try:
            # Get file size
            hashes['file_size'] = os.path.getsize(filepath)
            
            # Calculate all hashes in a single pass for efficiency
            hash_md5 = hashlib.md5()
            hash_sha1 = hashlib.sha1()
            hash_sha256 = hashlib.sha256()
            
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):  # 64KB chunks
                    hash_md5.update(chunk)
                    hash_sha1.update(chunk)
                    hash_sha256.update(chunk)
            
            hashes['md5'] = hash_md5.hexdigest()
            hashes['sha1'] = hash_sha1.hexdigest()
            hashes['sha256'] = hash_sha256.hexdigest()
            
        except Exception as e:
            hashes['error'] = str(e)
        
        hashes['calculation_time'] = round(time.time() - start_time, 3)
        return hashes
    
    def analyze_file(self, filepath: str) -> Dict:
        """Comprehensive hash analysis of a file"""
        # Check cache first
        cache_key = f"{filepath}:{os.path.getmtime(filepath)}"
        if cache_key in self.hash_cache:
            return self.hash_cache[cache_key]
        
        # Calculate hashes
        hashes = self.calculate_all_hashes(filepath)
        
        if 'error' in hashes:
            return {
                'status': 'error',
                'error': hashes['error'],
                'filepath': filepath
            }
        
        # Analyze hashes against databases
        analysis_result = {
            'status': 'analyzed',
            'filepath': filepath,
            'file_size': hashes['file_size'],
            'hashes': {
                'md5': hashes['md5'],
                'sha1': hashes['sha1'], 
                'sha256': hashes['sha256']
            },
            'calculation_time': hashes['calculation_time'],
            'threat_analysis': self.analyze_threat_status(hashes),
            'reputation': self.get_file_reputation(hashes),
            'timestamp': time.time()
        }
        
        # Cache the result
        self.hash_cache[cache_key] = analysis_result
        self.save_hash_cache()
        
        return analysis_result
    
    def analyze_threat_status(self, hashes: Dict) -> Dict:
        """Analyze if file hashes match known threats or trusted files"""
        threat_status = {
            'is_malware': False,
            'is_trusted': False,
            'malware_family': None,
            'threat_level': 'unknown',
            'matched_hash_type': None,
            'confidence': 0.0
        }
        
        # Check against malware database
        for hash_type in ['md5', 'sha1', 'sha256']:
            hash_value = hashes.get(hash_type, '').lower()
            if hash_value in self.malware_hashes:
                threat_info = self.malware_hashes[hash_value]
                threat_status.update({
                    'is_malware': True,
                    'malware_family': threat_info.get('family', 'Unknown'),
                    'threat_level': threat_info.get('severity', 'high'),
                    'matched_hash_type': hash_type,
                    'confidence': 1.0,
                    'first_seen': threat_info.get('first_seen', 'Unknown'),
                    'description': threat_info.get('description', 'Known malware')
                })
                break
        
        # Check against whitelist database
        if not threat_status['is_malware']:
            for hash_type in ['md5', 'sha1', 'sha256']:
                hash_value = hashes.get(hash_type, '').lower()
                if hash_value in self.whitelist_hashes:
                    whitelist_info = self.whitelist_hashes[hash_value]
                    threat_status.update({
                        'is_trusted': True,
                        'threat_level': 'safe',
                        'matched_hash_type': hash_type,
                        'confidence': 1.0,
                        'vendor': whitelist_info.get('vendor', 'Unknown'),
                        'description': whitelist_info.get('description', 'Trusted file')
                    })
                    break
        
        return threat_status
    
    def get_file_reputation(self, hashes: Dict) -> Dict:
        """Get file reputation based on hash analysis"""
        reputation = {
            'score': 50,  # Neutral score (0-100)
            'classification': 'unknown',
            'recommendations': []
        }
        
        md5 = hashes.get('md5', '').lower()
        sha256 = hashes.get('sha256', '').lower()
        
        if md5 in self.malware_hashes or sha256 in self.malware_hashes:
            reputation.update({
                'score': 0,
                'classification': 'malicious',
                'recommendations': [
                    'Quarantine this file immediately',
                    'Run full system scan',
                    'Check for system compromise indicators'
                ]
            })
        elif md5 in self.whitelist_hashes or sha256 in self.whitelist_hashes:
            reputation.update({
                'score': 100,
                'classification': 'trusted',
                'recommendations': [
                    'File is trusted and safe to execute',
                    'No further action required'
                ]
            })
        else:
            reputation.update({
                'score': 50,
                'classification': 'unknown',
                'recommendations': [
                    'File is unknown - proceed with caution',
                    'Consider additional analysis methods',
                    'Monitor file behavior if executed'
                ]
            })
        
        return reputation
    
    def load_malware_database(self):
        """Load known malware hash database"""
        db_path = os.path.join(self.cache_dir, 'malware_hashes.json')
        
        # Create sample malware database if it doesn't exist
        if not os.path.exists(db_path):
            sample_malware_db = {
                # Real malware hashes (historical/public domain)
                "44d88612fea8a8f36de82e1278abb02f": {
                    "family": "EICAR Test File",
                    "severity": "test",
                    "first_seen": "1991-01-01",
                    "description": "EICAR anti-virus test file"
                },
                "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": {
                    "family": "EICAR Test File",
                    "severity": "test", 
                    "first_seen": "1991-01-01",
                    "description": "EICAR anti-virus test file (SHA256)"
                },
                # Add more known malware hashes here
                "da39a3ee5e6b4b0d3255bfef95601890afd80709": {
                    "family": "Empty File",
                    "severity": "low",
                    "description": "Empty file hash"
                }
            }
            
            with open(db_path, 'w') as f:
                json.dump(sample_malware_db, f, indent=2)
            
            self.malware_hashes = sample_malware_db
        else:
            try:
                with open(db_path, 'r') as f:
                    self.malware_hashes = json.load(f)
            except Exception as e:
                print(f"Error loading malware database: {e}")
                self.malware_hashes = {}
    
    def load_whitelist_database(self):
        """Load trusted file hash database"""
        db_path = os.path.join(self.cache_dir, 'whitelist_hashes.json')
        
        # Create sample whitelist database
        if not os.path.exists(db_path):
            sample_whitelist_db = {
                # Common system files (examples)
                "d41d8cd98f00b204e9800998ecf8427e": {
                    "vendor": "System",
                    "description": "Empty file",
                    "verified": True
                },
                # Add more trusted file hashes
            }
            
            with open(db_path, 'w') as f:
                json.dump(sample_whitelist_db, f, indent=2)
            
            self.whitelist_hashes = sample_whitelist_db
        else:
            try:
                with open(db_path, 'r') as f:
                    self.whitelist_hashes = json.load(f)
            except Exception as e:
                print(f"Error loading whitelist database: {e}")
                self.whitelist_hashes = {}
    
    def load_hash_cache(self):
        """Load hash calculation cache"""
        cache_path = os.path.join(self.cache_dir, 'hash_cache.json')
        
        if os.path.exists(cache_path):
            try:
                with open(cache_path, 'r') as f:
                    self.hash_cache = json.load(f)
            except Exception as e:
                print(f"Error loading hash cache: {e}")
                self.hash_cache = {}
    
    def save_hash_cache(self):
        """Save hash calculation cache"""
        cache_path = os.path.join(self.cache_dir, 'hash_cache.json')
        
        try:
            # Keep only recent cache entries (last 1000)
            if len(self.hash_cache) > 1000:
                sorted_cache = sorted(
                    self.hash_cache.items(),
                    key=lambda x: x[1].get('timestamp', 0),
                    reverse=True
                )
                self.hash_cache = dict(sorted_cache[:1000])
            
            with open(cache_path, 'w') as f:
                json.dump(self.hash_cache, f, indent=2)
        except Exception as e:
            print(f"Error saving hash cache: {e}")
    
    def add_malware_hash(self, hash_value: str, family: str, severity: str = "high", description: str = ""):
        """Add a new malware hash to the database"""
        self.malware_hashes[hash_value.lower()] = {
            "family": family,
            "severity": severity,
            "first_seen": time.strftime("%Y-%m-%d"),
            "description": description
        }
        
        # Save updated database
        db_path = os.path.join(self.cache_dir, 'malware_hashes.json')
        with open(db_path, 'w') as f:
            json.dump(self.malware_hashes, f, indent=2)
    
    def add_trusted_hash(self, hash_value: str, vendor: str, description: str = ""):
        """Add a new trusted hash to the whitelist"""
        self.whitelist_hashes[hash_value.lower()] = {
            "vendor": vendor,
            "description": description,
            "verified": True,
            "added": time.strftime("%Y-%m-%d")
        }
        
        # Save updated database
        db_path = os.path.join(self.cache_dir, 'whitelist_hashes.json')
        with open(db_path, 'w') as f:
            json.dump(self.whitelist_hashes, f, indent=2)
    
    def get_statistics(self) -> Dict:
        """Get hash analysis statistics"""
        return {
            'malware_database_size': len(self.malware_hashes),
            'whitelist_database_size': len(self.whitelist_hashes),
            'cache_entries': len(self.hash_cache),
            'cache_directory': self.cache_dir
        }

# Test function
if __name__ == "__main__":
    analyzer = HashAnalyzer()
    
    # Test with a file
    import tempfile
    
    # Create test file
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as tf:
        tf.write("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
        test_file = tf.name
    
    try:
        result = analyzer.analyze_file(test_file)
        print("Hash Analysis Result:")
        print(json.dumps(result, indent=2))
        
        print("\\nStatistics:")
        print(json.dumps(analyzer.get_statistics(), indent=2))
        
    finally:
        os.unlink(test_file)
