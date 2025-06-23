#!/usr/bin/env python3
"""
SentinelScope Hash Analysis Demo
Demonstrates the enhanced malware detection capabilities
"""

import tempfile
import os
import json
from hash_analyzer import HashAnalyzer

def create_test_files():
    """Create test files for demonstration"""
    test_files = {}
    
    # Create EICAR test file (will be detected as malware)
    eicar_content = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
        f.write(eicar_content)
        test_files['eicar'] = f.name
    
    # Create clean file
    clean_content = "This is a completely clean and harmless text file."
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
        f.write(clean_content)
        test_files['clean'] = f.name
    
    # Create suspicious script file
    script_content = """
    function malicious() {
        eval(unescape('%73%6F%6D%65%20%6D%61%6C%69%63%69%6F%75%73%20%63%6F%64%65'));
        document.write('potentially harmful content');
    }
    """
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.js') as f:
        f.write(script_content)
        test_files['script'] = f.name
    
    return test_files

def demo_hash_analysis():
    """Demonstrate hash analysis capabilities"""
    print("🔍 SentinelScope Hash Analysis Demo")
    print("=" * 50)
    
    # Initialize hash analyzer
    analyzer = HashAnalyzer()
    
    # Get statistics
    stats = analyzer.get_statistics()
    print(f"📊 Hash Database Statistics:")
    print(f"   Malware database: {stats['malware_database_size']} entries")
    print(f"   Whitelist database: {stats['whitelist_database_size']} entries")
    print(f"   Cache entries: {stats['cache_entries']} files")
    print()
    
    # Create test files
    print("📝 Creating test files...")
    test_files = create_test_files()
    
    try:
        # Analyze each test file
        for file_type, filepath in test_files.items():
            print(f"\\n🔍 Analyzing {file_type.upper()} file: {os.path.basename(filepath)}")
            print("-" * 40)
            
            result = analyzer.analyze_file(filepath)
            
            if result['status'] == 'analyzed':
                # Display hash information
                hashes = result['hashes']
                print(f"📋 File Hashes:")
                print(f"   MD5:    {hashes['md5']}")
                print(f"   SHA1:   {hashes['sha1']}")
                print(f"   SHA256: {hashes['sha256']}")
                print(f"   Size:   {result['file_size']} bytes")
                print(f"   Time:   {result['calculation_time']}s")
                
                # Display threat analysis
                threat = result['threat_analysis']
                print(f"\\n⚠️  Threat Analysis:")
                if threat['is_malware']:
                    print(f"   🚨 STATUS: MALWARE DETECTED!")
                    print(f"   Family: {threat['malware_family']}")
                    print(f"   Threat Level: {threat['threat_level']}")
                    print(f"   Matched Hash: {threat['matched_hash_type']}")
                    print(f"   Confidence: {threat['confidence']*100}%")
                elif threat['is_trusted']:
                    print(f"   ✅ STATUS: TRUSTED FILE")
                    print(f"   Vendor: {threat.get('vendor', 'Unknown')}")
                    print(f"   Confidence: {threat['confidence']*100}%")
                else:
                    print(f"   ❓ STATUS: UNKNOWN FILE")
                    print(f"   Threat Level: {threat['threat_level']}")
                
                # Display reputation
                reputation = result['reputation']
                print(f"\\n📊 File Reputation:")
                print(f"   Score: {reputation['score']}/100")
                print(f"   Classification: {reputation['classification']}")
                print(f"   Recommendations:")
                for rec in reputation['recommendations']:
                    print(f"     • {rec}")
            
            else:
                print(f"❌ Error: {result.get('error', 'Unknown error')}")
    
    finally:
        # Clean up test files
        print(f"\\n🧹 Cleaning up test files...")
        for filepath in test_files.values():
            try:
                os.unlink(filepath)
            except:
                pass
    
    print(f"\\n✅ Demo completed!")
    print(f"\\n💡 Integration Benefits:")
    print(f"   • Instant malware detection via hash matching")
    print(f"   • Multiple hash algorithms (MD5, SHA1, SHA256)")
    print(f"   • Cached results for performance")
    print(f"   • Reputation scoring system")
    print(f"   • Extensible hash databases")
    print(f"   • Combined with YARA rules for comprehensive detection")

def demo_database_management():
    """Demonstrate hash database management"""
    print(f"\\n🗄️  Hash Database Management Demo")
    print("=" * 50)
    
    analyzer = HashAnalyzer()
    
    # Add a new malware hash
    print("➕ Adding new malware hash...")
    test_hash = "deadbeef" * 8  # 64-character hex string
    analyzer.add_malware_hash(
        hash_value=test_hash,
        family="Test Malware Family",
        severity="high",
        description="Demo malware hash for testing"
    )
    
    # Add a new trusted hash
    print("➕ Adding new trusted hash...")
    trusted_hash = "cafebabe" * 8  # 64-character hex string  
    analyzer.add_trusted_hash(
        hash_value=trusted_hash,
        vendor="Demo Vendor",
        description="Demo trusted file hash"
    )
    
    # Show updated statistics
    stats = analyzer.get_statistics()
    print(f"\\n📊 Updated Statistics:")
    print(f"   Malware database: {stats['malware_database_size']} entries")
    print(f"   Whitelist database: {stats['whitelist_database_size']} entries")
    
    print(f"\\n✅ Database management demo completed!")

if __name__ == "__main__":
    demo_hash_analysis()
    demo_database_management()
