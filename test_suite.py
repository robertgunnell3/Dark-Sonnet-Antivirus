#!/usr/bin/env python3
"""
Antivirus System Test Suite
Demonstrates detection capabilities with various test cases
"""

import os
import tempfile
import shutil
from pathlib import Path
from antivirus_engine import AntivirusEngine


class TestSuite:
    """Test suite for antivirus system"""
    
    def __init__(self):
        self.test_dir = Path(tempfile.mkdtemp(prefix='av_test_'))
        self.av = AntivirusEngine()
        print(f"Test directory: {self.test_dir}")
    
    def cleanup(self):
        """Clean up test directory"""
        if self.test_dir.exists():
            shutil.rmtree(self.test_dir)
    
    def create_test_file(self, name: str, content: bytes) -> Path:
        """Create a test file"""
        filepath = self.test_dir / name
        with open(filepath, 'wb') as f:
            f.write(content)
        return filepath
    
    def test_clean_file(self):
        """Test 1: Clean text file"""
        print("\n[TEST 1] Scanning clean text file...")
        
        filepath = self.create_test_file('clean.txt', b'Hello, this is a clean file!')
        result = self.av.scan_file(str(filepath))
        
        assert not result.is_infected, "Clean file should not be infected"
        assert result.heuristic_score < 20, "Clean file should have low heuristic score"
        
        print(f"✓ Result: CLEAN (Score: {result.heuristic_score})")
        return True
    
    def test_suspicious_python_script(self):
        """Test 2: Suspicious Python script"""
        print("\n[TEST 2] Scanning suspicious Python script...")
        
        content = b'''
import subprocess
import socket
import base64
import os

# Suspicious patterns
data = base64.b64decode("SGVsbG8gV29ybGQ=")
subprocess.run(["echo", "test"])
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
os.system("echo test")

# More suspicious stuff
eval("print('test')")
exec("x = 1")
'''
        
        filepath = self.create_test_file('suspicious.py', content)
        result = self.av.scan_file(str(filepath))
        
        print(f"Result: {'INFECTED' if result.is_infected else 'SUSPICIOUS'}")
        print(f"Heuristic Score: {result.heuristic_score}")
        print(f"Findings: {len(result.details.get('heuristic_findings', []))}")
        
        for finding in result.details.get('heuristic_findings', [])[:5]:
            print(f"  • {finding}")
        
        assert result.heuristic_score > 30, "Suspicious script should have high score"
        return True
    
    def test_fake_pe_executable(self):
        """Test 3: Fake PE executable"""
        print("\n[TEST 3] Scanning fake PE executable...")
        
        # Create a fake PE file with MZ header
        content = b'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00'
        content += b'\xb8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00'
        content += b'PE\x00\x00'  # PE signature
        content += b'\x00' * 100  # Padding
        
        filepath = self.create_test_file('fake.exe', content)
        result = self.av.scan_file(str(filepath))
        
        print(f"Heuristic Score: {result.heuristic_score}")
        print(f"Detected as PE: {'Yes' if 'PE executable' in str(result.details) else 'No'}")
        
        assert result.heuristic_score > 0, "PE file should trigger detection"
        return True
    
    def test_high_entropy_file(self):
        """Test 4: High entropy file (simulated encryption)"""
        print("\n[TEST 4] Scanning high entropy file...")
        
        # Create pseudo-random content (high entropy)
        import random
        random.seed(42)
        content = bytes([random.randint(0, 255) for _ in range(5000)])
        
        filepath = self.create_test_file('encrypted.bin', content)
        result = self.av.scan_file(str(filepath))
        
        print(f"Heuristic Score: {result.heuristic_score}")
        findings = result.details.get('heuristic_findings', [])
        high_entropy = any('entropy' in f.lower() for f in findings)
        
        print(f"High entropy detected: {high_entropy}")
        
        return True
    
    def test_embedded_urls(self):
        """Test 5: File with many URLs"""
        print("\n[TEST 5] Scanning file with multiple URLs...")
        
        content = b'''
        http://malicious1.com/payload
        http://malicious2.com/download
        http://malicious3.com/exploit
        https://evil4.com/backdoor
        https://evil5.com/trojan
        http://bad6.com/virus
        http://bad7.com/ransomware
        https://malware8.com/payload
        http://hack9.com/exploit
        http://phishing10.com/steal
        https://scam11.com/malware
        http://threat12.com/virus
        '''
        
        filepath = self.create_test_file('urls.txt', content)
        result = self.av.scan_file(str(filepath))
        
        print(f"Heuristic Score: {result.heuristic_score}")
        findings = result.details.get('heuristic_findings', [])
        url_finding = [f for f in findings if 'URL' in f]
        
        if url_finding:
            print(f"Finding: {url_finding[0]}")
        
        return True
    
    def test_signature_match(self):
        """Test 6: Known signature match"""
        print("\n[TEST 6] Testing signature detection...")
        
        # Add a test signature first
        test_pattern = b'\xDE\xAD\xBE\xEF'
        self.av.signature_db.add_signature(
            name="Test.Malware.Pattern",
            signature=test_pattern,
            threat_type="test",
            severity="high"
        )
        
        # Create file with the pattern
        content = b'Some normal content ' + test_pattern + b' more content'
        filepath = self.create_test_file('signature_test.bin', content)
        result = self.av.scan_file(str(filepath))
        
        print(f"Infected: {result.is_infected}")
        if result.is_infected:
            print(f"Threats found: {[t['name'] for t in result.threats_found]}")
        
        assert result.is_infected, "File with known signature should be detected"
        return True
    
    def test_hash_detection(self):
        """Test 7: Hash-based detection"""
        print("\n[TEST 7] Testing hash-based detection...")
        
        # Create a file
        content = b'This is a test malware file for hash detection'
        filepath = self.create_test_file('hash_test.txt', content)
        
        # Calculate its hash
        file_hash = self.av.calculate_file_hash(str(filepath))
        print(f"File hash: {file_hash}")
        
        # Add hash to database
        self.av.signature_db.add_hash(
            file_hash=file_hash,
            threat_name="Test.Malware.Hash",
            threat_type="test",
            severity="medium"
        )
        
        # Scan the file
        result = self.av.scan_file(str(filepath))
        
        print(f"Infected: {result.is_infected}")
        if result.is_infected:
            print(f"Detection method: {result.threats_found[0]['method']}")
        
        assert result.is_infected, "File with known hash should be detected"
        return True
    
    def test_directory_scan(self):
        """Test 8: Directory scanning"""
        print("\n[TEST 8] Testing directory scan...")
        
        # Create multiple files
        self.create_test_file('file1.txt', b'Clean file 1')
        self.create_test_file('file2.txt', b'Clean file 2')
        self.create_test_file('suspicious.py', b'import subprocess\nos.system("rm -rf /")')
        
        # Scan directory
        results = self.av.scan_directory(str(self.test_dir), recursive=False)
        
        print(f"Files scanned: {len(results)}")
        infected = sum(1 for r in results if r.is_infected)
        print(f"Infected files: {infected}")
        
        assert len(results) >= 3, "Should scan multiple files"
        return True
    
    def run_all_tests(self):
        """Run all tests"""
        print("=" * 70)
        print("ANTIVIRUS SYSTEM TEST SUITE")
        print("=" * 70)
        
        tests = [
            self.test_clean_file,
            self.test_suspicious_python_script,
            self.test_fake_pe_executable,
            self.test_high_entropy_file,
            self.test_embedded_urls,
            self.test_signature_match,
            self.test_hash_detection,
            self.test_directory_scan,
        ]
        
        passed = 0
        failed = 0
        
        for test in tests:
            try:
                if test():
                    passed += 1
                    print(f"✓ {test.__doc__} - PASSED")
                else:
                    failed += 1
                    print(f"✗ {test.__doc__} - FAILED")
            except Exception as e:
                failed += 1
                print(f"✗ {test.__doc__} - ERROR: {e}")
        
        print("\n" + "=" * 70)
        print(f"RESULTS: {passed} passed, {failed} failed")
        print("=" * 70)
        
        self.cleanup()
        return failed == 0


if __name__ == "__main__":
    suite = TestSuite()
    success = suite.run_all_tests()
    exit(0 if success else 1)
