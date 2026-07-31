"""
Advanced Antivirus Engine
A comprehensive antivirus system with multiple detection methods
"""

import hashlib
import os
import re
import json
import mmap
import struct
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Tuple, Optional
import logging

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ThreatSignature:
    """Represents a malware signature"""
    def __init__(self, name: str, signature: bytes, threat_type: str, severity: str):
        self.name = name
        self.signature = signature
        self.threat_type = threat_type
        self.severity = severity


class ScanResult:
    """Represents the result of a file scan"""
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.is_infected = False
        self.threats_found = []
        self.scan_time = datetime.now()
        self.file_hash = None
        self.heuristic_score = 0
        self.details = {}
    
    def add_threat(self, threat_name: str, detection_method: str, severity: str):
        """Add a detected threat"""
        self.is_infected = True
        self.threats_found.append({
            'name': threat_name,
            'method': detection_method,
            'severity': severity,
            'timestamp': datetime.now().isoformat()
        })
    
    def to_dict(self):
        """Convert to dictionary for reporting"""
        return {
            'filepath': self.filepath,
            'is_infected': self.is_infected,
            'threats': self.threats_found,
            'scan_time': self.scan_time.isoformat(),
            'file_hash': self.file_hash,
            'heuristic_score': self.heuristic_score,
            'details': self.details
        }


class SignatureDatabase:
    """Manages malware signatures"""
    def __init__(self, db_path: str = 'signatures.db'):
        self.db_path = db_path
        self.signatures: List[ThreatSignature] = []
        self.hash_database: Dict[str, dict] = {}
        self.load_signatures()
    
    def load_signatures(self):
        """Load signatures from database"""
        if os.path.exists(self.db_path):
            try:
                with open(self.db_path, 'r') as f:
                    data = json.load(f)
                    
                    # Load byte signatures
                    for sig in data.get('signatures', []):
                        self.signatures.append(ThreatSignature(
                            name=sig['name'],
                            signature=bytes.fromhex(sig['signature']),
                            threat_type=sig['type'],
                            severity=sig['severity']
                        ))
                    
                    # Load hash database
                    self.hash_database = data.get('hash_database', {})
                    
                logger.info(f"Loaded {len(self.signatures)} signatures and {len(self.hash_database)} hashes")
            except Exception as e:
                logger.error(f"Error loading signature database: {e}")
    
    def save_signatures(self):
        """Save signatures to database"""
        try:
            data = {
                'signatures': [
                    {
                        'name': sig.name,
                        'signature': sig.signature.hex(),
                        'type': sig.threat_type,
                        'severity': sig.severity
                    } for sig in self.signatures
                ],
                'hash_database': self.hash_database,
                'last_updated': datetime.now().isoformat()
            }
            
            with open(self.db_path, 'w') as f:
                json.dump(data, f, indent=2)
            
            logger.info(f"Saved {len(self.signatures)} signatures")
        except Exception as e:
            logger.error(f"Error saving signature database: {e}")
    
    def add_signature(self, name: str, signature: bytes, threat_type: str, severity: str):
        """Add a new signature"""
        self.signatures.append(ThreatSignature(name, signature, threat_type, severity))
        self.save_signatures()
    
    def add_hash(self, file_hash: str, threat_name: str, threat_type: str, severity: str):
        """Add a malicious file hash"""
        self.hash_database[file_hash] = {
            'name': threat_name,
            'type': threat_type,
            'severity': severity,
            'added': datetime.now().isoformat()
        }
        self.save_signatures()


class HeuristicAnalyzer:
    """Performs heuristic analysis on files"""
    
    # Suspicious patterns (regex)
    SUSPICIOUS_PATTERNS = [
        (rb'eval\s*\(', 'Code execution via eval()', 15),
        (rb'exec\s*\(', 'Code execution via exec()', 15),
        (rb'__import__\s*\(', 'Dynamic import', 10),
        (rb'subprocess\.', 'Subprocess execution', 12),
        (rb'os\.system', 'System command execution', 15),
        (rb'base64\.b64decode', 'Base64 decoding (possible obfuscation)', 8),
        (rb'socket\.socket', 'Network socket creation', 10),
        (rb'urllib.*open', 'URL opening', 8),
        (rb'requests\.get|requests\.post', 'HTTP requests', 7),
        (rb'pickle\.loads', 'Pickle deserialization', 12),
        (rb'marshal\.loads', 'Marshal loads', 12),
        (rb'\.popen\(', 'Popen execution', 13),
        (rb'cryptography|Crypto', 'Cryptography usage', 5),
        (rb'keylogger|keylogs', 'Keylogger keywords', 20),
        (rb'ransomware|encrypt.*files', 'Ransomware keywords', 25),
        (rb'password|passwd', 'Password-related', 5),
        (rb'cmd\.exe|powershell\.exe', 'Shell execution', 15),
        (rb'reg\s+add|regedit', 'Registry manipulation', 12),
        (rb'rundll32', 'Rundll32 execution', 13),
        (rb'schtasks|at\.exe', 'Task scheduling', 10),
        (rb'wscript|cscript', 'Script host execution', 12),
    ]
    
    # Suspicious API calls (Windows)
    SUSPICIOUS_APIS = [
        b'VirtualAlloc', b'VirtualProtect', b'CreateRemoteThread',
        b'WriteProcessMemory', b'OpenProcess', b'LoadLibrary',
        b'GetProcAddress', b'WinExec', b'ShellExecute'
    ]
    
    # File type magic numbers
    PE_SIGNATURE = b'MZ'
    ELF_SIGNATURE = b'\x7fELF'
    
    def __init__(self):
        self.suspicious_score_threshold = 50  # Threshold for flagging as suspicious
    
    def analyze_file(self, filepath: str) -> Tuple[int, List[str]]:
        """
        Perform heuristic analysis on a file
        Returns: (score, list of findings)
        """
        score = 0
        findings = []
        
        try:
            with open(filepath, 'rb') as f:
                content = f.read()
            
            # Check file size
            file_size = len(content)
            if file_size == 0:
                findings.append("Empty file")
                return 0, findings
            
            # Check for suspicious patterns
            for pattern, description, pattern_score in self.SUSPICIOUS_PATTERNS:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    count = len(matches)
                    score += pattern_score * min(count, 3)  # Cap multiplier at 3
                    findings.append(f"{description} (found {count} times)")
            
            # Check for suspicious API calls
            for api in self.SUSPICIOUS_APIS:
                if api in content:
                    score += 10
                    findings.append(f"Suspicious API call: {api.decode('utf-8', errors='ignore')}")
            
            # Check for high entropy (possible encryption/obfuscation)
            entropy = self.calculate_entropy(content[:min(len(content), 10000)])
            if entropy > 7.5:
                score += 15
                findings.append(f"High entropy detected: {entropy:.2f} (possible obfuscation)")
            
            # Check for executable characteristics
            if content.startswith(self.PE_SIGNATURE):
                findings.append("PE executable detected")
                score += self.analyze_pe_file(content, findings)
            elif content.startswith(self.ELF_SIGNATURE):
                findings.append("ELF executable detected")
                score += 5
            
            # Check for embedded executables
            if self.PE_SIGNATURE in content[100:]:
                score += 20
                findings.append("Embedded executable detected")
            
            # Check for long Base64 strings (possible payload)
            base64_pattern = rb'[A-Za-z0-9+/]{50,}={0,2}'
            base64_matches = re.findall(base64_pattern, content)
            if len(base64_matches) > 5:
                score += 10
                findings.append(f"Multiple Base64 strings found ({len(base64_matches)})")
            
            # Check for URLs
            url_pattern = rb'https?://[^\s<>"\']+|www\.[^\s<>"\']+'
            urls = re.findall(url_pattern, content)
            if len(urls) > 10:
                score += 8
                findings.append(f"Multiple URLs found ({len(urls)})")
            
            # Check for IP addresses
            ip_pattern = rb'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
            ips = re.findall(ip_pattern, content)
            if len(ips) > 5:
                score += 7
                findings.append(f"Multiple IP addresses found ({len(ips)})")
            
        except Exception as e:
            logger.error(f"Error during heuristic analysis: {e}")
            findings.append(f"Analysis error: {str(e)}")
        
        return score, findings
    
    def analyze_pe_file(self, content: bytes, findings: List[str]) -> int:
        """Analyze PE file structure for suspicious characteristics"""
        score = 0
        
        try:
            # Check for missing or invalid PE header
            if len(content) < 64:
                return 0
            
            # Get PE header offset
            pe_offset = struct.unpack('<I', content[60:64])[0]
            
            if pe_offset >= len(content) - 4:
                return 0
            
            # Verify PE signature
            if content[pe_offset:pe_offset+4] != b'PE\x00\x00':
                findings.append("Invalid PE signature")
                score += 15
            
            # Check for suspicious section names
            suspicious_sections = [b'.text', b'UPX', b'.vmp', b'.themida', b'ASPack']
            for section in suspicious_sections:
                if section in content:
                    findings.append(f"Suspicious section: {section.decode('utf-8', errors='ignore')}")
                    score += 10
            
        except Exception as e:
            logger.debug(f"PE analysis error: {e}")
        
        return score
    
    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0
        
        import math
        entropy = 0
        for x in range(256):
            p_x = float(data.count(bytes([x]))) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log2(p_x)
        
        return entropy


class AntivirusEngine:
    """Main antivirus engine"""
    
    def __init__(self, signature_db_path: str = 'signatures.db'):
        self.signature_db = SignatureDatabase(signature_db_path)
        self.heuristic_analyzer = HeuristicAnalyzer()
        self.quarantine_dir = Path('quarantine')
        self.quarantine_dir.mkdir(exist_ok=True)
        
        logger.info("Antivirus Engine initialized")
    
    def calculate_file_hash(self, filepath: str) -> str:
        """Calculate SHA256 hash of file"""
        sha256_hash = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            logger.error(f"Error calculating hash: {e}")
            return ""
    
    def signature_scan(self, filepath: str, result: ScanResult):
        """Perform signature-based scanning"""
        try:
            with open(filepath, 'rb') as f:
                # Use memory mapping for efficient scanning of large files
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mmapped_file:
                    content = mmapped_file[:]
                    
                    # Check each signature
                    for signature in self.signature_db.signatures:
                        if signature.signature in content:
                            result.add_threat(
                                signature.name,
                                'signature',
                                signature.severity
                            )
                            logger.warning(f"Signature match: {signature.name} in {filepath}")
        
        except Exception as e:
            logger.error(f"Error during signature scan: {e}")
            result.details['signature_scan_error'] = str(e)
    
    def hash_scan(self, filepath: str, result: ScanResult):
        """Perform hash-based scanning"""
        file_hash = self.calculate_file_hash(filepath)
        result.file_hash = file_hash
        
        if file_hash in self.signature_db.hash_database:
            threat_info = self.signature_db.hash_database[file_hash]
            result.add_threat(
                threat_info['name'],
                'hash',
                threat_info['severity']
            )
            logger.warning(f"Hash match: {threat_info['name']} in {filepath}")
    
    def heuristic_scan(self, filepath: str, result: ScanResult):
        """Perform heuristic analysis"""
        score, findings = self.heuristic_analyzer.analyze_file(filepath)
        result.heuristic_score = score
        result.details['heuristic_findings'] = findings
        
        if score >= self.heuristic_analyzer.suspicious_score_threshold:
            result.add_threat(
                f"Suspicious behavior (score: {score})",
                'heuristic',
                'medium' if score < 80 else 'high'
            )
            logger.warning(f"Heuristic detection: score {score} in {filepath}")
    
    def scan_file(self, filepath: str, use_heuristics: bool = True) -> ScanResult:
        """
        Perform a complete scan of a file
        """
        logger.info(f"Scanning: {filepath}")
        result = ScanResult(filepath)
        
        if not os.path.exists(filepath):
            result.details['error'] = 'File not found'
            return result
        
        if not os.path.isfile(filepath):
            result.details['error'] = 'Not a file'
            return result
        
        # Perform hash-based scan
        self.hash_scan(filepath, result)
        
        # Perform signature-based scan
        self.signature_scan(filepath, result)
        
        # Perform heuristic analysis if enabled
        if use_heuristics:
            self.heuristic_scan(filepath, result)
        
        return result
    
    def scan_directory(self, directory: str, recursive: bool = True, 
                      use_heuristics: bool = True) -> List[ScanResult]:
        """
        Scan all files in a directory
        """
        results = []
        
        if recursive:
            for root, dirs, files in os.walk(directory):
                for filename in files:
                    filepath = os.path.join(root, filename)
                    result = self.scan_file(filepath, use_heuristics)
                    results.append(result)
        else:
            for filename in os.listdir(directory):
                filepath = os.path.join(directory, filename)
                if os.path.isfile(filepath):
                    result = self.scan_file(filepath, use_heuristics)
                    results.append(result)
        
        return results
    
    def quarantine_file(self, filepath: str) -> bool:
        """Move infected file to quarantine"""
        try:
            filename = Path(filepath).name
            quarantine_path = self.quarantine_dir / f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{filename}"
            
            # Move file to quarantine
            os.rename(filepath, quarantine_path)
            logger.info(f"Quarantined: {filepath} -> {quarantine_path}")
            return True
        
        except Exception as e:
            logger.error(f"Error quarantining file: {e}")
            return False
    
    def update_signatures(self, new_signatures: List[dict]):
        """Update signature database with new signatures"""
        for sig in new_signatures:
            self.signature_db.add_signature(
                name=sig['name'],
                signature=bytes.fromhex(sig['signature']),
                threat_type=sig.get('type', 'unknown'),
                severity=sig.get('severity', 'medium')
            )
        logger.info(f"Updated {len(new_signatures)} signatures")
    
    def generate_report(self, results: List[ScanResult]) -> dict:
        """Generate a scan report"""
        total_files = len(results)
        infected_files = sum(1 for r in results if r.is_infected)
        
        report = {
            'scan_summary': {
                'total_files_scanned': total_files,
                'infected_files': infected_files,
                'clean_files': total_files - infected_files,
                'scan_date': datetime.now().isoformat()
            },
            'infected_files': [
                r.to_dict() for r in results if r.is_infected
            ],
            'statistics': {
                'detection_methods': {},
                'threat_types': {},
                'severity_levels': {}
            }
        }
        
        # Gather statistics
        for result in results:
            if result.is_infected:
                for threat in result.threats_found:
                    method = threat['method']
                    severity = threat['severity']
                    
                    report['statistics']['detection_methods'][method] = \
                        report['statistics']['detection_methods'].get(method, 0) + 1
                    report['statistics']['severity_levels'][severity] = \
                        report['statistics']['severity_levels'].get(severity, 0) + 1
        
        return report


if __name__ == "__main__":
    # Example usage
    print("Antivirus Engine - Example Usage")
    print("=" * 50)
    
    # Initialize engine
    av = AntivirusEngine()
    
    # Example: Add some test signatures
    print("\n[+] Adding example signatures...")
    av.signature_db.add_signature(
        name="Test.Malware.Generic",
        signature=b"\x4d\x5a\x90\x00",  # MZ header
        threat_type="trojan",
        severity="high"
    )
    
    print("[+] Antivirus engine ready!")
    print("[+] Use the AntivirusEngine class to scan files and directories")
