# Advanced Antivirus System

A comprehensive, multi-layered antivirus protection system with signature-based detection, heuristic analysis, and behavioral monitoring.

## 🛡️ Features

### 1. **Multi-Layer Detection**
- **Signature-based scanning**: Fast pattern matching against known malware signatures
- **Hash-based detection**: Quick identification of known malicious files using SHA256 hashes
- **Heuristic analysis**: Intelligent detection of suspicious patterns and behaviors
- **Behavioral monitoring**: Real-time process and file system monitoring

### 2. **Core Capabilities**
- ✅ File and directory scanning (recursive)
- ✅ Real-time behavioral monitoring
- ✅ Automatic quarantine system
- ✅ Detailed threat reporting
- ✅ Custom signature management
- ✅ Process termination for suspicious activity
- ✅ Entropy analysis for obfuscation detection
- ✅ PE/ELF file analysis

## 📁 Project Structure

```
antivirus-system/
├── antivirus_engine.py      # Core scanning engine
├── behavioral_analysis.py    # Real-time monitoring system
├── antivirus_cli.py         # Command-line interface
├── example_signatures.json  # Sample malware signatures
├── signatures.db            # Signature database (auto-created)
├── quarantine/              # Quarantine directory (auto-created)
└── README.md               # This file
```

## 🚀 Quick Start

### Installation

1. **Install dependencies:**
```bash
pip install psutil --break-system-packages
```

2. **Make the CLI executable:**
```bash
chmod +x antivirus_cli.py
```

### Basic Usage

#### 1. Scan a Single File
```bash
python3 antivirus_cli.py scan /path/to/file
```

#### 2. Scan a Directory (Recursive)
```bash
python3 antivirus_cli.py scan /path/to/directory -r
```

#### 3. Scan with Quarantine
```bash
python3 antivirus_cli.py scan /path/to/directory -r --quarantine
```

#### 4. Generate Report
```bash
python3 antivirus_cli.py scan /path/to/directory -r --report scan_report.json
```

#### 5. Real-Time Monitoring
```bash
python3 antivirus_cli.py monitor
```

#### 6. Update Signatures
```bash
python3 antivirus_cli.py update --signature-file example_signatures.json
```

#### 7. Manage Quarantine
```bash
# List quarantined files
python3 antivirus_cli.py quarantine --list

# Restore a file
python3 antivirus_cli.py quarantine --restore filename.ext

# Delete a file
python3 antivirus_cli.py quarantine --delete filename.ext

# Clear all quarantine
python3 antivirus_cli.py quarantine --clear
```

## 🔍 Detection Methods Explained

### 1. Signature-Based Detection
Scans files for known byte patterns that match malware signatures. Fast and reliable for known threats.

**Example signatures:**
- `4d5a` - MZ header (Windows executable)
- `255044462d` - PDF header
- Custom malware patterns

### 2. Hash-Based Detection
Compares SHA256 hash of files against database of known malicious file hashes. Instant detection for exact matches.

### 3. Heuristic Analysis
Analyzes files for suspicious characteristics without needing exact signatures:

**Detection criteria:**
- Suspicious API calls (VirtualAlloc, CreateRemoteThread, etc.)
- Code execution patterns (eval, exec, subprocess)
- High entropy (encryption/obfuscation)
- Embedded executables
- Network activity patterns
- Registry modifications
- Multiple Base64 strings
- Suspicious file operations

**Scoring system:**
- 0-30: Low risk
- 31-50: Medium risk (flagged)
- 51-80: High risk
- 81+: Critical risk

### 4. Behavioral Monitoring
Real-time monitoring of system activity:

**Monitored behaviors:**
- Rapid file creation (ransomware indicator)
- Mass file modifications
- Network scanning
- Privilege escalation attempts
- Suspicious network connections
- File extension changes (encryption)
- High CPU usage (crypto mining)

## 🧪 Testing the System

### Create Test Files

```python
# Create a test file with suspicious content
with open('test_suspicious.py', 'w') as f:
    f.write('''
import subprocess
import socket
import base64

# This will trigger heuristic detection
data = base64.b64decode("dGVzdA==")
subprocess.run(["echo", "test"])
sock = socket.socket()
''')
```

```bash
# Scan the test file
python3 antivirus_cli.py scan test_suspicious.py
```

Expected output: High heuristic score due to multiple suspicious patterns

## 📊 Understanding Scan Results

### Sample Output
```
File: /path/to/file.exe
Status: INFECTED
Hash: a1b2c3d4...
Heuristic Score: 75

Threats Detected:
  • Trojan.Generic.MZ
    Method: signature | Severity: high
  • Suspicious behavior (score: 75)
    Method: heuristic | Severity: high

Heuristic Findings:
  • Code execution via subprocess.
  • Network socket creation
  • High entropy detected: 7.8 (possible obfuscation)
  • Multiple Base64 strings found (12)
  • PE executable detected
```

### Severity Levels
- **Low**: Minor suspicious indicators, likely false positive
- **Medium**: Multiple suspicious patterns, investigate further
- **High**: Strong malware indicators, likely threat
- **Critical**: Definite threat, immediate action required

## 🔧 Advanced Usage

### Using the API Programmatically

```python
from antivirus_engine import AntivirusEngine

# Initialize engine
av = AntivirusEngine()

# Scan a file
result = av.scan_file('/path/to/file')

if result.is_infected:
    print(f"Threats found: {result.threats_found}")
    print(f"Heuristic score: {result.heuristic_score}")
    
    # Quarantine the file
    av.quarantine_file('/path/to/file')

# Scan a directory
results = av.scan_directory('/path/to/dir', recursive=True)

# Generate report
report = av.generate_report(results)
print(report)
```

### Adding Custom Signatures

```python
from antivirus_engine import AntivirusEngine

av = AntivirusEngine()

# Add a signature
av.signature_db.add_signature(
    name="MyMalware.Variant.A",
    signature=b"\x4d\x5a\x90\x00",  # Byte pattern
    threat_type="trojan",
    severity="high"
)

# Add a malicious file hash
av.signature_db.add_hash(
    file_hash="abc123...",
    threat_name="Known.Malware.Hash",
    threat_type="ransomware",
    severity="critical"
)
```

### Custom Behavioral Monitoring

```python
from behavioral_analysis import BehavioralAnalyzer

analyzer = BehavioralAnalyzer()

# Custom alert handler
def my_alert_handler(alert):
    print(f"ALERT: {alert['description']}")
    if alert['severity'] == 'critical':
        # Take action
        pass

analyzer.process_monitor.register_alert_callback(my_alert_handler)
analyzer.start_monitoring()
```

## 🏗️ Architecture

### System Components

```
┌─────────────────────────────────────────────────────┐
│                 CLI Interface                       │
│            (antivirus_cli.py)                       │
└───────────────┬─────────────────────────────────────┘
                │
                ├─────────────────────────────────────┐
                │                                     │
    ┌───────────▼───────────┐         ┌──────────────▼──────────┐
    │  Antivirus Engine     │         │  Behavioral Analyzer    │
    │ (antivirus_engine.py) │         │ (behavioral_analysis.py)│
    └───────────┬───────────┘         └───────────┬─────────────┘
                │                                  │
    ┌───────────┼──────────────────────┐          │
    │           │                      │          │
┌───▼────┐ ┌───▼─────┐ ┌──────────▼───────┐ ┌───▼──────┐
│Signature│ │  Hash   │ │   Heuristic      │ │ Process  │
│ Scanner │ │ Scanner │ │    Analyzer      │ │ Monitor  │
└─────────┘ └─────────┘ └──────────────────┘ └──────────┘
                                              ┌──────────┐
                                              │   File   │
                                              │  Watcher │
                                              └──────────┘
```

### Detection Flow

```
File Input
    │
    ├─→ Hash Scan ────────→ Known Hash? ──→ [THREAT]
    │                           │
    │                           ↓
    │                         [Continue]
    │
    ├─→ Signature Scan ───→ Pattern Match? ─→ [THREAT]
    │                           │
    │                           ↓
    │                         [Continue]
    │
    └─→ Heuristic Analysis
            │
            ├─→ Pattern Detection
            ├─→ Entropy Analysis
            ├─→ API Call Analysis
            └─→ Behavioral Scoring
                    │
                    ↓
                Score > Threshold? ─→ [SUSPICIOUS]
                    │
                    ↓
                 [CLEAN]
```

## 🔒 Security Considerations

### Safe Malware Handling
When working with actual malware samples:

1. **Use virtual machines** - Never test on production systems
2. **Air-gap systems** - Isolate testing environments
3. **Use legitimate sources** - VirusTotal, malware databases
4. **Encrypted storage** - Secure malware samples properly
5. **Proper disposal** - Securely wipe samples after testing

### Production Deployment
For production use:

1. **Regular signature updates** - Implement automated updates
2. **Performance monitoring** - Watch system resource usage
3. **False positive management** - Maintain whitelist for safe files
4. **Logging and auditing** - Track all detections and actions
5. **User permissions** - Require admin rights for system-level operations

## 📈 Performance Optimization

### For Large-Scale Scanning
```python
# Use parallel processing for directory scans
import concurrent.futures

def scan_file_wrapper(filepath):
    av = AntivirusEngine()
    return av.scan_file(filepath)

with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
    results = list(executor.map(scan_file_wrapper, file_list))
```

### Memory-Mapped File Scanning
The engine uses `mmap` for efficient scanning of large files without loading entire contents into memory.

### Signature Database Optimization
- Index signatures by prefix for faster lookup
- Use bloom filters for quick negative matches
- Cache frequently accessed signatures

## 🔍 Troubleshooting

### Common Issues

**Issue: "Permission denied" errors**
- Run with appropriate permissions: `sudo python3 antivirus_cli.py scan /`
- Some system files require elevated privileges

**Issue: High CPU usage during monitoring**
- Reduce monitoring frequency in `behavioral_analysis.py`
- Limit monitored directories for file system watching

**Issue: False positives**
- Adjust heuristic threshold in `HeuristicAnalyzer`
- Add files to whitelist
- Use `--no-heuristics` flag for signature-only scanning

**Issue: Slow scanning**
- Disable heuristic analysis for quick scans
- Use signature-only mode
- Scan smaller directory trees

## 📝 Customization

### Adjust Heuristic Sensitivity
Edit `antivirus_engine.py`:
```python
class HeuristicAnalyzer:
    def __init__(self):
        self.suspicious_score_threshold = 50  # Lower = more sensitive
```

### Add Custom Patterns
Edit `SUSPICIOUS_PATTERNS` in `HeuristicAnalyzer`:
```python
SUSPICIOUS_PATTERNS = [
    (rb'your_pattern', 'Your description', 15),  # score weight
    # Add more patterns...
]
```

### Modify Behavioral Alerts
Edit `BehaviorPattern` thresholds in `behavioral_analysis.py`:
```python
'rapid_file_creation': BehaviorPattern(
    'Rapid File Creation',
    'Process creating many files quickly',
    'high',
    threshold=50  # Adjust this
)
```

## 🎯 Roadmap

### Planned Features
- [ ] Cloud-based signature updates
- [ ] Machine learning-based detection
- [ ] Network traffic analysis
- [ ] Email attachment scanning
- [ ] Browser extension protection
- [ ] Web-based management interface
- [ ] Distributed scanning across multiple machines
- [ ] Integration with threat intelligence feeds

## 🤝 Contributing

To add your own detection methods:

1. Create a new module in the project
2. Implement the scanning logic
3. Integrate with `AntivirusEngine`
4. Add tests and documentation
5. Update this README

## 📚 Further Reading

- [YARA Rules](https://virustotal.github.io/yara/) - Advanced pattern matching
- [VirusTotal API](https://www.virustotal.com/gui/home/upload) - Malware intelligence
- [MITRE ATT&CK](https://attack.mitre.org/) - Threat tactics and techniques
- [Malware Analysis](https://www.malware-traffic-analysis.net/) - Training resources

## ⚠️ Disclaimer

This antivirus system is provided for educational and research purposes. While it implements multiple detection methods, it should not be considered a replacement for professional, commercial antivirus solutions in production environments. Always test thoroughly and use in conjunction with other security measures.

## 📄 License

This project is provided as-is for educational purposes. Use responsibly and ethically.

---

**Built with security in mind** 🔐
