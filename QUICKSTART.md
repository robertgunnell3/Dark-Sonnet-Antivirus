# 🚀 Quick Start Guide - Antivirus System

## Installation (1 minute)

```bash
# 1. Install required dependency
pip install psutil --break-system-packages

# 2. Make scripts executable
chmod +x antivirus_cli.py test_suite.py

# 3. Test the system
python3 test_suite.py
```

## Basic Usage Examples

### Scan a Single File
```bash
python3 antivirus_cli.py scan myfile.exe
```

### Scan Your Downloads Folder
```bash
python3 antivirus_cli.py scan ~/Downloads -r
```

### Scan and Auto-Quarantine Threats
```bash
python3 antivirus_cli.py scan ~/Downloads -r --quarantine
```

### Real-Time Protection
```bash
python3 antivirus_cli.py monitor
# Press Ctrl+C to stop
```

### Update Signatures
```bash
python3 antivirus_cli.py update --signature-file example_signatures.json
```

### View Quarantined Files
```bash
python3 antivirus_cli.py quarantine --list
```

## What Gets Detected?

✅ **Known Malware** - Via signatures and file hashes
✅ **Suspicious Scripts** - Python/shell scripts with dangerous commands
✅ **Obfuscated Code** - High entropy, Base64 encoding
✅ **Network Activity** - Multiple connections, suspicious ports
✅ **File Operations** - Mass file modifications (ransomware behavior)
✅ **System Commands** - Attempts to execute system commands
✅ **Process Behavior** - Privilege escalation, unusual CPU usage

## Understanding Results

When you scan a file, you'll see:
- **Status**: CLEAN or INFECTED
- **Hash**: SHA256 fingerprint
- **Heuristic Score**: 0-100 (higher = more suspicious)
- **Threats**: Specific malware detected
- **Findings**: Why it's suspicious

### Score Interpretation
- **0-30**: Likely safe
- **31-50**: Suspicious, review manually
- **51-80**: High risk, probably malware
- **81+**: Critical threat

## Creating Your Own Signatures

Edit `example_signatures.json`:
```json
{
  "name": "MyThreat.Name",
  "signature": "4d5a",  // Hex bytes to match
  "type": "trojan",
  "severity": "high"
}
```

Then update:
```bash
python3 antivirus_cli.py update --signature-file example_signatures.json
```

## Python API Usage

```python
from antivirus_engine import AntivirusEngine

# Initialize
av = AntivirusEngine()

# Scan a file
result = av.scan_file('/path/to/file')

if result.is_infected:
    print(f"THREAT: {result.threats_found}")
    av.quarantine_file('/path/to/file')
else:
    print("File is clean")
```

## Common Workflows

### Daily System Scan
```bash
python3 antivirus_cli.py scan ~ -r --report daily_scan.json
```

### Check Suspicious Email Attachment
```bash
python3 antivirus_cli.py scan attachment.pdf
```

### Monitor System During Software Install
```bash
python3 antivirus_cli.py monitor
# Install your software in another terminal
# Watch for suspicious behavior
```

## Troubleshooting

**"Permission denied"** - Run with sudo for system files
**"Slow scanning"** - Use `--no-heuristics` for faster scans
**"Too many false positives"** - Lower threshold or whitelist files

## Safety Tips

⚠️ **Never test with real malware on production systems**
⚠️ **Use virtual machines for testing**
⚠️ **Don't open quarantined files directly**
⚠️ **Keep signatures updated regularly**

## Next Steps

1. Run `python3 test_suite.py` to see all features
2. Read `README.md` for detailed documentation
3. Customize detection patterns in `antivirus_engine.py`
4. Add your own signatures to `example_signatures.json`

## Getting Help

Check the full documentation in `README.md` for:
- Architecture details
- Advanced configuration
- Custom detection methods
- Performance optimization
- API reference

---
**Stay protected!** 🛡️
