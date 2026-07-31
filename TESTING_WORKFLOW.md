# Testing & Development Workflow Guide

## Quick Start Testing

### 1. Run the Interactive Lab

```bash
python3 heuristic_lab.py
```

This gives you a full interactive environment to:
- Test individual files
- Benchmark on datasets
- Tune detection weights
- Add custom rules
- Extract features for analysis

### 2. Run Automated Tests

```bash
# Full test suite
python3 test_suite.py

# Advanced heuristics testing
python3 advanced_heuristics.py
```

## Testing Workflow

### Phase 1: Baseline Testing

**Goal:** Understand current detection capabilities

```bash
# 1. Create test samples
python3 -c "from advanced_heuristics import create_test_samples; create_test_samples()"

# 2. Run benchmark
python3 advanced_heuristics.py

# 3. Review results
# Check True Positive Rate (should be >80%)
# Check False Positive Rate (should be <5%)
```

**Expected Output:**
```
True Positive Rate: 75-90%
False Positive Rate: 0-5%
Optimal Threshold: 40-50
```

### Phase 2: Custom Rule Development

**Scenario:** You want to detect a specific malware family

```python
# In Python shell or script:
from advanced_heuristics import AdvancedHeuristicEngine

engine = AdvancedHeuristicEngine()

# Add custom rule
engine.add_custom_rule(
    name="MyMalware.Variant.A",
    pattern=b"unique_malware_string",  # Or bytes.fromhex("4d5a90")
    weight=25,
    description="Detects MyMalware via unique string",
    category="code_execution"
)

# Test it
score, matches = engine.analyze_with_custom_rules("suspicious_file.exe")
print(f"Score: {score}")
print(f"Matches: {matches}")
```

### Phase 3: Weight Tuning

**Problem:** Too many false positives or missing threats

```bash
# Start interactive lab
python3 heuristic_lab.py

# Then:
# [3] Benchmark on Dataset - See current performance
# [4] Adjust Weights - Modify detection sensitivity
# [3] Benchmark again - Verify improvements
# [9] Export Configuration - Save your settings
```

**Tuning Strategy:**

```
Too many FALSE POSITIVES?
→ Increase threshold (50 → 60)
→ Decrease pattern weights
→ Add more specific patterns

Too many FALSE NEGATIVES (missed threats)?
→ Decrease threshold (50 → 40)
→ Increase critical pattern weights
→ Add behavioral patterns
```

### Phase 4: Feature Engineering

**Goal:** Extract features for ML or deep analysis

```bash
python3 heuristic_lab.py
# Select [7] Feature Extraction Analysis
# Enter file path
# Review extracted features
# Save to JSON for ML training
```

**Features Extracted:**
- Entropy statistics
- String patterns
- Import tables (PE files)
- Opcode distributions
- Network indicators
- Behavioral patterns

## Real-World Testing Scenarios

### Scenario 1: Testing a Suspicious Email Attachment

```bash
# Method 1: CLI
python3 antivirus_cli.py scan downloaded_file.pdf

# Method 2: Interactive Lab
python3 heuristic_lab.py
# [1] Test Single File
# Enter path: downloaded_file.pdf
# Review: Score, Findings, Risk Level
```

### Scenario 2: Scanning Downloads Folder

```bash
# Quick scan
python3 antivirus_cli.py scan ~/Downloads -r

# With quarantine
python3 antivirus_cli.py scan ~/Downloads -r --quarantine

# Generate report
python3 antivirus_cli.py scan ~/Downloads -r --report downloads_scan.json
```

### Scenario 3: Analyzing Known Malware Sample

**⚠️ IMPORTANT: Only in isolated VM!**

```bash
# Extract all features
python3 heuristic_lab.py
# [7] Feature Extraction Analysis
# Enter: /path/to/malware_sample.exe
# Review detailed analysis
# Save features for signature creation
```

### Scenario 4: Creating Detection Rules from Sample

```python
# 1. Analyze the sample
from advanced_heuristics import AdvancedHeuristicEngine

engine = AdvancedHeuristicEngine()
features = engine.extract_all_features("malware_sample.exe")

# 2. Identify unique patterns
# Look at: strings, imports, opcodes

# 3. Create rule
with open("malware_sample.exe", "rb") as f:
    data = f.read()
    
# Find unique byte sequence
unique_pattern = b"\xde\xad\xbe\xef"  # Example

engine.add_custom_rule(
    name="Malware.Family.Variant",
    pattern=unique_pattern,
    weight=30,
    description="Unique identifier for this malware family",
    category="code_execution"
)

# 4. Test on samples
score, matches = engine.analyze_with_custom_rules("malware_sample.exe")
score2, matches2 = engine.analyze_with_custom_rules("clean_file.exe")

print(f"Malware: {score}, Clean: {score2}")
# Should be: High score for malware, low for clean
```

## Performance Testing

### Scan Speed Benchmark

```python
import time
from antivirus_engine import AntivirusEngine

av = AntivirusEngine()

# Test small files
start = time.time()
for i in range(100):
    av.scan_file("test_small.txt")
small_time = (time.time() - start) / 100

# Test large files
start = time.time()
av.scan_file("test_large_10mb.bin")
large_time = time.time() - start

print(f"Small files: {small_time*1000:.2f}ms avg")
print(f"Large file (10MB): {large_time:.2f}s")
```

**Target Performance:**
- Small files (<1KB): <10ms
- Medium files (1-10MB): <1s
- Large files (10-100MB): <10s

### Memory Usage Testing

```bash
# Monitor during scan
python3 -c "
from antivirus_engine import AntivirusEngine
import psutil
import os

process = psutil.Process(os.getpid())
print(f'Before: {process.memory_info().rss / 1024 / 1024:.2f} MB')

av = AntivirusEngine()
av.scan_directory('/path/to/large/directory', recursive=True)

print(f'After: {process.memory_info().rss / 1024 / 1024:.2f} MB')
"
```

## Advanced Testing Techniques

### 1. Adversarial Testing

**Create obfuscated malware to test detection:**

```python
# Test 1: Base64 obfuscation
import base64

malicious_code = b"import os; os.system('rm -rf /')"
obfuscated = base64.b64encode(malicious_code)

# Should still detect via base64 pattern + suspicious strings

# Test 2: String splitting
code = """
cmd = "rm " + "-rf" + " /"
os.system(cmd)
"""

# Test 3: XOR encoding
xor_key = 0x42
encoded = bytes([b ^ xor_key for b in malicious_code])
```

### 2. Polymorphic Testing

**Test detection of code that changes each time:**

```python
# Generate variants
import random

templates = [
    "import {module}; {module}.{func}('{arg}')",
    "from {module} import {func}; {func}('{arg}')",
    "__{module}__.__import__('{func}')({arg})",
]

for _ in range(10):
    template = random.choice(templates)
    code = template.format(
        module=random.choice(['os', 'subprocess']),
        func=random.choice(['system', 'run', 'popen']),
        arg='malicious_command'
    )
    
    # Test each variant
    # All should be detected despite different syntax
```

### 3. Evasion Testing

**Test if detector can be evaded:**

```python
# Test different encodings
encodings = ['utf-8', 'utf-16', 'utf-32', 'latin-1']

malicious_string = "password stealer"
for encoding in encodings:
    encoded = malicious_string.encode(encoding)
    # Test detection on each encoding
    
# Test case variations
variations = [
    b"PASSWORD",
    b"PaSsWoRd",
    b"p4ssw0rd",
    b"passw" + b"\x00" + b"ord",  # Null byte
]
```

## Continuous Testing Setup

### Automated Testing Pipeline

```bash
#!/bin/bash
# test_pipeline.sh

echo "=== Antivirus Testing Pipeline ==="

# 1. Run unit tests
echo "[1/5] Running unit tests..."
python3 test_suite.py || exit 1

# 2. Benchmark detection rates
echo "[2/5] Benchmarking detection..."
python3 advanced_heuristics.py > benchmark_results.txt

# 3. Performance test
echo "[3/5] Performance testing..."
time python3 antivirus_cli.py scan test_samples -r > /dev/null

# 4. Memory test
echo "[4/5] Memory profiling..."
/usr/bin/time -v python3 antivirus_cli.py scan test_samples -r 2>&1 | grep "Maximum resident"

# 5. Generate report
echo "[5/5] Generating report..."
python3 antivirus_cli.py scan test_samples -r --report test_report.json

echo "=== Pipeline Complete ==="
```

### Regression Testing

```python
# Keep baseline of known samples
baseline = {
    'clean/file1.txt': {'score': 0, 'infected': False},
    'clean/file2.py': {'score': 5, 'infected': False},
    'malicious/trojan.exe': {'score': 85, 'infected': True},
}

# Test against baseline
from antivirus_engine import AntivirusEngine

av = AntivirusEngine()
regressions = []

for filepath, expected in baseline.items():
    result = av.scan_file(filepath)
    
    if result.heuristic_score != expected['score']:
        regressions.append({
            'file': filepath,
            'expected_score': expected['score'],
            'actual_score': result.heuristic_score,
        })
    
    if result.is_infected != expected['infected']:
        regressions.append({
            'file': filepath,
            'expected_infected': expected['infected'],
            'actual_infected': result.is_infected,
        })

if regressions:
    print("⚠️  REGRESSIONS DETECTED:")
    for r in regressions:
        print(f"  {r}")
else:
    print("✓ All baseline tests passed")
```

## Debugging Detection Issues

### Issue: False Positive

```bash
# 1. Analyze why it was flagged
python3 heuristic_lab.py
# [1] Test Single File
# Review heuristic findings

# 2. Extract features
# [7] Feature Extraction Analysis

# 3. Identify problematic pattern
# Look for patterns with low specificity

# 4. Solutions:
# - Increase threshold
# - Reduce weight of that pattern
# - Add more context to pattern (combine with other indicators)
# - Whitelist the file/pattern
```

### Issue: False Negative

```bash
# 1. Analyze why it was missed
python3 heuristic_lab.py
# [1] Test Single File
# Note: Score too low

# 2. Identify missed patterns
# [7] Feature Extraction Analysis
# Look for malicious indicators not in current rules

# 3. Solutions:
# - Decrease threshold
# - Add new detection rule for missed pattern
# - Increase weight of relevant patterns
# - Add behavioral pattern matching
```

## Documentation

### Record Your Rules

```python
# Keep a rules database
rules_db = {
    'rule_001': {
        'name': 'Ransomware.CryptoLocker.Pattern',
        'pattern': bytes.fromhex('deadbeef'),
        'weight': 30,
        'added': '2024-01-15',
        'reason': 'Unique identifier in CryptoLocker samples',
        'tested_on': ['sample1.exe', 'sample2.exe'],
        'false_positives': 0,
    }
}
```

### Maintain Test Dataset

```
test_samples/
├── clean/
│   ├── benign_script.py
│   ├── system_binary_copy
│   └── clean_documents/
├── malicious/
│   ├── ransomware_samples/
│   ├── trojans/
│   ├── keyloggers/
│   └── backdoors/
└── edge_cases/
    ├── obfuscated_clean/
    ├── packed_legitimate/
    └── borderline/
```

## Next Steps

1. **Build your test dataset** - Collect clean and malicious samples
2. **Run baseline benchmark** - Establish current performance
3. **Tune for your use case** - Adjust for your threat model
4. **Add custom rules** - Detect specific threats you care about
5. **Automate testing** - Set up CI/CD pipeline
6. **Monitor in production** - Track false positive/negative rates

## Resources

- Test malware samples: https://www.malware-traffic-analysis.net/
- Clean file dataset: https://github.com/corkami/pocs
- YARA rules: https://github.com/Yara-Rules/rules
- PE samples: https://github.com/corkami/pics/tree/master/binary
