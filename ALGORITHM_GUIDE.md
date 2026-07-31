# Heuristic Algorithm Development Guide

## Understanding the Detection Engine Architecture

### Core Detection Flow

```
File Input
    │
    ├─→ Hash Check (O(1) lookup)
    │       │
    │       ├─→ Match? → THREAT [100% confidence]
    │       └─→ No match → Continue
    │
    ├─→ Signature Scan (Pattern matching)
    │       │
    │       ├─→ Match? → THREAT [High confidence]
    │       └─→ No match → Continue
    │
    └─→ Heuristic Analysis (Weighted scoring)
            │
            ├─→ Pattern Detection (regex, byte sequences)
            ├─→ Entropy Analysis (encryption/obfuscation)
            ├─→ Behavioral Indicators (API calls, imports)
            ├─→ Statistical Analysis (anomaly detection)
            │
            └─→ Score ≥ Threshold? → SUSPICIOUS
                                   └─→ Score < Threshold → CLEAN
```

## Scoring Algorithm

### Current Implementation

```python
total_score = Σ (pattern_weight × min(match_count, 3))
              + entropy_score
              + api_call_score
              + structural_anomaly_score
```

### Weight Selection Strategy

1. **Critical Indicators (15-25 points)**
   - Direct code execution: `eval()`, `exec()`
   - System command execution: `os.system()`, `subprocess.run()`
   - Memory manipulation: `VirtualAlloc`, `WriteProcessMemory`
   - File encryption patterns
   
2. **High Indicators (10-15 points)**
   - Network operations: `socket.socket()`, HTTP requests
   - Dynamic imports: `__import__()`, `importlib`
   - Registry modifications
   - Process manipulation
   
3. **Medium Indicators (5-10 points)**
   - Base64 encoding/decoding
   - URL patterns
   - Obfuscation techniques
   - Suspicious strings
   
4. **Low Indicators (1-5 points)**
   - Common API usage
   - File operations
   - Generic patterns

### Threshold Selection

**Trade-offs:**
```
Lower Threshold → Higher Detection Rate (TP↑) + More False Positives (FP↑)
Higher Threshold → Lower False Positives (FP↓) + More Misses (FN↑)
```

**Optimal Range:** 40-60 for general purpose
- **20-40**: Aggressive (security-critical environments)
- **40-60**: Balanced (recommended)
- **60-80**: Conservative (minimize false positives)

## Advanced Detection Algorithms

### 1. Entropy-Based Detection

**Purpose:** Detect encrypted, packed, or obfuscated code

```python
def calculate_entropy(data: bytes, block_size: int = 256) -> float:
    """
    Shannon Entropy: H(X) = -Σ p(x) log₂ p(x)
    
    High entropy (>7.5) → Likely encrypted/packed
    Low entropy (<3.0) → Likely plain text
    Medium entropy (4-7) → Normal binary
    """
    import math
    
    if not data:
        return 0
    
    # Calculate byte frequency
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1
    
    # Calculate probabilities and entropy
    entropy = 0
    length = len(data)
    
    for count in freq:
        if count == 0:
            continue
        p_x = count / length
        entropy -= p_x * math.log2(p_x)
    
    return entropy
```

**Enhanced Block Analysis:**
```python
def analyze_entropy_variance(data: bytes, block_size: int = 256) -> dict:
    """
    Analyze entropy across blocks to detect:
    - Encrypted sections (high, consistent entropy)
    - Packed malware (entropy spike)
    - Polymorphic code (varying entropy)
    """
    blocks = [data[i:i+block_size] for i in range(0, len(data), block_size)]
    entropies = [calculate_entropy(block) for block in blocks]
    
    mean = sum(entropies) / len(entropies)
    variance = sum((e - mean) ** 2 for e in entropies) / len(entropies)
    
    return {
        'mean_entropy': mean,
        'variance': variance,
        'max_entropy': max(entropies),
        'min_entropy': min(entropies),
        'high_entropy_blocks': sum(1 for e in entropies if e > 7.5),
        'is_encrypted': mean > 7.5 and variance < 0.5,  # Consistent high
        'is_packed': max(entropies) > 7.8 and variance > 1.0,  # Spiky
    }
```

### 2. N-gram Analysis

**Purpose:** Detect shellcode and malicious patterns

```python
def extract_byte_ngrams(data: bytes, n: int = 3) -> dict:
    """
    Extract byte n-grams for anomaly detection
    Common in shellcode: NOP sleds, repeating patterns
    """
    ngrams = {}
    
    for i in range(len(data) - n + 1):
        ngram = data[i:i+n]
        ngrams[ngram] = ngrams.get(ngram, 0) + 1
    
    # Analyze
    total_ngrams = len(data) - n + 1
    unique_ngrams = len(ngrams)
    diversity = unique_ngrams / total_ngrams if total_ngrams > 0 else 0
    
    # Find most common (potential shellcode patterns)
    most_common = sorted(ngrams.items(), key=lambda x: x[1], reverse=True)[:10]
    
    return {
        'diversity': diversity,  # Low diversity = repetitive (shellcode)
        'most_common': most_common,
        'nop_sled_detected': b'\x90' * n in ngrams and ngrams[b'\x90' * n] > 20
    }
```

### 3. Import Address Table (IAT) Analysis

**Purpose:** Detect suspicious API usage in PE files

```python
def analyze_pe_imports(pe_data: bytes) -> dict:
    """
    Score based on imported functions
    
    Scoring matrix:
    - Memory manipulation: 20 pts each
    - Process injection: 18 pts each
    - Network: 12 pts each
    - File operations: 5 pts each
    - Registry: 10 pts each
    """
    
    import_scoring = {
        # Memory manipulation (code injection indicators)
        b'VirtualAlloc': 20,
        b'VirtualProtect': 20,
        b'VirtualAllocEx': 25,
        b'WriteProcessMemory': 25,
        b'ReadProcessMemory': 15,
        
        # Process manipulation
        b'CreateRemoteThread': 25,
        b'CreateRemoteThreadEx': 25,
        b'OpenProcess': 15,
        b'TerminateProcess': 15,
        
        # Dynamic loading (obfuscation)
        b'LoadLibrary': 12,
        b'LoadLibraryEx': 12,
        b'GetProcAddress': 15,
        
        # Network (C2 communication)
        b'InternetOpen': 12,
        b'InternetConnect': 12,
        b'InternetReadFile': 12,
        b'HttpSendRequest': 12,
        b'WSAStartup': 10,
        b'socket': 10,
        b'connect': 10,
        b'send': 8,
        b'recv': 8,
        
        # File operations
        b'CreateFile': 5,
        b'WriteFile': 8,
        b'DeleteFile': 10,
        b'MoveFile': 8,
        
        # Registry (persistence)
        b'RegOpenKey': 10,
        b'RegSetValue': 15,
        b'RegCreateKey': 15,
        b'RegDeleteKey': 12,
        
        # Crypto (ransomware indicator)
        b'CryptEncrypt': 18,
        b'CryptDecrypt': 15,
        b'CryptGenKey': 15,
    }
    
    score = 0
    found_imports = []
    
    for api, weight in import_scoring.items():
        if api in pe_data:
            score += weight
            found_imports.append(api.decode('utf-8', errors='ignore'))
    
    return {
        'score': score,
        'imports': found_imports,
        'import_count': len(found_imports),
        'risk_level': 'critical' if score > 100 else 'high' if score > 50 else 'medium'
    }
```

### 4. Behavioral Pattern Matching

**Purpose:** Detect malware behavior patterns

```python
class BehaviorPattern:
    """Define behavioral patterns for detection"""
    
    RANSOMWARE_PATTERNS = [
        # File encryption + network + persistence
        {
            'name': 'Ransomware Behavior',
            'patterns': [
                b'CryptEncrypt',
                b'\.encrypt',
                b'bitcoin',
                b'ransom',
            ],
            'min_matches': 2,
            'weight': 50
        }
    ]
    
    BACKDOOR_PATTERNS = [
        # Reverse shell + command execution
        {
            'name': 'Backdoor Behavior',
            'patterns': [
                b'/bin/bash',
                b'cmd.exe',
                b'/bin/sh',
                b'socket',
                b'CreateProcess',
            ],
            'min_matches': 2,
            'weight': 40
        }
    ]
    
    KEYLOGGER_PATTERNS = [
        # Input capture + network exfiltration
        {
            'name': 'Keylogger Behavior',
            'patterns': [
                b'GetAsyncKeyState',
                b'keylog',
                b'keyboard',
                b'SetWindowsHook',
            ],
            'min_matches': 2,
            'weight': 45
        }
    ]
    
    @staticmethod
    def detect_behavioral_pattern(data: bytes, pattern_set: list) -> tuple:
        """
        Detect if file exhibits behavioral pattern
        Returns: (detected: bool, score: int, matched_patterns: list)
        """
        for pattern in pattern_set:
            matches = []
            
            for p in pattern['patterns']:
                if p in data:
                    matches.append(p.decode('utf-8', errors='ignore'))
            
            if len(matches) >= pattern['min_matches']:
                return True, pattern['weight'], matches
        
        return False, 0, []
```

### 5. Machine Learning Feature Engineering

**Feature Vector for ML Models:**

```python
def extract_ml_features(filepath: str) -> list:
    """
    Extract numerical features for ML classification
    Returns: 50+ dimensional feature vector
    """
    
    with open(filepath, 'rb') as f:
        data = f.read()
    
    features = []
    
    # 1. File metadata (5 features)
    features.extend([
        len(data),                    # File size
        len(set(data)),               # Unique bytes
        data.count(b'\x00'),          # Null bytes
        data.count(b'\xff'),          # 0xFF bytes
        1 if data.startswith(b'MZ') else 0,  # Is PE?
    ])
    
    # 2. Entropy features (5 features)
    entropy_analysis = analyze_entropy_variance(data)
    features.extend([
        entropy_analysis['mean_entropy'],
        entropy_analysis['variance'],
        entropy_analysis['max_entropy'],
        entropy_analysis['high_entropy_blocks'],
        1 if entropy_analysis['is_encrypted'] else 0,
    ])
    
    # 3. String features (8 features)
    import re
    strings = re.findall(b'[\x20-\x7e]{4,}', data)
    features.extend([
        len(strings),                 # String count
        sum(len(s) for s in strings) / len(strings) if strings else 0,  # Avg length
        len([s for s in strings if b'http' in s]),  # URL count
        len([s for s in strings if re.match(rb'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', s)]),  # IP count
        sum(1 for s in strings if b'password' in s.lower()),
        sum(1 for s in strings if b'admin' in s.lower()),
        sum(1 for s in strings if b'encrypt' in s.lower()),
        sum(1 for s in strings if b'key' in s.lower()),
    ])
    
    # 4. Opcode features (10 features)
    opcodes = {
        b'\x90': data.count(b'\x90'),  # NOP
        b'\xe8': data.count(b'\xe8'),  # CALL
        b'\xeb': data.count(b'\xeb'),  # JMP short
        b'\xcd': data.count(b'\xcd'),  # INT
        b'\x89': data.count(b'\x89'),  # MOV
        b'\x31': data.count(b'\x31'),  # XOR
        b'\x50': data.count(b'\x50'),  # PUSH
        b'\x58': data.count(b'\x58'),  # POP
        b'\xc3': data.count(b'\xc3'),  # RET
        b'\xff': data.count(b'\xff'),  # Various
    }
    features.extend(opcodes.values())
    
    # 5. Import features (if PE) (10 features)
    if data.startswith(b'MZ'):
        import_analysis = analyze_pe_imports(data)
        features.extend([
            import_analysis['score'],
            import_analysis['import_count'],
            1 if 'VirtualAlloc' in import_analysis['imports'] else 0,
            1 if 'CreateRemoteThread' in import_analysis['imports'] else 0,
            1 if 'WriteProcessMemory' in import_analysis['imports'] else 0,
            1 if 'LoadLibrary' in import_analysis['imports'] else 0,
            1 if 'InternetOpen' in import_analysis['imports'] else 0,
            1 if 'RegSetValue' in import_analysis['imports'] else 0,
            1 if 'CryptEncrypt' in import_analysis['imports'] else 0,
            1 if import_analysis['risk_level'] == 'critical' else 0,
        ])
    else:
        features.extend([0] * 10)
    
    # 6. Behavioral patterns (5 features)
    ransomware_detected, ransomware_score, _ = BehaviorPattern.detect_behavioral_pattern(
        data, BehaviorPattern.RANSOMWARE_PATTERNS
    )
    backdoor_detected, backdoor_score, _ = BehaviorPattern.detect_behavioral_pattern(
        data, BehaviorPattern.BACKDOOR_PATTERNS
    )
    keylogger_detected, keylogger_score, _ = BehaviorPattern.detect_behavioral_pattern(
        data, BehaviorPattern.KEYLOGGER_PATTERNS
    )
    
    features.extend([
        1 if ransomware_detected else 0,
        ransomware_score,
        1 if backdoor_detected else 0,
        backdoor_score,
        keylogger_score,
    ])
    
    return features  # Total: 53 features
```

## Testing and Validation

### 1. Cross-Validation Strategy

```python
def k_fold_validation(samples: list, labels: list, k: int = 5):
    """
    Perform k-fold cross-validation
    Ensures algorithm generalizes well
    """
    from random import shuffle
    
    # Shuffle data
    combined = list(zip(samples, labels))
    shuffle(combined)
    samples, labels = zip(*combined)
    
    fold_size = len(samples) // k
    results = []
    
    for i in range(k):
        # Split data
        test_start = i * fold_size
        test_end = (i + 1) * fold_size
        
        test_set = samples[test_start:test_end]
        test_labels = labels[test_start:test_end]
        
        train_set = samples[:test_start] + samples[test_end:]
        train_labels = labels[:test_start] + labels[test_end:]
        
        # Train and test
        # ... model training code ...
        
        # Evaluate
        accuracy = evaluate(test_set, test_labels)
        results.append(accuracy)
    
    return {
        'mean_accuracy': sum(results) / len(results),
        'std_dev': std_dev(results),
        'fold_results': results
    }
```

### 2. Performance Metrics

```python
def calculate_metrics(tp: int, tn: int, fp: int, fn: int) -> dict:
    """
    Calculate comprehensive performance metrics
    
    tp: True Positives (correctly identified malware)
    tn: True Negatives (correctly identified clean)
    fp: False Positives (clean marked as malware)
    fn: False Negatives (malware marked as clean)
    """
    
    # Basic metrics
    accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0  # aka True Positive Rate
    specificity = tn / (tn + fp) if (tn + fp) > 0 else 0
    
    # Combined metrics
    f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    f2_score = 5 * (precision * recall) / (4 * precision + recall) if (4 * precision + recall) > 0 else 0  # Emphasizes recall
    
    # Error rates
    false_positive_rate = fp / (fp + tn) if (fp + tn) > 0 else 0
    false_negative_rate = fn / (fn + tp) if (fn + tp) > 0 else 0
    
    return {
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'specificity': specificity,
        'f1_score': f1_score,
        'f2_score': f2_score,
        'fpr': false_positive_rate,
        'fnr': false_negative_rate,
    }
```

## Optimization Techniques

### 1. Weight Optimization via Grid Search

```python
def optimize_weights(training_data: list, labels: list):
    """
    Find optimal pattern weights using grid search
    """
    weight_ranges = {
        'eval_exec': range(10, 25, 5),
        'subprocess': range(8, 20, 4),
        'network': range(5, 15, 5),
        'entropy': range(10, 25, 5),
    }
    
    best_score = 0
    best_config = {}
    
    # Grid search
    for eval_w in weight_ranges['eval_exec']:
        for sub_w in weight_ranges['subprocess']:
            for net_w in weight_ranges['network']:
                for ent_w in weight_ranges['entropy']:
                    
                    config = {
                        'eval_exec': eval_w,
                        'subprocess': sub_w,
                        'network': net_w,
                        'entropy': ent_w,
                    }
                    
                    # Test configuration
                    f1 = test_configuration(config, training_data, labels)
                    
                    if f1 > best_score:
                        best_score = f1
                        best_config = config
    
    return best_config, best_score
```

### 2. Adaptive Thresholding

```python
def adaptive_threshold(file_type: str, context: str) -> int:
    """
    Adjust threshold based on file type and context
    
    Examples:
    - Executable from email: Lower threshold (more aggressive)
    - Script in /usr/bin: Higher threshold (avoid false positives)
    - Unknown file type: Default threshold
    """
    
    thresholds = {
        ('executable', 'email_attachment'): 30,  # Aggressive
        ('executable', 'download'): 40,
        ('executable', 'system'): 70,            # Conservative
        ('script', 'email_attachment'): 35,
        ('script', 'user_directory'): 45,
        ('script', 'system'): 65,
        ('document', 'any'): 50,
        ('default', 'default'): 50,
    }
    
    return thresholds.get((file_type, context), 50)
```

## Next Steps for Advanced Development

1. **Implement ML classifier** - Random Forest or XGBoost on feature vectors
2. **Add YARA integration** - Use YARA rules for complex pattern matching
3. **Implement sandboxing** - Execute suspicious files in isolated environment
4. **Add threat intelligence** - Integrate with VirusTotal, AbuseIPDB APIs
5. **Develop polymorphic detection** - Handle code that changes each execution
6. **Add packer detection** - Identify and unpack common packers (UPX, ASPack)

## Resources

- **YARA Documentation**: https://yara.readthedocs.io/
- **PE Format**: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
- **Malware Analysis**: https://www.malware-traffic-analysis.net/
- **MITRE ATT&CK**: https://attack.mitre.org/
