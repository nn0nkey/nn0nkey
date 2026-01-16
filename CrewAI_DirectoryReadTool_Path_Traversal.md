# CVE Application: CrewAI DirectoryReadTool Path Traversal Vulnerability

## Vulnerability Summary

**Product**: CrewAI (crewai-tools)
**Affected Version**: <= 1.0.0a2
**Vulnerability Type**: Path Traversal (CWE-22)
**CVSS v3.1 Score**: 6.5 (Medium)
**CVSS Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N

## Description

The DirectoryReadTool in crewai-tools allows an attacker to list the contents of arbitrary directories on the host system through path traversal. The `_run()` method directly uses user-supplied `directory` parameter in an `os.walk()` call without any validation or sanitization.

## Affected Component

**File**: `crewai-tools/src/crewai_tools/tools/directory_read_tool/directory_read_tool.py`

**Vulnerable Code** (lines 34-47):
```python
def _run(
    self,
    **kwargs: Any,
) -> Any:
    directory = kwargs.get("directory", self.directory)
    if directory[-1] == "/":
        directory = directory[:-1]
    files_list = [
        f"{directory}/{(os.path.join(root, filename).replace(directory, '').lstrip(os.path.sep))}"
        for root, dirs, files in os.walk(directory)  # ← No path validation
        for filename in files
    ]
    files = "\n- ".join(files_list)
    return f"File paths: \n-{files}"
```

## Proof of Concept

```python
#!/usr/bin/env python3
import sys
sys.path.insert(0, '/path/to/crewai-tools/src')

from crewai_tools.tools.directory_read_tool.directory_read_tool import DirectoryReadTool

tool = DirectoryReadTool()

# List system directories
result = tool.run(directory='/etc')
print(result)  # Returns all files in /etc

result = tool.run(directory='/tmp')
print(result)  # Returns all files in /tmp

# List user home directory
import os
result = tool.run(directory=os.path.expanduser('~'))
print(result)  # Returns all files in user home
```

**Expected Behavior**: The tool should restrict directory access to a predefined safe directory.
**Actual Behavior**: The tool lists files from any directory specified by the attacker.

## Impact

An attacker can:
1. **Discover sensitive file locations** - Enumerate the filesystem to find configuration files, credentials, or other sensitive data
2. **Information disclosure** - Learn about the system structure, installed software, and user directories
3. **Facilitate further attacks** - Use the discovered file paths in combination with other vulnerabilities (e.g., FileReadTool)

## CVSS v3.1 Score Breakdown

**Base Score**: 6.5 (Medium)

| Metric | Value | Description |
|--------|-------|-------------|
| Attack Vector (AV) | Network | The vulnerability is exploitable over the network |
| Attack Complexity (AC) | Low | No special conditions required |
| Privileges Required (PR) | None | No authentication required |
| User Interaction (UI) | None | No user interaction required |
| Scope (S) | Unchanged | Vulnerability does not impact resources beyond the vulnerable component |
| Confidentiality (C) | High | Full read access to all file listings on the system |
| Integrity (I) | None | No impact on data integrity |
| Availability (A) | None | No impact on system availability |

## Attack Scenario

1. An attacker with access to a CrewAI agent that has the DirectoryReadTool enabled
2. Attacker invokes the tool with arbitrary directory paths (e.g., `/etc`, `/root`, `/home/user`)
3. Tool recursively lists all files in the specified directories
4. Attacker discovers sensitive file locations and uses other tools (FileReadTool) to read their contents
5. Combined with FileWriterTool's arbitrary file write vulnerability, this enables full file system compromise

## Remediation

### Recommended Fix

```python
import os
from pathlib import Path
from typing import Any

class DirectoryReadTool(BaseTool):
    directory: str | None = None
    allowed_base_dirs: list[str] = Field(default_factory=lambda: [os.getcwd()])

    def __init__(self, directory: str | None = None, **kwargs):
        super().__init__(**kwargs)
        if directory is not None:
            # Validate directory is within allowed paths
            validated_dir = self._validate_directory(directory)
            self.directory = validated_dir

    def _validate_directory(self, directory: str) -> str:
        """Validate that directory is within allowed base directories."""
        dir_path = Path(directory).resolve()

        # Check against allowed directories
        for allowed_dir in self.allowed_base_dirs:
            allowed_path = Path(allowed_dir).resolve()
            try:
                dir_path.relative_to(allowed_path)
                return str(dir_path)
            except ValueError:
                continue

        raise ValueError(
            f"Access denied: directory '{directory}' is outside allowed paths"
        )

    def _run(self, **kwargs: Any) -> Any:
        directory = kwargs.get("directory", self.directory)

        # Always validate directory parameter
        validated_dir = self._validate_directory(directory)

        # ... rest of implementation using validated_dir
```

### Alternative Fix

Disable the tool entirely or require explicit whitelisting of allowed directories at configuration time.

## Timeline

- **2025-01-16**: Vulnerability discovered during security audit
- **2025-01-16**: Vulnerability confirmed with proof-of-concept
- **2025-01-16**: Vendor notification pending

## References

- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html)
- [CWE-23: Relative Path Traversal](https://cwe.mitre.org/data/definitions/23.html)
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [CrewAI GitHub Repository](https://github.com/crewAIInc/crewAI)

## Credit

Discovered by: Security Researcher
Contact: [Responsible Disclosure]

## Disclaimer

This vulnerability report is provided for security research and educational purposes only. All testing was conducted in an authorized environment. Please do not use this information for unauthorized testing or malicious attacks.

---

**Report Generated**: 2025-01-16
**Status**: Pending CVE Assignment
