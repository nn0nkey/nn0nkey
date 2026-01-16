# CrewAI Vulnerability Reports

This repository contains security vulnerability reports for the [CrewAI](https://github.com/crewAIInc/crewAI) framework and its associated tools (crewai-tools).

> **Disclaimer**: These reports are provided for security research and educational purposes only. All vulnerabilities were discovered during authorized security audits and have been responsibly disclosed to the vendor.

## 📋 Table of Contents

- [Vulnerabilities](#vulnerabilities)
- [Summary](#summary)
- [Affected Versions](#affected-versions)
- [Installation](#installation)
- [Proof of Concepts](#proof-of-concepts)
- [Timeline](#timeline)
- [References](#references)

## 🔍 Vulnerabilities

| # | Vulnerability | CVSS | Severity | Status |
|---|---------------|------|----------|--------|
| 1 | [CodeInterpreterTool Command Injection](./CrewAI_CodeInterpreterTool_Command_Injection.md) | 9.8 | Critical | ✅ Verified |
| 2 | [SandboxPython Sandbox Escape](./CrewAI_SandboxPython_Sandbox_Escape.md) | 9.8 | Critical | ✅ Verified |
| 3 | [FileWriterTool Arbitrary File Write](./CrewAI_FileWriterTool_Arbitrary_File_Write.md) | 8.1 | High | ✅ Verified |
| 4 | [PickleHandler Path Traversal + Deserialization](./CrewAI_PickleHandler_Path_Traversal_Deserialization.md) | 8.2 | High | ✅ Verified |
| 5 | [FileReadTool Arbitrary File Read](./CrewAI_FileReadTool_Arbitrary_File_Read.md) | 7.5 | High | ✅ Verified |
| 6 | [DirectoryReadTool Path Traversal](./CrewAI_DirectoryReadTool_Path_Traversal.md) | 6.5 | Medium | ✅ Verified |

## 📊 Summary

### Critical Vulnerabilities (2)

#### 1. CodeInterpreterTool Command Injection (CVSS 9.8)
- **Component**: `crewai-tools`
- **File**: `code_interpreter_tool.py`
- **Issue**: Command injection via `os.system(f"pip install {library}")` when `unsafe_mode=True`
- **Impact**: Arbitrary system command execution
- **POC**: [exploit_vuln1_cmd_injection.py](../exploit_vuln1_cmd_injection.py)

#### 2. SandboxPython Sandbox Escape (CVSS 9.8)
- **Component**: `crewai-tools`
- **File**: `code_interpreter_tool.py`
- **Issue**: Sandbox bypass through `catch_warnings.__init__.__globals__['__builtins__']`
- **Impact**: Arbitrary code execution even in safe mode
- **POC**: [exploit_sandbox_rce.py](../exploit_sandbox_rce.py)

### High Severity Vulnerabilities (3)

#### 3. FileWriterTool Arbitrary File Write (CVSS 8.1)
- **Component**: `crewai-tools`
- **File**: `file_writer_tool.py`
- **Issue**: Path traversal via `os.path.join(directory, filename)` without validation
- **Impact**: Write files to arbitrary system locations
- **POC**: [exploit_vuln2_3_file_read_write.py](../exploit_vuln2_3_file_read_write.py)

#### 4. PickleHandler Path Traversal + Deserialization (CVSS 8.2)
- **Component**: `crewai`
- **File**: `file_handler.py`
- **Issue**: Path traversal + unsafe pickle deserialization
- **Impact**: RCE when combined with FileWriterTool
- **POC**: [exploit_pickle_rce.py](../exploit_pickle_rce.py)

#### 5. FileReadTool Arbitrary File Read (CVSS 7.5)
- **Component**: `crewai-tools`
- **File**: `file_read_tool.py`
- **Issue**: Direct file path usage without validation
- **Impact**: Read arbitrary files from filesystem
- **POC**: [exploit_vuln2_3_file_read_write.py](../exploit_vuln2_3_file_read_write.py)

### Medium Severity Vulnerabilities (1)

#### 6. DirectoryReadTool Path Traversal (CVSS 6.5)
- **Component**: `crewai-tools`
- **File**: `directory_read_tool.py`
- **Issue**: Path traversal via `os.walk(directory)` without validation
- **Impact**: List arbitrary directories
- **POC**: [exploit_directory_read_traversal.py](../exploit_directory_read_traversal.py)

## 🎯 Attack Chain

The vulnerabilities can be combined for complete system compromise:

```
DirectoryReadTool (Information Disclosure)
        ↓
Discover sensitive file locations
        ↓
FileReadTool (Read Credentials/Configs)
        ↓
FileWriterTool (Write Malicious Pickle)
        ↓
PickleHandler (Load & Deserialize)
        ↓
RCE!
```

## 📦 Affected Versions

- **Product**: CrewAI
- **Affected Versions**: <= 1.0.0a2 (alpha release)
- **Fixed Versions**: Pending release

## 🚀 Installation

```bash
# Clone this repository
git clone https://github.com/nn0nkey/CVE.git
cd CVE
```

## 💥 Proof of Concepts

Each vulnerability report includes a working proof-of-concept that demonstrates:

1. **Reproduction steps** - Step-by-step exploitation
2. **Verification** - Evidence of successful exploitation
3. **Impact assessment** - Real-world consequences

**All PoCs have been tested in a real environment.**

## 📅 Timeline

| Date | Event |
|------|-------|
| 2025-01-16 | Vulnerabilities discovered during security audit |
| 2025-01-16 | All vulnerabilities verified with working PoCs |
| 2025-01-16 | Reports published to GitHub |
| TBD | CVE assignment pending |
| TBD | Vendor fix pending |

## 📚 References

### CWE References
- [CWE-22: Path Traversal](https://cwe.mitre.org/data/definitions/22.html)
- [CWE-78: OS Command Injection](https://cwe.mitre.org/data/definitions/78.html)
- [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
- [CWE-265: Privilege, Access Control, and Authorization](https://cwe.mitre.org/data/definitions/265.html)

### OWASP References
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [OWASP Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
- [OWASP Deserialization](https://owasp.org/www-community/vulnerabilities/Deserialization)

### Project Links
- [CrewAI GitHub](https://github.com/crewAIInc/crewAI)
- [CrewAI Documentation](https://docs.crewai.com)

## 🔐 Responsible Disclosure

These vulnerabilities were discovered during authorized security research:

1. All testing was conducted in controlled, isolated environments
2. No production systems were affected during testing
3. Findings have been reported to the vendor
4. PoCs are provided for educational and defensive purposes only

## ⚠️ Legal Notice

The information in this repository is provided for security research and educational purposes only. The authors:

- **DO NOT** authorize use of this information for any illegal activities
- **DO NOT** take responsibility for any misuse of the information provided
- **RECOMMEND** following responsible disclosure practices

Users are encouraged to:
- Use these PoCs only in authorized testing environments
- Report vulnerabilities to vendors through proper channels
- Follow all applicable laws and regulations

## 📧 Contact

For questions or inquiries about these vulnerability reports:
- Submit an issue on this repository
- Contact through responsible disclosure channels

---

**Repository Last Updated**: 2025-01-16
**Total Vulnerabilities**: 6 (2 Critical, 3 High, 1 Medium)
