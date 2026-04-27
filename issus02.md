# Stored Injection RCE via SQL Text → Runtime.exec()

## Project Information
- **Project:** DTStack/Taier
- **Type:** Stored Injection RCE
- **Severity:** Critical (CVSS 9.8)
- **CWE:** CWE-94 (Code Injection), CWE-78 (OS Command Injection)

## Vulnerability Description

DTStack Taier (大数据开发平台) contains a stored injection vulnerability where user-supplied SQL text is stored in MySQL and later passed to `Runtime.exec()` without sanitization. An attacker can inject OS commands via the `sqlText` parameter, which flows from REST API input through database storage to command execution.

## Data Flow

```
REST API (sqlText) → MySQL Storage → Runtime.exec("sh -c <sqlText>")
```

### Write Path (REST → MySQL)

1. REST endpoint accepts `sqlText` parameter from user input
2. The SQL text is stored in MySQL via MyBatis mapper without sanitization
3. No validation is performed on the content of `sqlText` beyond type checks

### Read Path (MySQL → Runtime.exec)

1. Stored `sqlText` is read from database
2. The value is passed to `Runtime.exec()` with `"sh -c"` prefix
3. OS command injection occurs when attacker-controlled characters are present

## Attack Vectors

### Vector 1: Stored Injection
An attacker submits SQL text containing shell command injection (e.g., `; rm -rf /`) via the REST API. The malicious input is stored in MySQL and later executed when a job runs.

### Vector 2: Direct Execution
The `sqlText` parameter can contain shell metacharacters that are interpreted by `/bin/sh -c`.

## Authentication

The REST API endpoints require authentication. However, any user with task/job creation permissions can exploit this vulnerability.

## Evidence

The `sqlText` parameter flows from REST input to `Runtime.exec("sh -c ...")` without sanitization. No input validation, command allowlisting, or parameterized execution is performed between the write and read paths.

## Remediation

1. **Input Validation:** Validate SQL text against expected patterns; reject shell metacharacters (`;`, `|`, `&`, backticks, `$()`)
2. **Parameterized Execution:** Use `ProcessBuilder` with explicit argument lists instead of `Runtime.exec("sh -c " + input)`
3. **Command Allowlisting:** Restrict executable commands to a predefined allowlist
4. **Least Privilege:** Run execution processes with minimal OS privileges

## References

- CWE-94: Code Injection
- CWE-78: OS Command Injection
