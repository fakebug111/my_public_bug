# Stored Injection RCE via MCP Tool Command Execution

## Project Information
- **Project:** ageerle/ruoyi-ai
- **Type:** Stored Injection RCE via ProcessBuilder
- **Severity:** Critical (CVSS 9.8)
- **CWE:** CWE-78 (OS Command Injection), CWE-94 (Code Injection)

## Vulnerability Description

ageerle ruoyi-ai contains a stored injection RCE where MCP tool configuration stored in the database includes `command` and `args` fields that are executed via `ProcessBuilder` without any command whitelist or argument sanitization.

## Data Flow

```
POST /mcp/tool → McpToolServiceImpl.insert() → mcp_tool_info DB → LangChain4jMcpToolProviderService.createStdioClient() → ProcessBuilder(command, args)
```

### Write Path
1. `McpToolController` (`POST /mcp/tool`): accepts MCP tool configuration
2. `McpToolServiceImpl.insert()`: stores to `mcp_tool_info` table
3. `configJson` field contains `command` and `args` for LOCAL type tools
4. `validEntityBeforeSave` is an empty TODO stub — no validation

### Read/Exec Path
5. `LangChain4jMcpToolProviderService.createStdioClient()`: reads stored config
6. `ProcessBuilder(command, args)` executes attacker-provided command
7. `isCommandAvailable()` also runs attacker-provided command via ProcessBuilder

## Key Evidence

**No validation** (`McpToolBo.configJson`): No validation annotations. `validEntityBeforeSave` is empty TODO stub.

**Direct command execution**: `ProcessBuilder` with attacker-controlled `command` and `args` — no allowlist, no sanitization.

**Secondary validation also vulnerable**: `isCommandAvailable()` runs attacker command to "check availability."

## Authentication

Authentication required (admin-level for MCP tool management). However, write (tool creation) and trigger (tool use) can be performed by different users.

## Remediation

1. **Command allowlisting**: Restrict allowed commands to a predefined safe list
2. **Input validation**: Validate `configJson` schema strictly
3. **Implement `validEntityBeforeSave`**: Add actual validation logic
4. **Sandboxing**: Execute MCP tools in isolated containers
5. **Least privilege**: Run ProcessBuilder with minimal OS privileges

## References

- CWE-78: OS Command Injection
- CWE-94: Code Injection
