# Stored Injection RCE via Resource Group Properties → Spark/Flink Shell Execution

## Project Information
- **Project:** apache/amoro
- **Type:** Stored Injection RCE via Shell Command Injection
- **Severity:** Critical (CVSS 9.8)
- **CWE:** CWE-78 (OS Command Injection)

## Vulnerability Description

Apache Amoro contains a stored injection RCE where resource group properties are stored in the database and later injected into shell commands executed via `ProcessBuilder` with `/bin/sh -c`. Multiple injection vectors exist through `export.*` properties, `spark-conf.*` properties, and other configuration values.

## Data Flow

```
PUT /api/ams/v1/optimize/resourceGroups → DB → POST .../optimizers → ProcessBuilder("/bin/sh", "-c", cmd)
```

### Write Path
1. `OptimizerGroupController.updateResourceGroup()` (line 253-262): Accepts arbitrary `properties` map
2. `PropertiesUtil.sanitizeProperties()` (line 81-100): Only trims keys/values — no shell character filtering
3. `DefaultOptimizerManager.updateResourceGroup()` → `ResourceMapper` → MySQL `resource_group.properties` (JSON)

### Read/Exec Path
4. `POST /api/ams/v1/optimize/optimizerGroups/{group}/optimizers` (`scaleOutOptimizer`): Reads stored properties
5. `AbstractOptimizerContainer.exportSystemProperties()` (line 149-161):
   ```java
   cmds.add(String.format("export %s=%s", exportPropertyName, exportValue));
   ```
   Any `export.*` key injected into shell export command — attacker can inject `;malicious_cmd #`
6. `SparkOptimizerContainer.buildOptimizerStartupArgsString()` (line 141-186):
   ```java
   "--conf " + entry.getKey() + "=" + entry.getValue()
   ```
7. Final execution: `String[] cmd = {"/bin/sh", "-c", startUpCmd}` → `ProcessBuilder(cmd).start()`

## Key Evidence

**Export injection** (`AbstractOptimizerContainer.java:149-161`):
```java
cmds.add(String.format("export %s=%s", exportPropertyName, exportValue));
```

**Shell execution** (`SparkOptimizerContainer.java:108-116`):
```java
String startUpCmd = String.format("%s && %s", exportCmd, startUpArgs);
String[] cmd = {"/bin/sh", "-c", startUpCmd};
Process exec = new ProcessBuilder(cmd).redirectErrorStream(true).start();
```

**Insufficient sanitization** (`PropertiesUtil.java:81-100`):
```java
String value = entry.getValue() == null ? null : entry.getValue().trim();  // only trims
```

## Authentication

**Required but weak**: Authorization defaults to disabled (`http-server.authorization.enabled=false`). Default admin credentials: `admin:admin`. Any authenticated user can create/trigger optimizers.

## Remediation

1. **Shell escaping**: Sanitize all property values before shell command injection
2. **Property key whitelist**: Restrict allowed property keys to known safe names
3. **ProcessBuilder argument lists**: Avoid `sh -c` string execution
4. **Enable authorization**: Default to authorization enabled with strict RBAC
5. **Change default credentials**: Remove default admin:admin

## References

- CWE-78: OS Command Injection
