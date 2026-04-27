# Stored Injection RCE via ZooKeeper Cluster Configuration → Runtime.exec()

## Project Information
- **Project:** alibaba/otter
- **Type:** Stored Injection RCE (Command Injection via ZK Cluster Config)
- **Severity:** Critical (CVSS 9.1)
- **CWE:** CWE-78 (OS Command Injection), CWE-94 (Code Injection)

## Vulnerability Description

alibaba Otter (数据同步平台) contains a stored injection RCE where the ZooKeeper cluster address field (`serverList`) is stored in MySQL and later injected into shell command templates (`echo stat | nc <ip> <port>`) that are executed via `Runtime.exec()` with `/bin/bash -c`. The vulnerability exists in the latest code (commit 7544d05, 2024-05-25).

## Data Flow

```
AutoKeeperClusterAction.doAdd() → MySQL → AutoKeeperCollector → String.format("echo stat | nc %s %s") → Runtime.exec("/bin/bash -c <cmd>")
```

### Write Path
1. `AutoKeeperClusterAction.java:44-61` (`doAdd`): Admin submits ZooKeeper cluster form with `zookeeperClusters` parameter
2. Value split by `;` and stored as `AutoKeeperCluster.serverList`
3. `AutoKeeperClusterServiceImpl.createAutoKeeperCluster()` → `IbatisAutoKeeperClusterDAO` → MySQL `AUTOKEEPER_CLUSTER.SERVER_LIST`

### Read Path
4. `AutoKeeperCollector.startCollect()` (line 311): Scheduled task reads all clusters from DB every 300 seconds
5. For each cluster address, `splitAddress()` (line 269) splits on `:` — no shell character filtering
6. Command templates (lines 70-73): `"echo stat | nc %s %s"`, `"echo cons | nc %s %s"`, etc.
7. `String.format(CMD_STAT, ip, port)` → `String[] cmd = { "/bin/bash", "-c", cmdStr }` (line 170)
8. `Exec.execute()` → `Runtime.getRuntime().exec(cmd)` (Exec.java:62)

### Trigger
- **Automatic**: Scheduled task runs every 300 seconds
- **Manual**: `doRefresh()` (line 81) accessible by anonymous users via `autoKeeperClustersList.htm`

## Key Evidence

**Command template with string format injection** (`AutoKeeperCollector.java:70-73,170`):
```java
private static final String CMD_STAT = "echo stat | nc %s %s";
String[] cmd = { "/bin/bash", "-c", String.format(CMD_STAT, ip, port) };
```

**No shell character sanitization** (`splitAddress()` line 269):
```java
List<String> ipPort = Arrays.asList(address.split(":"));
```
If address is `";id;:2181"`, ip becomes `";id;"`, resulting in bash command: `echo stat | nc ;id; 2181`.

**Auto-scheduled execution** (`startCollect()` line 311):
```java
collectorExecutor.scheduleAtFixedRate(new Runnable() {
    public void run() {
        for (AutoKeeperCluster cluster : clusters) {
            for (String address : cluster.getServerList()) {
                collectorServerStat(address);
            }
        }
    }
}, delay, collectInterval, TimeUnit.SECONDS);
```

## Authentication

**Write requires admin** (`webx.xml:194-205`): `AutoKeeperClusterAction.doAdd` and `doEdit` require admin role.

**Trigger is unauthenticated**: `doRefresh()` matches anonymous pattern `/.*List\.htm` — any user can trigger execution.

## Remediation

1. **Input validation**: Strictly validate ZK addresses against IP:port regex with no shell metacharacters
2. **Use ProcessBuilder with argument list**: Avoid `bash -c` string execution
3. **Shell escaping**: Sanitize address values before string format injection
4. **Service-layer validation**: Add deep validation beyond form-level checks

## References

- CWE-78: OS Command Injection
- CWE-94: Code Injection
