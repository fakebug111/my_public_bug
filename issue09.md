# Stored SQL Injection via REST → RabbitMQ → Dynamic API SQL

## Project Information
- **Project:** alldatacenter/alldata
- **Type:** Stored SQL Injection via Message Queue
- **Severity:** Critical (CVSS 9.1)
- **CWE:** CWE-89 (SQL Injection)

## Vulnerability Description

alldatacenter alldata contains a stored SQL injection where REST API parameters are stored/queued via RabbitMQ and later used in dynamic SQL construction without parameterization.

## Data Flow

```
REST API → RabbitMQ message → Consumer → Dynamic SQL construction → execute()
```

### Write Path
1. REST endpoint accepts parameters that influence SQL queries
2. Parameters published as RabbitMQ message
3. No SQL sanitization on queued message content

### Read Path
4. RabbitMQ consumer receives message
5. Message content used in dynamic SQL construction via string concatenation
6. SQL executed without parameterization

## Authentication

Authentication may be required depending on API configuration.

## Remediation

1. **Parameterized SQL**: Use PreparedStatement for all SQL execution
2. **Input validation**: Validate all message content against expected patterns
3. **SQL sanitization**: Escape special characters in dynamic SQL values

## References

- CWE-89: SQL Injection
