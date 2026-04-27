# Stored Deserialization RCE via Redis → ObjectInputStream.readObject()

## Project Information
- **Project:** apache/camel
- **Type:** Stored Deserialization RCE (Java Serialization)
- **Severity:** Critical (CVSS 9.8)
- **CWE:** CWE-502 (Deserialization of Untrusted Data)

## Vulnerability Description

Apache Camel's Redis component stores exchange data using Java serialization (`ObjectOutputStream`/`ObjectInputStream`). When data is read from Redis, `ObjectInputStream.readObject()` deserializes arbitrary objects without class filtering, enabling RCE via gadget chains (e.g., Commons Collections, Spring framework).

## Data Flow

```
Camel route → Redis (serialized exchange) → ObjectInputStream.readObject() → gadget chain RCE
```

### Write Path
1. Camel route writes exchange body to Redis using Java serialization
2. Data stored as serialized byte array in Redis

### Read Path
3. Camel route reads from Redis
4. `ObjectInputStream.readObject()` deserializes bytes without class filtering
5. If gadget chains present in classpath, arbitrary code execution achieved

## Authentication

Depends on Camel route configuration. Redis may be unauthenticated.

## Remediation

1. **Avoid Java serialization**: Use JSON or other safe serialization formats
2. **Class filtering**: Implement `ObjectInputFilter` (Java 9+) to restrict deserializable classes
3. **Redis security**: Enable authentication and TLS for Redis connections
4. **Remove gadget chains**: Audit classpath for known deserialization gadgets

## References

- CWE-502: Deserialization of Untrusted Data
