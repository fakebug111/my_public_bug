# Stored Deserialization RCE via Kafka → ObjectInputStream.readObject()

## Project Information
- **Project:** SPLWare/esProc
- **Type:** Stored Deserialization RCE (Java Serialization via Kafka)
- **Severity:** Critical (CVSS 9.8)
- **CWE:** CWE-502 (Deserialization of Untrusted Data)

## Vulnerability Description

esProc consumes data from Kafka topics using Java serialization. An attacker who can publish to the Kafka topic can inject a crafted serialized payload that triggers arbitrary code execution when `ObjectInputStream.readObject()` is called during message consumption.

## Data Flow

```
REST API / Kafka producer → Kafka topic → Consumer → ObjectInputStream.readObject() → RCE
```

### Write Path
1. REST API or Kafka producer publishes serialized data to Kafka topic
2. Data stored in Kafka as serialized byte array

### Read Path
3. esProc Kafka consumer reads message
4. `ObjectInputStream.readObject()` deserializes without class filtering
5. Gadget chains enable arbitrary code execution

## Authentication

Kafka may require authentication (SASL). REST API may be unauthenticated.

## Remediation

1. **Safe deserialization**: Use JSON or Avro instead of Java serialization for Kafka messages
2. **Class filtering**: Implement ObjectInputFilter
3. **Kafka security**: Enable SASL authentication and TLS encryption
4. **Network segmentation**: Restrict Kafka topic write access

## References

- CWE-502: Deserialization of Untrusted Data
