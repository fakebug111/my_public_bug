# Stored Deserialization via Kafka — Chain Incomplete

## Project Information
- **Project:** SPLWare/esProc
- **Type:** Stored Deserialization (Reported) → CHAIN INCOMPLETE
- **CWE:** CWE-502 (Deserialization of Untrusted Data)

## Verdict: CHAIN INCOMPLETE — byte2Obj() not called in Kafka data flow

## Investigation Findings

1. **`ImUtils.byte2Obj()`** uses raw `ObjectInputStream.readObject()` with no class filtering — inherently dangerous
2. **NOT called in Kafka data path**: `ImFunction.getData()` processes Kafka bytes via `Sequence.fillRecord()` (custom binary format) or converts to String — never calls `byte2Obj()`
3. **HTTP server has no authentication**: `SplxHttpHandler` adds `Access-Control-Allow-Origin: *`, no auth checks
4. **Separate risk via SocketData**: `SocketData` uses `ObjectInputStream.readUnshared()` on raw TCP sockets for parallel computing nodes
5. **FilteredObjectInputStream exists but defaults to no filtering**: only filters when `allowedClassName` is set

## Potential Risk

- `byte2Obj()` is a dormant risk — if future code paths call it with Kafka data, the vulnerability would materialize
- TCP `SocketData` path provides an alternative deserialization attack surface

## References

- CWE-502: Deserialization of Untrusted Data
