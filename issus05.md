# Stored SSRF via IoT Data Sink HTTP Configuration → RestTemplate

## Project Information
- **Project:** YunaiV/yudao-cloud
- **Type:** Stored SSRF (Server-Side Request Forgery via IoT Data Sink)
- **Severity:** High (CVSS 7.5)
- **CWE:** CWE-918 (Server-Side Request Forgery)

## Vulnerability Description

yudao-cloud IoT module contains a stored SSRF where HTTP sink configuration URLs are stored in the database without URL validation. When IoT device messages arrive, stored URLs are used by RestTemplate for outbound HTTP requests without internal IP filtering, protocol restrictions, or scheme validation.

## Data Flow

```
POST /admin-api/iot/data-sink/create → DB (iot_data_sink.config) → IoT message trigger → RestTemplate.postForObject(stored_url)
```

### Write Path
1. `IotDataSinkController`: Accepts data sink config including HTTP URL
2. `IotDataSinkSaveReqVO` → `IotDataSinkServiceImpl` → `IotDataSinkDO` → MySQL
3. `IotDataSinkHttpConfig` stores URL with no validation
4. Also affects TCP (`IotDataSinkTcpConfig`), WebSocket, and MQTT sink types

### Read Path
5. `IotDataRuleServiceImpl` triggers on IoT device messages
6. `IotHttpDataSinkAction` reads stored HTTP URL from database
7. `RestTemplate.postForObject(storedUrl, payload)` — no URL validation, no IP filtering

## Key Evidence

**No URL validation**: `IotDataSinkHttpConfig` stores arbitrary URL strings without scheme, host, or IP checks.

**Direct RestTemplate execution**: Stored URL used directly as RestTemplate target.

**Multiple sink types**: SSRF extends to TCP, WebSocket, and MQTT configurations.

## Authentication

**Required**: Admin authentication needed for data sink configuration.

## Remediation

1. **URL validation**: Restrict to HTTPS scheme only
2. **Internal IP blocking**: Reject private/internal IP ranges
3. **Allowlist**: Restrict to approved domains
4. **Cloud metadata blocking**: Block 169.254.169.254

## References

- CWE-918: Server-Side Request Forgery
