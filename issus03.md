# Stored SSRF via Config Property URL → HttpClient.execute()

## Project Information
- **Project:** DependencyTrack/dependency-track
- **Type:** Stored SSRF (Server-Side Request Forgery via Config Properties)
- **Severity:** High (CVSS 7.2)
- **CWE:** CWE-918 (Server-Side Request Forgery)

## Vulnerability Description

DependencyTrack (v4.14.0+) contains a stored SSRF where authenticated users with SYSTEM_CONFIGURATION permission can store arbitrary URLs in config properties. These URLs are later used by background tasks for outbound HTTP requests without internal IP blocking or scheme restrictions.

## Data Flow

```
POST /api/v1/configProperty → JPA (CONFIGPROPERTY) → Background tasks → HttpClient.execute(stored_url)
```

### Write Path
1. `ConfigPropertyResource.java:96-124`: `POST /api/v1/configProperty` accepts `{groupName, propertyName, propertyValue}`
2. Requires `SYSTEM_CONFIGURATION` permission
3. `AbstractConfigPropertyResource.updatePropertyValueInternal()` (line 90-100): For URL types, only checks `java.net.URL` format validity — **no scheme restriction, no internal IP blocking**
4. Stored via `qm.persist(property)` in `CONFIGPROPERTY` table

### Read Path (Multiple Sinks)
5. **OSS Index Scanner** (`OssIndexAnalysisTask.java:160-179`): reads `scanner.ossindex.base.url`
6. **Trivy Scanner** (`TrivyAnalysisTask.java:517-533`): reads `scanner.trivy.base.url`
7. **Snyk Scanner** (`SnykAnalysisTask.java:385-402`): reads `scanner.snyk.base.url`
8. **NVD Feed Mirror** (`NistMirrorTask.java:160-166`): reads `vuln-source.nvd.feeds.url`
9. **EPSS Feed Mirror**: reads EPSS feed URL
10. All use `HttpClientPool.getClient().execute(request)` with stored URL

## Key Evidence

**Insufficient URL validation** (`AbstractConfigPropertyResource.java:90-100`):
```java
// Only checks URL format, no scheme or IP restrictions
url.toExternalForm()  // stored as-is
```

**Direct HTTP execution** (`OssIndexAnalysisTask.java:334`):
```java
HttpClientPool.getClient().execute(request);  // request uses stored URL
```

## Authentication

**Required**: `SYSTEM_CONFIGURATION` permission needed. Admin-level access.

## Remediation

1. **URL validation**: Restrict schemes to `https://` only
2. **Internal IP blocking**: Reject URLs pointing to private/internal IP ranges (10.x, 172.16-31.x, 192.168.x, 127.x, 169.254.x)
3. **Allowlist approach**: Restrict configurable URLs to approved domains
4. **Cloud metadata blocking**: Block access to 169.254.169.254 (cloud metadata)

## References

- CWE-918: Server-Side Request Forgery
