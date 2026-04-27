# Stored SSRF via Chat Model API Host Configuration

## Project Information
- **Project:** ageerle/ruoyi-ai
- **Type:** Stored SSRF (Server-Side Request Forgery)
- **Severity:** High (CVSS 8.1)
- **CWE:** CWE-918 (Server-Side Request Forgery)

## Vulnerability Description

ageerle ruoyi-ai contains a stored SSRF vulnerability where the `apiHost` field in chat model configuration is stored in the database without URL validation. The stored URL is then used as the base URL for outbound HTTP requests across at least 13 different sink points, including OpenAI, Ollama, Custom API, and embedding provider services.

## Data Flow

```
POST /system/model → ChatModelServiceImpl.insertByBo() → chat_model DB → .baseUrl(chatModelVo.getApiHost()) → HTTP client requests
```

### Write Path
1. `ChatModelController` (`POST /system/model`): accepts chat model configuration
2. `ChatModelServiceImpl.insertByBo()`: stores to `chat_model` table
3. `apiHost` field stored without URL validation (no scheme, hostname, or IP range check)
4. `validEntityBeforeSave` is an empty TODO stub

### Read Path
5. Multiple services use stored `apiHost` via `.baseUrl(chatModelVo.getApiHost())`:
   - `AbstractChatService`, `OpenAIServiceImpl`, `OllamaServiceImpl`, `CustomApiServiceImpl`
   - Embedding providers and other HTTP clients
6. HTTP clients make outbound requests to attacker-controlled URL

### Secondary SSRF Path
7. `ChatConfigController` → `chat_config` → `SysOssServiceImpl.initConfig()` → `QwenFileUploadUtils.uploadFile()` → `OkHttpClient` with stored `apiHost`

## Key Evidence

**No URL validation**: `apiHost` stored without scheme, hostname, or IP range validation.

**13+ sink points**: Stored URL used directly as HTTP client base URL across numerous services.

**Empty validation stub**: `validEntityBeforeSave` in `ChatModelServiceImpl` is empty TODO.

## Authentication

Authentication required. Any user with model management permissions can exploit this. The SSRF impacts all users who subsequently use the compromised model configuration.

## Remediation

1. **URL validation**: Validate `apiHost` against allowed schemes (https), hostnames, and IP ranges
2. **Block internal IPs**: Reject URLs pointing to internal/private IP ranges
3. **Implement `validEntityBeforeSave`**: Add actual URL validation
4. **Network policies**: Restrict outbound HTTP connections to approved domains
5. **Allowlist approach**: Only allow connections to pre-approved API endpoints

## References

- CWE-918: Server-Side Request Forgery
