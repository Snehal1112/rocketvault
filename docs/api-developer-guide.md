# RocketVault API Developer Guide

## Overview

The RocketVault API provides a comprehensive REST interface for managing secrets, keys, certificates, and system health monitoring. This guide covers authentication, request/response formats, error handling, and integration patterns.

## Base URL

```
https://api.rocketvault.local/api/v1
```

## Authentication

All API endpoints except health checks require JWT authentication. Include the JWT token in the `Authorization` header:

```
Authorization: Bearer <your-jwt-token>
```

### Obtaining a JWT Token

JWT tokens are obtained through the CLI login process:

```bash
./rocketvault users login --username admin --password yourpassword --totp-code 123456
```

The CLI will return a JWT token that can be used for API authentication.

### Token Expiration

- JWT tokens expire after 1 hour (configurable via `jwt.expiry` in `.rocketvault.yaml`)
- Include the token in all authenticated requests
- Handle 401 responses by re-authenticating

## Request/Response Format

### Content Type

All requests and responses use JSON format:

```
Content-Type: application/json
Accept: application/json
```

### Response Structure

#### Success Response

Endpoints return the resource object directly in the response body, with no
`data`/`message`/`status` wrapper. For example, a secret creation response:

```json
{
  "id": "3f1b2c4a-...",
  "name": "my-secret",
  "value": "...",
  "created_at": "2023-12-01T10:30:00Z"
}
```

#### Error Response

```json
{
  "id": "endpoint_name",
  "message": "Human-readable error message",
  "detailed_error": "Technical error details",
  "status_code": 400
}
```

## API Endpoints

### Health Endpoints

#### Get Health Metrics

```http
GET /api/v1/health
```

Returns comprehensive system health information.

**Response:**

```json
{
  "status": "healthy",
  "timestamp": "2023-12-01T10:30:00Z",
  "uptime": "2h 15m 30s",
  "memory": {
    "used": "45.2 MB",
    "total": "512 MB",
    "percentage": 8.8
  },
  "cpu": {
    "usage": 12.5,
    "cores": 4
  },
  "database": {
    "status": "connected",
    "connection_pool": {
      "active": 2,
      "idle": 5,
      "max_open": 10
    }
  },
  "query_metrics": {
    "query_count": 1250,
    "total_duration": "1.2s",
    "avg_duration": "950µs",
    "slow_queries": 3
  }
}
```

#### Readiness Check

```http
GET /api/v1/health/ready
```

**Response:**

```json
{
  "status": "ready"
}
```

#### Liveness Check

```http
GET /api/v1/health/live
```

**Response:**

```json
{
  "status": "alive"
}
```

### Vault Endpoints

#### Create Vault

```http
POST /api/v1/vaults
```

Requires JWT authentication with the `vaults:manage` permission (admin only).

#### List Vaults

```http
GET /api/v1/vaults
```

Supports `?include_deleted=true` to include soft-deleted vaults.

#### Update Vault

```http
PATCH /api/v1/vaults/{name}
```

#### Delete Vault

```http
DELETE /api/v1/vaults/{name}
```

Soft-deletes the vault (returns 204). The `default` vault cannot be deleted.

See the [Administrator Manual](admin-manual.html) for full request/response examples.

### Secrets Endpoints

All secrets endpoints require authentication.

#### Export Secrets

```http
POST /api/v1/secrets/export
Authorization: Bearer <token>
Content-Type: application/json
```

**Request Body:**

```json
{
  "format": "json",
  "encrypt": true,
  "passphrase": "<your-export-passphrase>",
  "tags": ["production", "api"],
  "include_tags": true
}
```

**Parameters:**

- `format`: `"json"` or `"csv"`
- `encrypt`: Boolean, whether to encrypt the export
- `passphrase`: String, required when `encrypt` is `true`. A non-empty
  passphrase alone (without `encrypt: true`) also triggers encryption. Never
  logged or echoed back. No minimum length enforced.
- `tags`: Array of tag strings to filter secrets
- `include_tags`: Boolean, include tags in export

**Response:** Binary file download with appropriate content type.

#### Import Secrets

```http
POST /api/v1/secrets/import
Authorization: Bearer <token>
Content-Type: multipart/form-data
```

**Form Data:**

- `file`: File containing secrets data
- `format`: `"json"` or `"csv"`
- `overwrite`: `"true"` or `"false"`
- `passphrase`: Required only when the uploaded file is a passphrase-sealed
  encrypted export (detected automatically by content). Ignored for a
  plaintext file.

**Response:**

```json
{
  "success": true,
  "message": "Successfully imported 5 secrets",
  "imported_count": 5,
  "total_count": 5,
  "format": "json",
  "imported_at": "2023-12-01T10:30:00Z"
}
```

#### List Secret Versions

```http
GET /api/v1/secrets/{id}/versions
Authorization: Bearer <token>
```

**Parameters:**

- `id`: Secret UUID

**Response:**

```json
[
  {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "version": 1,
    "name": "database-password",
    "value": "encrypted-secret-value",
    "tags": ["production", "database"],
    "created_at": "2023-12-01T10:30:00Z",
    "updated_at": "2023-12-01T10:30:00Z",
    "created_by": "550e8400-e29b-41d4-a716-446655440001"
  }
]
```

#### Get Secret Version

```http
GET /api/v1/secrets/{id}/versions/{version}
Authorization: Bearer <token>
```

**Parameters:**

- `id`: Secret UUID
- `version`: Version number (integer ≥ 1)

#### Get Latest Secret Version

```http
GET /api/v1/secrets/{id}/versions/latest
Authorization: Bearer <token>
```

**Parameters:**

- `id`: Secret UUID

### Key Endpoints

All key endpoints require authentication, plus a per-vault role assignment
granting the matching data action (see the [Administrator Manual](admin-manual.html)
for the full RSA/ECDSA/OCT create, rotate, and crypto-operation reference).

#### Import Key

```http
POST /api/v1/keys/import
Authorization: Bearer <token>
Content-Type: application/json
```

Imports an externally-generated RSA or ECDSA private key supplied as a JWK,
storing it exactly as a generated key would be (encrypted PEM, or a
non-extractable PKCS#11 object on an HSM-backed vault). This is the REST
equivalent of `rocketvault keys import` (see the [CLI Guide](cli-guide.md)).

Requires the `Microsoft.KeyVault/vaults/keys/import/action` data action in the
target vault, granted by the `Key Vault Crypto Officer` or
`Key Vault Administrator` role.

**Request Body:**

```json
{
  "name": "imported-signing-key",
  "jwk": {
    "kty": "RSA",
    "n": "...",
    "e": "AQAB",
    "d": "...",
    "p": "...",
    "q": "..."
  },
  "tags": ["production", "migrated"],
  "enabled": true,
  "purge_protection": false
}
```

**Parameters:**

- `name`: String, required. Key name.
- `jwk`: Object, required. A JWK containing private key material (`kty`
  `"RSA"` or `"EC"`). A public-only JWK (no private component) is rejected
  with a 400.
- `tags`: Array of tag strings, optional.
- `enabled`: Boolean, optional. Defaults to `true`.
- `purge_protection`: Boolean, optional. Leaves the stored default alone when
  omitted.

**Response:** `201 Created`

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "imported-signing-key",
  "type": "RSA",
  "bits": 2048,
  "enabled": true,
  "revoked": false,
  "tags": ["production", "migrated"],
  "user_id": "550e8400-e29b-41d4-a716-446655440001",
  "created_at": "2026-08-25T10:30:00Z"
}
```

Private key material is never returned; the response includes only public
components (RSA `n`/`e`, EC `x`/`y`), same as `POST /api/v1/keys`.

#### Export a Key

```http
POST /api/v1/vaults/{vault_name}/keys/{key_id}/export
Authorization: Bearer <token>
Content-Type: application/json

{"format": "pem", "version": 0}
```

The body is optional; an empty body exports the current version as PEM.
Only a software-backed key created or imported with `"exportable": true`
can be exported, and only by a principal holding the Key Vault Key Exporter
role (or Administrator) in that vault. HSM-backed, `oct` and ES256K keys are
never exportable. A revoked key, and a key that is disabled, expired or not
yet valid, is refused with `409` `key_disabled`. The flat route
`POST /api/v1/keys/{key_id}/export` acts on the `default` vault.

**Response:** `200 OK` with `Cache-Control: no-store` and `Pragma: no-cache`
(no export response, success or error, is cacheable):

```json
{
  "id": "6f1c...", "name": "signer", "type": "RSA", "version": 1,
  "format": "pem",
  "private_key_pem": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n",
  "key_algorithm": "RSA-2048"
}
```

### Certificate Endpoints

Certificates are versioned. Every create and every renewal produces a new
numbered version; the certificate's ID and name never change. Version numbers
are sequential integers starting at 1 (Azure Key Vault uses 32-hex version
IDs; this is a deliberate divergence). Every route below also exists under
`/api/v1/vaults/{vault_name}/certificates/...`. No response ever carries a PEM
or a private key.

#### Renew a Certificate

```http
POST /api/v1/certificates/{certificate_id}/renew
Authorization: Bearer <token>
Content-Type: application/json

{"validity_days": 90}
```

The body is optional; without `validity_days` the new version keeps the
current version's validity period. Requires the
`Microsoft.KeyVault/vaults/certificates/create` data action.

**Response:** `200 OK`, the new version's metadata:

```json
{
  "certificate_id": "550e8400-e29b-41d4-a716-446655440000",
  "version": 3,
  "current": true,
  "created_at": "2026-10-01T10:30:00Z",
  "expires_at": "2026-12-30T10:30:00Z",
  "not_before": "2026-10-01T10:30:00Z",
  "enabled": true
}
```

Renewal re-signs over the certificate's existing key, so the caller must own
that key: `403` means the key belongs to another user. `409` means the
certificate is disabled or outside its validity window, its key is no longer
available, it was signed by a CA this installation no longer records, or a
concurrent renewal won; re-read and retry only in the last case.

#### List and Read Versions

```http
GET /api/v1/certificates/{certificate_id}/versions
GET /api/v1/certificates/{certificate_id}/versions/{version}
```

The list is `{"versions": [...]}`, oldest first, with the current version last
and marked `"current": true`. Both require the
`Microsoft.KeyVault/vaults/certificates/read` data action.

#### Update a Version's Lifecycle

```http
PUT /api/v1/certificates/{certificate_id}/versions/{version}
Content-Type: application/json

{"enabled": false}
```

Accepts `enabled`, `expires_at` and `not_before`; at least one is required and
`not_before` must not be after `expires_at` (otherwise `400`). Updating the
current version is the same as updating the certificate's own attributes. A
disabled or expired version is unusable, and a disabled certificate gates every
version. Requires `Microsoft.KeyVault/vaults/certificates/update`. There is no
route to delete a single version.

#### Export a Certificate with its Private Key

```http
POST /api/v1/vaults/{vault_name}/certificates/{certificate_id}/export
Authorization: Bearer <token>
Content-Type: application/json

{"format": "pem"}
```

or, for a PKCS12 bundle:

```json
{"format": "pkcs12", "password": "", "compat": "modern", "version": 0}
```

`format` is required (`pem` or `pkcs12`). For `pkcs12` the `password` field
must be present; an empty string is allowed. `compat: "legacy"` produces
PBE-SHA1-3DES with a SHA-1 MAC for old consumers; the default is modern
(AES-256, SHA-256 MAC). `version` 0 or omitted exports the current version;
an archived version must itself be enabled and inside its own validity
window, and a disabled certificate blocks every version. The flat route
`POST /api/v1/certificates/{certificate_id}/export` acts on the `default`
vault.

Requires the Key Vault Certificate Exporter role (or Administrator) and a
certificate created with `"exportable": true`, which in turn requires a key
created with `"exportable": true`.

**Granting the export roles.** Key Vault Administrator also holds both export
actions, and a delegated Key Vault Data Access Administrator can grant it. The
two exporter roles (Key Vault Key Exporter and Key Vault Certificate
Exporter) can only be granted, and revoked, by a global admin.

**PEM response** (`Cache-Control: no-store`, `Pragma: no-cache`):

```json
{
  "id": "550e8400-...", "name": "rocket-client", "version": 1, "format": "pem",
  "certificate_pem": "-----BEGIN CERTIFICATE-----\n(leaf)\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\n(intermediate)\n-----END CERTIFICATE-----\n",
  "private_key_pem": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n",
  "not_before": "2026-10-01T10:00:00Z", "expires_at": "2027-10-01T10:00:00Z",
  "key_algorithm": "EC-P256"
}
```

The chain is leaf first, then intermediates; the root is never included. A
PKCS12 response carries `pkcs12_base64` instead of the two PEM fields.

#### Export Errors

The two export routes use their own error body:

```json
{"error": {"code": "certificate_not_exportable", "message": "certificate is not exportable: the certificate was not created with exportable: true", "key_algorithm": "RSA-2048"}}
```

| Status | Code | When |
|---|---|---|
| 400 | `bad_request` | bad body, unknown `format`/`compat`, `pkcs12` without `password`, bad `version` |
| 403 | `certificate_not_exportable` / `key_not_exportable` | flag false, HSM, `oct`, ES256K |
| 404 | `not_found` | unknown, soft-deleted, out of vault, or unknown version |
| 409 | `certificate_disabled` / `key_disabled` | disabled, expired or outside its window; also a revoked key |
| 500 | `internal_error` | anything else, including an unbuildable issuer chain; the message is generic |

A 401 (no session) and a 403 for a missing role come from the middleware and
keep their usual bodies; read the status, not the body, for those.

#### Export Caveats

- **Existing items are permanently non-exportable.** `exportable` is set only
  at creation or import and can never be changed. Re-create or re-import to
  get an exportable item.
- **A restore loses exportability.** Restoring a certificate or key backup
  always produces a non-exportable item.
- **A key rotation does not change an exported certificate.** A certificate
  keeps its own copy of the key; export reflects that copy until the
  certificate is renewed.
- **Chains use each CA's current certificate.** If a CA was renewed after the
  leaf was issued, the chain carries the CA's newer certificate, which still
  verifies because renewal keeps the CA's key. This also applies when you
  export an archived version of the leaf: its chain is built from the CA's
  current certificate, not the one that was current at issue time.
- **Nothing is cacheable.** Every export response carries `Cache-Control:
  no-store` and `Pragma: no-cache`.
- Every export attempt is audited (`export_certificate` / `export_key`); no
  key, chain or password is ever logged.

## Error Handling

### HTTP Status Codes

- `200`: Success
- `201`: Created
- `400`: Bad Request (invalid input)
- `401`: Unauthorized (missing/invalid token)
- `404`: Not Found
- `409`: Conflict (the resource changed concurrently, or is in a state that refuses the operation)
- `403` on an export route can also mean the item is not exportable; see Export Errors.
- `500`: Internal Server Error

### Common Error Patterns

#### Authentication Error

```json
{
  "id": "SessionRequired",
  "message": "Missing Authorization header",
  "detailed_error": "",
  "status_code": 401
}
```

#### Validation Error

```json
{
  "id": "exportSecrets",
  "message": "Invalid format. Must be 'json' or 'csv'",
  "detailed_error": "",
  "status_code": 400
}
```

#### Not Found Error

```json
{
  "id": "listSecretVersions",
  "message": "Secret not found",
  "detailed_error": "secret_id=550e8400-e29b-41d4-a716-446655440000",
  "status_code": 404
}
```

## Rate Limiting

Two independent limits apply, and a request must pass both. Exceeding either returns
`429 Too Many Requests`.

| Limit | Counted per | Default | Config key |
|-------|-------------|---------|------------|
| General endpoints | client IP | 300 req/min | `rate_limit.default` |
| Auth endpoints (`/login`, `/refresh`, `/oauth2/token`) | client IP | 5 req/min | `rate_limit.auth` |
| All authenticated endpoints | vault | 600 req/min | `rate_limit.per_vault` |

Each limit reports its own response headers, so you can tell which ceiling you hit:

| Header | Meaning |
|--------|---------|
| `X-RateLimit-Limit` / `-Remaining` / `-Reset` | Your per-IP budget. |
| `X-RateLimit-Vault-Limit` / `-Remaining` / `-Reset` | The budget of the vault you addressed. |

`-Reset` is a Unix timestamp for when the bucket is full again. Both are continuously-refilling
token buckets, not fixed windows, so capacity returns gradually rather than all at once.

### The per-vault limit

The per-vault budget is shared by every caller of that vault, so a client can be throttled by
someone else's traffic against the same vault while its own per-IP budget is untouched. Check
`X-RateLimit-Vault-Remaining` to distinguish the two cases before retrying.

Three behaviours affect how you should integrate:

- **Requests that resolve no vault of their own count against the `default` vault.** That covers
  vault-management routes (`/vaults/…`) and the legacy flat resource paths (`/secrets`, `/keys`,
  `/certificates`). Prefer the vault-scoped routes (`/vaults/{name}/secrets`) so your traffic is
  budgeted against your own vault.
- **Rejected requests still count.** The limit is applied before authorization, so a `403` still
  spends vault budget. Do not retry a `403` in a tight loop — you will throttle the vault for
  everyone using it.
- **Health probes are exempt.** `/health`, `/health/ready`, `/health/live` and `/health/database`
  are never counted, so a probe cannot exhaust a vault's budget.

Back off on `429` and honour `-Reset`.

## Best Practices

### 1. Handle Authentication Gracefully

```javascript
// Example: Automatic token refresh
async function apiRequest(url, options = {}) {
  const token = getStoredToken();

  if (!token) {
    throw new Error("No authentication token available");
  }

  const response = await fetch(url, {
    ...options,
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
      ...options.headers,
    },
  });

  if (response.status === 401) {
    // Token expired, redirect to login
    redirectToLogin();
    return;
  }

  return response;
}
```

### 2. Implement Retry Logic

```javascript
// Example: Retry with exponential backoff
async function retryApiRequest(url, options = {}, maxRetries = 3) {
  let attempt = 0;

  while (attempt < maxRetries) {
    try {
      const response = await apiRequest(url, options);

      if (response.ok) {
        return response;
      }

      // Don't retry on client errors (4xx)
      if (response.status >= 400 && response.status < 500) {
        throw new Error(`Client error: ${response.status}`);
      }
    } catch (error) {
      attempt++;

      if (attempt >= maxRetries) {
        throw error;
      }

      // Exponential backoff: 1s, 2s, 4s...
      const delay = Math.pow(2, attempt - 1) * 1000;
      await new Promise((resolve) => setTimeout(resolve, delay));
    }
  }
}
```

### 3. Validate Input Data

```javascript
// Example: Input validation before API calls
function validateExportRequest(data) {
  const errors = [];

  if (!["json", "csv"].includes(data.format)) {
    errors.push('Format must be "json" or "csv"');
  }

  if (data.tags && !Array.isArray(data.tags)) {
    errors.push("Tags must be an array");
  }

  if (typeof data.encrypt !== "boolean") {
    errors.push("Encrypt must be a boolean");
  }

  return errors;
}

const exportData = {
  format: "json",
  encrypt: true,
  passphrase: process.env.EXPORT_PASSPHRASE,
  tags: ["production"],
};

const validationErrors = validateExportRequest(exportData);
if (validationErrors.length > 0) {
  console.error("Validation errors:", validationErrors);
  return;
}
```

### 4. Handle File Uploads Properly

```javascript
// Example: Secure file upload for secret import
async function importSecrets(file, format, options = {}) {
  const formData = new FormData();
  formData.append("file", file);
  formData.append("format", format);
  if (options.passphrase) {
    formData.append("passphrase", options.passphrase);
  }
  formData.append("overwrite", options.overwrite ? "true" : "false");

  const response = await apiRequest("/api/v1/secrets/import", {
    method: "POST",
    body: formData,
    // Don't set Content-Type header - let browser set it with boundary
    headers: {
      Authorization: `Bearer ${getStoredToken()}`,
    },
  });

  return response.json();
}
```

## SDK Examples

### JavaScript/Node.js

```javascript
class PasswordManagerAPI {
  constructor(baseURL, token) {
    this.baseURL = baseURL;
    this.token = token;
  }

  async request(endpoint, options = {}) {
    const url = `${this.baseURL}${endpoint}`;
    const response = await fetch(url, {
      ...options,
      headers: {
        Authorization: `Bearer ${this.token}`,
        "Content-Type": "application/json",
        ...options.headers,
      },
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(`${error.message} (${error.status_code})`);
    }

    return response.json();
  }

  async getHealth() {
    return this.request("/health");
  }

  async exportSecrets(format, options = {}) {
    return this.request("/secrets/export", {
      method: "POST",
      body: JSON.stringify({
        format,
        encrypt: options.encrypt || false,
        passphrase: options.passphrase || "",
        tags: options.tags || [],
        include_tags: options.includeTags || false,
      }),
    });
  }

  async getSecretVersions(secretId) {
    return this.request(`/secrets/${secretId}/versions`);
  }
}

// Usage
const api = new PasswordManagerAPI(
  "https://api.rocketvault.local/api/v1",
  token
);

// Get health status
const health = await api.getHealth();
console.log("System health:", health.status);

// Export secrets
const exportResponse = await api.exportSecrets("json", {
  encrypt: true,
  passphrase: process.env.EXPORT_PASSPHRASE,
  tags: ["production"],
  includeTags: true,
});

// Get secret versions
const versions = await api.getSecretVersions(
  "550e8400-e29b-41d4-a716-446655440000"
);
console.log("Secret versions:", versions);
```

### Python

```python
import requests
import json
from typing import Dict, List, Optional

class PasswordManagerAPI:
    def __init__(self, base_url: str, token: str):
        self.base_url = base_url.rstrip('/')
        self.token = token
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        })

    def _request(self, method: str, endpoint: str, **kwargs) -> Dict:
        url = f"{self.base_url}/api/v1{endpoint}"
        response = self.session.request(method, url, **kwargs)

        if not response.ok:
            error_data = response.json()
            raise Exception(f"{error_data['message']} ({error_data['status_code']})")

        return response.json()

    def get_health(self) -> Dict:
        """Get system health metrics"""
        return self._request('GET', '/health')

    def export_secrets(self, format: str, encrypt: bool = False,
                      tags: List[str] = None, include_tags: bool = False) -> bytes:
        """Export secrets in specified format"""
        data = {
            'format': format,
            'encrypt': encrypt,
            'tags': tags or [],
            'include_tags': include_tags
        }

        url = f"{self.base_url}/api/v1/secrets/export"
        response = self.session.post(url, json=data)

        if not response.ok:
            error_data = response.json()
            raise Exception(f"{error_data['message']} ({error_data['status_code']})")

        return response.content

    def import_secrets(self, file_path: str, format: str,
                      encrypted: bool = False, overwrite: bool = False) -> Dict:
        """Import secrets from file"""
        with open(file_path, 'rb') as f:
            files = {'file': f}
            data = {
                'format': format,
                'encrypted': str(encrypted).lower(),
                'overwrite': str(overwrite).lower()
            }

            url = f"{self.base_url}/api/v1/secrets/import"
            response = self.session.post(url, files=files, data=data)

            if not response.ok:
                error_data = response.json()
                raise Exception(f"{error_data['message']} ({error_data['status_code']})")

            return response.json()

    def get_secret_versions(self, secret_id: str) -> List[Dict]:
        """Get all versions of a secret"""
        return self._request('GET', f'/secrets/{secret_id}/versions')

    def get_secret_version(self, secret_id: str, version: int) -> Dict:
        """Get specific version of a secret"""
        return self._request('GET', f'/secrets/{secret_id}/versions/{version}')

    def get_latest_secret_version(self, secret_id: str) -> Dict:
        """Get latest version of a secret"""
        return self._request('GET', f'/secrets/{secret_id}/versions/latest')

# Usage example
api = PasswordManagerAPI('https://api.rocketvault.local', token)

# Get health status
health = api.get_health()
print(f"System status: {health['status']}")

# Export secrets
export_data = api.export_secrets('json', encrypt=True, tags=['production'])
with open('secrets_export.json', 'wb') as f:
    f.write(export_data)

# Import secrets
import_result = api.import_secrets('secrets_import.json', 'json', encrypted=True)
print(f"Imported {import_result['imported_count']} secrets")

# Get secret versions
versions = api.get_secret_versions('550e8400-e29b-41d4-a716-446655440000')
for version in versions:
    print(f"Version {version['version']}: {version['name']}")
```

### Go

```go
package main

import (
    "bytes"
    "encoding/json"
    "fmt"
    "io"
    "mime/multipart"
    "net/http"
    "os"
)

type PasswordManagerAPI struct {
    BaseURL string
    Token   string
    Client  *http.Client
}

type ExportRequest struct {
    Format      string   `json:"format"`
    Encrypt     bool     `json:"encrypt"`
    Tags        []string `json:"tags"`
    IncludeTags bool     `json:"include_tags"`
}

type ImportResponse struct {
    Success       bool   `json:"success"`
    Message       string `json:"message"`
    ImportedCount int    `json:"imported_count"`
    TotalCount    int    `json:"total_count"`
    Format        string `json:"format"`
    ImportedAt    string `json:"imported_at"`
}

func NewPasswordManagerAPI(baseURL, token string) *PasswordManagerAPI {
    return &PasswordManagerAPI{
        BaseURL: baseURL,
        Token:   token,
        Client:  &http.Client{},
    }
}

func (api *PasswordManagerAPI) makeRequest(method, endpoint string, body io.Reader) (*http.Response, error) {
    url := api.BaseURL + "/api/v1" + endpoint
    req, err := http.NewRequest(method, url, body)
    if err != nil {
        return nil, err
    }

    req.Header.Set("Authorization", "Bearer "+api.Token)
    if body != nil {
        req.Header.Set("Content-Type", "application/json")
    }

    return api.Client.Do(req)
}

func (api *PasswordManagerAPI) GetHealth() (map[string]interface{}, error) {
    resp, err := api.makeRequest("GET", "/health", nil)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("API request failed with status: %d", resp.StatusCode)
    }

    var result map[string]interface{}
    if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
        return nil, err
    }

    return result, nil
}

func (api *PasswordManagerAPI) ExportSecrets(format string, encrypt bool, tags []string, includeTags bool) ([]byte, error) {
    exportReq := ExportRequest{
        Format:      format,
        Encrypt:     encrypt,
        Tags:        tags,
        IncludeTags: includeTags,
    }

    jsonData, err := json.Marshal(exportReq)
    if err != nil {
        return nil, err
    }

    resp, err := api.makeRequest("POST", "/secrets/export", bytes.NewBuffer(jsonData))
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("export failed with status: %d", resp.StatusCode)
    }

    return io.ReadAll(resp.Body)
}

func (api *PasswordManagerAPI) ImportSecrets(filePath, format string, encrypted, overwrite bool) (*ImportResponse, error) {
    file, err := os.Open(filePath)
    if err != nil {
        return nil, err
    }
    defer file.Close()

    var buf bytes.Buffer
    writer := multipart.NewWriter(&buf)

    // Add file
    fileWriter, err := writer.CreateFormFile("file", filePath)
    if err != nil {
        return nil, err
    }
    io.Copy(fileWriter, file)

    // Add other fields
    writer.WriteField("format", format)
    writer.WriteField("encrypted", fmt.Sprintf("%t", encrypted))
    writer.WriteField("overwrite", fmt.Sprintf("%t", overwrite))
    writer.Close()

    req, err := http.NewRequest("POST", api.BaseURL+"/api/v1/secrets/import", &buf)
    if err != nil {
        return nil, err
    }

    req.Header.Set("Authorization", "Bearer "+api.Token)
    req.Header.Set("Content-Type", writer.FormDataContentType())

    resp, err := api.Client.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("import failed with status: %d", resp.StatusCode)
    }

    var result ImportResponse
    if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
        return nil, err
    }

    return &result, nil
}

func main() {
    api := NewPasswordManagerAPI("https://api.rocketvault.local", "your-jwt-token")

    // Get health status
    health, err := api.GetHealth()
    if err != nil {
        fmt.Printf("Error getting health: %v\n", err)
        return
    }
    fmt.Printf("System status: %v\n", health["status"])

    // Export secrets
    exportData, err := api.ExportSecrets("json", true, []string{"production"}, true)
    if err != nil {
        fmt.Printf("Error exporting secrets: %v\n", err)
        return
    }

    // Save to file
    err = os.WriteFile("secrets_export.json", exportData, 0644)
    if err != nil {
        fmt.Printf("Error saving export file: %v\n", err)
        return
    }

    // Import secrets
    importResult, err := api.ImportSecrets("secrets_import.json", "json", true, false)
    if err != nil {
        fmt.Printf("Error importing secrets: %v\n", err)
        return
    }

    fmt.Printf("Imported %d secrets successfully\n", importResult.ImportedCount)
}
```

## Troubleshooting

### Common Issues

1. **401 Unauthorized**

   - Check if JWT token is valid and not expired
   - Verify token format: `Bearer <token>`
   - Ensure token was obtained from the correct environment

2. **400 Bad Request**

   - Validate request body format
   - Check required fields are present
   - Verify data types match API specifications

3. **404 Not Found**

   - Verify endpoint URL is correct
   - Check if resource exists
   - Ensure proper path parameters

4. **500 Internal Server Error**
   - Check server logs for detailed error information
   - Verify database connectivity
   - Ensure all required services are running

### Debug Mode

Enable debug logging by setting the log level to debug in your configuration:

```yaml
logging:
  level: debug
  format: json
```

### Health Check Monitoring

Set up monitoring for the health endpoints:

```bash
# Check readiness
curl -f https://api.rocketvault.local/api/v1/health/ready

# Check liveness
curl -f https://api.rocketvault.local/api/v1/health/live

# Get detailed health metrics
curl https://api.rocketvault.local/api/v1/health | jq .
```

## Security Considerations

1. **Always use HTTPS** in production
2. **Store JWT tokens securely** - never in local storage for web apps
3. **Implement token refresh** logic to handle expiration
4. **Validate SSL certificates** when making API calls
5. **Use appropriate timeouts** to prevent hanging requests
6. **Implement proper error handling** without exposing sensitive information
7. **Rate limiting** is enforced per IP *and* per vault - respect both to avoid being blocked

## Support

For additional support or questions about the API:

- Check the [troubleshooting guide](troubleshooting.markdown)
- Review the [architecture documentation](architecture.markdown)
- Open an issue on the GitHub repository
- Contact the development team
