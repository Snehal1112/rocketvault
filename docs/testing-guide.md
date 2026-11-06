# RocketVault Testing Guide

This guide provides comprehensive steps to test the RocketVault's export functionality and related features.

## Unit tests (Go)

Run the whole suite with `go build ./... && go test ./...`. Useful narrower runs:

```bash
go test ./cmd/... -v          # CLI commands
go test ./cmd/secrets/... -v  # one command group
go test ./cmd/... -cover      # with coverage
```

CLI tests use `cmd/testutils`. `testutils.NewTestContext(t)` returns a `TestContext` that holds a
`MockServiceContainer` plus testify mocks for the user, secret, authentication, RBAC, vault, role
assignment and access policy services, and a test user and vault ID. `tc.CreateTestCommand(cmd)`
wires a Cobra command to that container. Tests are table-driven:

```go
tests := []struct {
    name          string
    setupMocks    func(*testutils.TestContext)
    flags         map[string]string
    expectedError string
}{
    // Test cases.
}

for _, tt := range tests {
    t.Run(tt.name, func(t *testing.T) {
        tc := testutils.NewTestContext(t)
        tt.setupMocks(tc)
        testCmd := tc.CreateTestCommand(createCmd)
        for k, v := range tt.flags {
            _ = testCmd.Flags().Set(k, v)
        }
        err := testCmd.Execute()
        // Assert on err and on tc's mock expectations.
    })
}
```

The rest of this guide is a manual walkthrough of the export features.

## Prerequisites

1. **Go Environment**: Ensure Go 1.25+ is installed
2. **Dependencies**: Run `go mod tidy` to install all dependencies
3. **Build**: Compile the application with `go build -o rocketvault`

## Test Configuration

The test configuration file `test-config.yaml` should contain:
```yaml
master_key: "GENERATE_WITH: openssl rand -base64 32"
bootstrap_token: "test-bootstrap-token-12345"
database:
  connection: "./test-secrets.db"
log:
  level: "debug"
  file: "./test-secrets.log"
```

## Step 1: Initialize the System

### 1.1 Create Admin User

Since this is a fresh database, you need to create the initial admin user:

```bash
# Create admin user with bootstrap token
./rocketvault users admin \
  --admin-username admin1 \
  --admin-password admin123 \
  --bootstrap-token test-bootstrap-token-12345 \
  --config test-config.yaml
```

**Expected Output:**
- Admin user created successfully message
- TOTP secret for MFA (save this for authentication)

### 1.2 Generate TOTP Code

Use the TOTP generator script to get valid authentication codes:

```bash
# Generate current TOTP code
go run test/totp_generator.go
```

**Expected Output:**
```
Current TOTP Code for admin1: 123456
Secret: ZR4G6KJSNLGO2SUK5HOK7WB2LRIBEFXE
Use this code with --totp-code flag for authentication
```

## Step 2: Create Test Secrets

### 2.1 Create Basic Secret (No Tags)

```bash
./rocketvault secrets create "test-secret-1" "my-test-password-123" \
  --config test-config.yaml \
  --username admin1 \
  --password admin123 \
  --totp-code <CURRENT_TOTP_CODE>
```

### 2.2 Create Secret with Tags

```bash
./rocketvault secrets create "test-secret-2" "another-password-456" \
  --tags "api,test" \
  --config test-config.yaml \
  --username admin1 \
  --password admin123 \
  --totp-code <CURRENT_TOTP_CODE>
```

### 2.3 Create Another Secret with Different Tags

```bash
./rocketvault secrets create "test-secret-3" "database-connection-string" \
  --tags "database,production" \
  --config test-config.yaml \
  --username admin1 \
  --password admin123 \
  --totp-code <CURRENT_TOTP_CODE>
```

### 2.4 Verify Secrets Created

```bash
./rocketvault secrets list \
  --config test-config.yaml \
  --username admin1 \
  --password admin123 \
  --totp-code <CURRENT_TOTP_CODE>
```

**Expected Output:**
```json
[
  {
    "ID": "uuid-1",
    "UserID": "admin-uuid",
    "Name": "test-secret-1",
    "Value": "my-test-password-123",
    "Version": 1,
    "Tags": null,
    "CreatedAt": "2025-09-11T..."
  },
  {
    "ID": "uuid-2", 
    "UserID": "admin-uuid",
    "Name": "test-secret-2",
    "Value": "another-password-456",
    "Version": 1,
    "Tags": ["api", "test"],
    "CreatedAt": "2025-09-11T..."
  },
  {
    "ID": "uuid-3",
    "UserID": "admin-uuid", 
    "Name": "test-secret-3",
    "Value": "database-connection-string",
    "Version": 1,
    "Tags": ["database", "production"],
    "CreatedAt": "2025-09-11T..."
  }
]
```

## Step 3: Test Export Functionality

### 3.1 JSON Export (Unencrypted)

```bash
./rocketvault secrets export \
  --format json \
  --file test-export-unencrypted.json \
  --encrypt=false \
  --config test-config.yaml \
  --username admin1 \
  --password admin123 \
  --totp-code <CURRENT_TOTP_CODE>
```

**Expected Output:**
```
✅ Secrets exported successfully!
📄 Format: json
📁 File: test-export-unencrypted.json
🔒 Status: unencrypted
```

**Verify Content:**
```bash
cat test-export-unencrypted.json | jq .
```

**Expected JSON Structure:**
```json
{
  "metadata": {
    "format": "json",
    "include_tags": true,
    "encrypt": false,
    "user_id": "admin-uuid",
    "exported_at": "2025-09-11T...",
    "exported_by": "admin1"
  },
  "secrets": [
    {
      "id": "uuid-1",
      "name": "test-secret-1",
      "value": "my-test-password-123",
      "version": 1,
      "tags": null,
      "created_at": "2025-09-11T..."
    },
    {
      "id": "uuid-2",
      "name": "test-secret-2", 
      "value": "another-password-456",
      "version": 1,
      "tags": ["api", "test"],
      "created_at": "2025-09-11T..."
    },
    {
      "id": "uuid-3",
      "name": "test-secret-3",
      "value": "database-connection-string", 
      "version": 1,
      "tags": ["database", "production"],
      "created_at": "2025-09-11T..."
    }
  ]
}
```

### 3.2 JSON Export (Encrypted)

```bash
./rocketvault secrets export \
  --format json \
  --file test-export-encrypted.json \
  --encrypt \
  --config test-config.yaml \
  --username admin1 \
  --password admin123 \
  --totp-code <CURRENT_TOTP_CODE>
```

**Expected Output:**
```
✅ Secrets exported successfully!
📄 Format: json
📁 File: test-export-encrypted.json
🔒 Status: encrypted
```

**Verify Content (should be encrypted):**
```bash
head -c 100 test-export-encrypted.json
# Should show base64-encoded encrypted data
```

### 3.3 CSV Export (Unencrypted)

```bash
./rocketvault secrets export \
  --format csv \
  --file test-export.csv \
  --encrypt=false \
  --config test-config.yaml \
  --username admin1 \
  --password admin123 \
  --totp-code <CURRENT_TOTP_CODE>
```

**Expected Output:**
```
✅ Secrets exported successfully!
📄 Format: csv
📁 File: test-export.csv
🔒 Status: unencrypted
```

**Verify Content:**
```bash
cat test-export.csv
```

**Expected CSV Structure:**
```csv
id,name,value,version,tags,created_at
uuid-1,test-secret-1,my-test-password-123,1,,2025-09-11T...
uuid-2,test-secret-2,another-password-456,1,api;test,2025-09-11T...
uuid-3,test-secret-3,database-connection-string,1,database;production,2025-09-11T...
```

## Step 4: Test Tag Filtering

### 4.1 Export with Tag Filter

```bash
./rocketvault secrets export \
  --format json \
  --file test-export-api-only.json \
  --encrypt=false \
  --tags "api" \
  --config test-config.yaml \
  --username admin1 \
  --password admin123 \
  --totp-code <CURRENT_TOTP_CODE>
```

**Expected Result:** Only secrets with "api" tag should be exported

## Step 5: Test Error Scenarios

### 5.1 Invalid Authentication

```bash
./rocketvault secrets export \
  --format json \
  --file test-export.json \
  --config test-config.yaml \
  --username admin1 \
  --password wrongpassword \
  --totp-code 000000
```

**Expected Output:**
```
Error: Authentication failed - invalid credentials
Usage:
  rocketvault secrets export [flags]
```

### 5.2 Missing Required File Parameter

```bash
./rocketvault secrets export \
  --format json \
  --encrypt=false \
  --config test-config.yaml \
  --username admin1 \
  --password admin123 \
  --totp-code <CURRENT_TOTP_CODE>
```

**Expected Output:**
```
Error: required flag(s) "file" not set
```

### 5.3 Unsupported Format

```bash
./rocketvault secrets export \
  --format xml \
  --file test-export.xml \
  --encrypt=false \
  --config test-config.yaml \
  --username admin1 \
  --password admin123 \
  --totp-code <CURRENT_TOTP_CODE>
```

**Expected Output:**
```
Error: unsupported format: xml (supported: json, csv)
```

## Step 6: Test Additional Features

### 6.1 List Users

```bash
./rocketvault users list \
  --config test-config.yaml \
  --username admin1 \
  --password admin123 \
  --totp-code <CURRENT_TOTP_CODE>
```

### 6.2 Get User Information

```bash
./rocketvault users get admin1 \
  --config test-config.yaml \
  --username admin1 \
  --password admin123 \
  --totp-code <CURRENT_TOTP_CODE>
```

## Step 7: Cleanup

### 7.1 Remove Test Files

```bash
rm -f test-export*.json test-export.csv
```

### 7.2 Clean Database (Optional)

```bash
rm -f test-secrets.db test-secrets.log
```

## Test Scripts

### TOTP Generator Script (`test/totp_generator.go`)

```go
package main

import (
"fmt"
"time"
"github.com/pquerna/otp/totp"
)

func main() {
// TOTP secret generated for admin1 user
secret := "ZR4G6KJSNLGO2SUK5HOK7WB2LRIBEFXE"

code, err := totp.GenerateCode(secret, time.Now())
if err != nil {
fmt.Printf("Error generating TOTP: %v\n", err)
return
}

fmt.Printf("Current TOTP Code for admin1: %s\n", code)
fmt.Printf("Secret: %s\n", secret)
fmt.Printf("Use this code with --totp-code flag for authentication\n")
}
```

## Common Issues and Solutions

### Issue: Authentication Failed
**Solution:** 
1. Ensure TOTP code is current (valid for 30 seconds)
2. Check username and password are correct
3. Regenerate TOTP code if expired

### Issue: No Secrets Exported
**Solution:**
1. Verify secrets exist using `secrets list` command
2. Check user authentication is working
3. Ensure export command uses correct user context

### Issue: Encrypted File Appears Empty
**Solution:**
1. Encrypted files contain binary data
2. Use `head -c 100 file` to see encrypted content
3. Decryption requires proper master key

### Issue: Bootstrap Token Error
**Solution:**
1. Ensure `bootstrap_token` is set in config file
2. Use correct bootstrap token value
3. Bootstrap tokens can only be used once

## Performance Testing

### Large Dataset Export
```bash
# Create multiple secrets for performance testing
for i in {1..100}; do
  ./rocketvault secrets create "bulk-secret-$i" "value-$i" \
    --config test-config.yaml \
    --username admin1 \
    --password admin123 \
    --totp-code <CURRENT_TOTP_CODE>
done

# Test export performance
time ./rocketvault secrets export \
  --format json \
  --file bulk-export.json \
  --encrypt \
  --config test-config.yaml \
  --username admin1 \
  --password admin123 \
  --totp-code <CURRENT_TOTP_CODE>
```

## Security Testing

### Test Encryption Strength
1. Export with encryption enabled
2. Attempt to read encrypted file without proper decryption
3. Verify encrypted content is unreadable

### Test Access Control
1. Try exporting with different user credentials
2. Verify users can only access their own secrets
3. Test admin vs regular user permissions

## Summary

This testing guide covers:
- ✅ System initialization and user creation
- ✅ Secret creation with various configurations
- ✅ Export functionality in all supported formats
- ✅ Encryption and unencrypted exports
- ✅ Tag-based filtering
- ✅ Error handling and edge cases
- ✅ Performance and security testing

All tests should pass successfully, demonstrating the robustness of the RocketVault's export functionality.
