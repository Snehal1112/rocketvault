# RocketVault API Integration Examples

This document provides practical integration examples for common use cases when working with the RocketVault API.

## Table of Contents

- [Authentication Flow](#authentication-flow)
- [Secret Backup and Restore](#secret-backup-and-restore)
- [Automated Secret Rotation](#automated-secret-rotation)
- [Certificate Renewal and Version History](#certificate-renewal-and-version-history)
- [mTLS Client Identity from an Exported Certificate](#mtls-client-identity-from-an-exported-certificate)
- [CI/CD Pipeline Integration](#cicd-pipeline-integration)
- [Monitoring and Alerting](#monitoring-and-alerting)
- [Multi-Environment Management](#multi-environment-management)

## Authentication Flow

### CLI-Based Authentication

```bash
#!/bin/bash
# authenticate.sh - Get JWT token for API access

USERNAME="admin"
PASSWORD="your-secure-password"
TOTP_CODE="123456"

# Get JWT token
TOKEN=$(./rocketvault login --username "$USERNAME" --password "$PASSWORD" --totp-code "$TOTP_CODE" 2>/dev/null | grep -o '"token":"[^"]*"' | cut -d'"' -f4)

if [ -z "$TOKEN" ]; then
    echo "Authentication failed"
    exit 1
fi

echo "Authentication successful"
export JWT_TOKEN="$TOKEN"
```

### API Token Management

```javascript
// tokenManager.js - JWT token management utility
class TokenManager {
  constructor(baseURL) {
    this.baseURL = baseURL;
    this.token = null;
    this.refreshPromise = null;
  }

  async authenticate(username, password, totpCode) {
    // This would typically call your authentication endpoint
    // For now, we'll assume the token comes from CLI
    const token = await this.getTokenFromCLI(username, password, totpCode);
    this.token = token;
    return token;
  }

  async getValidToken() {
    if (!this.token) {
      throw new Error("Not authenticated");
    }

    // Check if token is expired (simple check)
    if (this.isTokenExpired(this.token)) {
      if (!this.refreshPromise) {
        this.refreshPromise = this.refreshToken();
      }
      await this.refreshPromise;
      this.refreshPromise = null;
    }

    return this.token;
  }

  isTokenExpired(token) {
    try {
      const payload = JSON.parse(atob(token.split(".")[1]));
      return payload.exp * 1000 < Date.now();
    } catch {
      return true;
    }
  }

  async refreshToken() {
    // Implement token refresh logic
    // This might involve re-authentication or a refresh endpoint
    throw new Error("Token refresh not implemented");
  }

  async getTokenFromCLI(username, password, totpCode) {
    // This is a placeholder - in practice, you'd need to
    // call the CLI or authentication API
    return new Promise((resolve, reject) => {
      // Simulate CLI call
      setTimeout(() => {
        resolve("your-jwt-token-here");
      }, 1000);
    });
  }
}
```

## Secret Backup and Restore

### Automated Daily Backup

```bash
#!/bin/bash
# backup-secrets.sh - Daily automated backup of all secrets

BACKUP_DIR="/var/backups/rocketvault"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_FILE="$BACKUP_DIR/secrets_backup_$TIMESTAMP.json"

# Source authentication
source ./authenticate.sh

# BACKUP_PASSPHRASE must be set from a secret store (e.g. `source
# ./secrets.env` or a secrets manager), never hardcoded in this script.

# Create backup directory if it doesn't exist
mkdir -p "$BACKUP_DIR"

# Export all secrets
curl -X POST \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "format": "json",
    "encrypt": true,
    "passphrase": "'"$BACKUP_PASSPHRASE"'",
    "include_tags": true
  }' \
  "https://api.rocketvault.local/api/v1/secrets/export" \
  -o "$BACKUP_FILE"

# Verify backup integrity
if [ $? -eq 0 ] && [ -s "$BACKUP_FILE" ]; then
    echo "Backup completed successfully: $BACKUP_FILE"

    # Calculate checksum
    CHECKSUM=$(sha256sum "$BACKUP_FILE" | cut -d' ' -f1)
    echo "$CHECKSUM  $BACKUP_FILE" > "$BACKUP_FILE.sha256"

    # Clean up old backups (keep last 30 days)
    find "$BACKUP_DIR" -name "secrets_backup_*.json" -mtime +30 -delete
    find "$BACKUP_DIR" -name "secrets_backup_*.sha256" -mtime +30 -delete
else
    echo "Backup failed!"
    exit 1
fi
```

### Selective Restore

```bash
#!/bin/bash
# restore-secrets.sh - Restore secrets from backup

BACKUP_FILE="$1"
OVERWRITE="${2:-false}"

if [ -z "$BACKUP_FILE" ]; then
    echo "Usage: $0 <backup_file> [overwrite]"
    exit 1
fi

# Source authentication
source ./authenticate.sh

# BACKUP_PASSPHRASE must be set from a secret store, never hardcoded in this
# script -- required only if $BACKUP_FILE is a passphrase-encrypted export.

# Restore secrets
curl -X POST \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -F "file=@$BACKUP_FILE" \
  -F "format=json" \
  -F "passphrase=$BACKUP_PASSPHRASE" \
  -F "overwrite=$OVERWRITE" \
  "https://api.rocketvault.local/api/v1/secrets/import"

if [ $? -eq 0 ]; then
    echo "Restore completed successfully"
else
    echo "Restore failed!"
    exit 1
fi
```

### Cross-Environment Backup

```python
#!/usr/bin/env python3
# cross_env_backup.py - Backup secrets across multiple environments

import requests
import json
import os
from datetime import datetime

class CrossEnvironmentBackup:
    def __init__(self):
        self.environments = {
            'dev': 'https://dev-api.rocketvault.local/api/v1',
            'staging': 'https://staging-api.rocketvault.local/api/v1',
            'prod': 'https://api.rocketvault.local/api/v1'
        }
        self.tokens = {}

    def authenticate_all(self):
        """Authenticate with all environments"""
        for env, url in self.environments.items():
            # In practice, you'd get tokens from secure storage
            self.tokens[env] = os.getenv(f'{env.upper()}_JWT_TOKEN')
            if not self.tokens[env]:
                raise ValueError(f"Missing token for {env}")

    def backup_environment(self, env, tags=None):
        """Backup secrets from specific environment"""
        url = f"{self.environments[env]}/secrets/export"
        headers = {
            'Authorization': f'Bearer {self.tokens[env]}',
            'Content-Type': 'application/json'
        }

        payload = {
            'format': 'json',
            'encrypt': True,
            'include_tags': True
        }

        if tags:
            payload['tags'] = tags

        response = requests.post(url, json=payload, headers=headers)
        response.raise_for_status()

        return response.content

    def create_cross_env_backup(self, output_dir='./backups'):
        """Create backups for all environments"""
        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

        backups = {}
        for env in self.environments.keys():
            try:
                print(f"Backing up {env} environment...")
                data = self.backup_environment(env)

                filename = f"{output_dir}/{env}_secrets_{timestamp}.json"
                with open(filename, 'wb') as f:
                    f.write(data)

                backups[env] = filename
                print(f"✓ {env} backup saved to {filename}")

            except Exception as e:
                print(f"✗ Failed to backup {env}: {e}")

        # Create manifest
        manifest = {
            'timestamp': timestamp,
            'environments': list(backups.keys()),
            'files': backups
        }

        manifest_file = f"{output_dir}/backup_manifest_{timestamp}.json"
        with open(manifest_file, 'w') as f:
            json.dump(manifest, f, indent=2)

        print(f"Backup manifest saved to {manifest_file}")
        return manifest

if __name__ == '__main__':
    backup_tool = CrossEnvironmentBackup()
    backup_tool.authenticate_all()
    manifest = backup_tool.create_cross_env_backup()
    print("Cross-environment backup completed!")
    print(json.dumps(manifest, indent=2))
```

## Automated Secret Rotation

### Database Password Rotation

```python
#!/usr/bin/env python3
# rotate_db_passwords.py - Automated database password rotation

import requests
import json
import psycopg2
import secrets
import string
from datetime import datetime

class DatabasePasswordRotator:
    def __init__(self, api_url, jwt_token):
        self.api_url = api_url
        self.headers = {
            'Authorization': f'Bearer {jwt_token}',
            'Content-Type': 'application/json'
        }

    def generate_password(self, length=32):
        """Generate a secure random password"""
        alphabet = string.ascii_letters + string.digits + string.punctuation
        return ''.join(secrets.choice(alphabet) for _ in range(length))

    def update_password_manager(self, secret_name, new_password, tags=None):
        """Update password in password manager"""
        # This would typically use the secrets API
        # For now, we'll simulate the update
        print(f"Updating {secret_name} in password manager...")

        # In a real implementation, you might:
        # 1. Create a new version of the secret
        # 2. Update the secret value
        # 3. Tag it appropriately

        return True

    def update_database(self, db_config, new_password):
        """Update password in database"""
        try:
            # Connect with current password
            conn = psycopg2.connect(
                host=db_config['host'],
                port=db_config['port'],
                database=db_config['database'],
                user=db_config['user'],
                password=db_config['current_password']
            )

            conn.autocommit = True
            cursor = conn.cursor()

            # Update password for the user
            cursor.execute(
                "ALTER USER %s PASSWORD %s",
                (db_config['user'], new_password)
            )

            cursor.close()
            conn.close()

            print(f"Database password updated for user {db_config['user']}")
            return True

        except Exception as e:
            print(f"Failed to update database password: {e}")
            return False

    def rotate_password(self, secret_name, db_config):
        """Rotate password for a database user"""
        print(f"Starting password rotation for {secret_name}")

        # Generate new password
        new_password = self.generate_password()

        # Update database first
        if not self.update_database(db_config, new_password):
            print("Database update failed, aborting rotation")
            return False

        # Update password manager
        tags = ['database', 'rotated', f"env:{db_config.get('environment', 'prod')}"]
        if not self.update_password_manager(secret_name, new_password, tags):
            print("Password manager update failed")
            # You might want to rollback the database change here
            return False

        print(f"Password rotation completed for {secret_name}")
        return True

    def rotate_all_db_passwords(self, databases):
        """Rotate passwords for all configured databases"""
        results = {}
        timestamp = datetime.now().isoformat()

        for db_name, config in databases.items():
            try:
                success = self.rotate_password(db_name, config)
                results[db_name] = {
                    'success': success,
                    'timestamp': timestamp
                }
            except Exception as e:
                print(f"Rotation failed for {db_name}: {e}")
                results[db_name] = {
                    'success': False,
                    'error': str(e),
                    'timestamp': timestamp
                }

        return results

# Configuration
databases = {
    'postgres_main': {
        'host': 'localhost',
        'port': 5432,
        'database': 'main_db',
        'user': 'app_user',
        'current_password': 'current_password_here',
        'environment': 'prod'
    },
    'postgres_analytics': {
        'host': 'localhost',
        'port': 5432,
        'database': 'analytics_db',
        'user': 'analytics_user',
        'current_password': 'current_password_here',
        'environment': 'prod'
    }
}

if __name__ == '__main__':
    # Initialize rotator
    rotator = DatabasePasswordRotator(
        api_url='https://api.rocketvault.local/api/v1',
        jwt_token='your-jwt-token'
    )

    # Rotate all passwords
    results = rotator.rotate_all_db_passwords(databases)

    # Report results
    successful = sum(1 for r in results.values() if r['success'])
    total = len(results)

    print(f"\nRotation Summary: {successful}/{total} successful")

    for db_name, result in results.items():
        status = "✓" if result['success'] else "✗"
        print(f"{status} {db_name}: {result.get('error', 'OK')}")
```

### API Key Rotation

```javascript
// rotateApiKeys.js - Automated API key rotation

const axios = require("axios");
const crypto = require("crypto");

class APIKeyRotator {
  constructor(apiBaseURL, jwtToken) {
    this.apiBaseURL = apiBaseURL;
    this.client = axios.create({
      baseURL: apiBaseURL,
      headers: {
        Authorization: `Bearer ${jwtToken}`,
        "Content-Type": "application/json",
      },
    });
  }

  generateAPIKey(length = 64) {
    return crypto.randomBytes(length).toString("hex");
  }

  async rotateAPIKey(serviceName, currentKey) {
    console.log(`Rotating API key for ${serviceName}`);

    try {
      // Generate new key
      const newKey = this.generateAPIKey();

      // Update in password manager
      await this.updateSecretInManager(serviceName, newKey);

      // Update external service
      await this.updateExternalService(serviceName, currentKey, newKey);

      // Verify the new key works
      const verified = await this.verifyNewKey(serviceName, newKey);

      if (verified) {
        console.log(`✓ API key rotation completed for ${serviceName}`);
        return { success: true, newKey };
      } else {
        console.log(`✗ API key verification failed for ${serviceName}`);
        // Rollback would go here
        return { success: false, error: "Verification failed" };
      }
    } catch (error) {
      console.error(
        `API key rotation failed for ${serviceName}:`,
        error.message
      );
      return { success: false, error: error.message };
    }
  }

  async updateSecretInManager(serviceName, newKey) {
    // This would create a new version of the secret
    const secretData = {
      name: `${serviceName}_api_key`,
      value: newKey,
      tags: ["api-key", "rotated", serviceName],
    };

    // In practice, you'd call the appropriate API endpoint
    console.log(`Updating secret in password manager for ${serviceName}`);
  }

  async updateExternalService(serviceName, oldKey, newKey) {
    // Update the external service with the new key
    console.log(`Updating external service ${serviceName} with new key`);

    // This would vary depending on the service
    // Examples:
    // - AWS API Gateway
    // - GitHub
    // - Slack
    // - etc.
  }

  async verifyNewKey(serviceName, newKey) {
    // Verify the new key works
    console.log(`Verifying new key for ${serviceName}`);

    // This would make a test API call with the new key
    return true; // Placeholder
  }

  async rotateMultipleKeys(services) {
    const results = {};
    const startTime = new Date();

    for (const [serviceName, config] of Object.entries(services)) {
      results[serviceName] = await this.rotateAPIKey(
        serviceName,
        config.currentKey
      );
    }

    const endTime = new Date();
    const duration = endTime - startTime;

    console.log(`\nRotation Summary:`);
    console.log(`Total time: ${duration}ms`);
    console.log(
      `Successful: ${Object.values(results).filter((r) => r.success).length}`
    );
    console.log(
      `Failed: ${Object.values(results).filter((r) => !r.success).length}`
    );

    return results;
  }
}

// Configuration
const services = {
  github: {
    currentKey: "ghp_old_key_here",
  },
  slack: {
    currentKey: "xoxb-old_key_here",
  },
  aws: {
    currentKey: "AKIA_old_key_here",
  },
};

// Usage
const rotator = new APIKeyRotator(
  "https://api.rocketvault.local/api/v1",
  "your-jwt-token"
);

rotator
  .rotateMultipleKeys(services)
  .then((results) => {
    console.log("Rotation completed:", results);
  })
  .catch((error) => {
    console.error("Rotation failed:", error);
  });
```

## Certificate Renewal and Version History

Renew a certificate, then confirm the previous version was kept:

```bash
#!/usr/bin/env bash
# renew_cert.sh - renew a certificate and show its version history.
set -euo pipefail

API="${ROCKETVAULT_URL:-http://127.0.0.1:8774}/api/v1/vaults/${VAULT:-default}"
CERT_ID="$1"

curl -sS -X POST "$API/certificates/$CERT_ID/renew" \
  -H "Authorization: Bearer $ROCKETVAULT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"validity_days": 90}' | jq '{version, expires_at}'

curl -sS "$API/certificates/$CERT_ID/versions" \
  -H "Authorization: Bearer $ROCKETVAULT_TOKEN" | jq '.versions[] | {version, current, enabled, expires_at}'
```

Renewal re-signs over the certificate's existing key, so the caller must own
that key; otherwise the route answers `403`.

The same from the CLI:

```bash
rocketvault certificate renew "$CERT_ID" --validity-days 90 --vault "$VAULT"
rocketvault certificate versions list "$CERT_ID" --vault "$VAULT"
```

To retire an old version without deleting it, disable it:

```bash
curl -sS -X PUT "$API/certificates/$CERT_ID/versions/1" \
  -H "Authorization: Bearer $ROCKETVAULT_TOKEN" \
  -H "Content-Type: application/json" -d '{"enabled": false}'
```

## mTLS Client Identity from an Exported Certificate

A service principal fetches its client certificate and key at send time and
does not write them to a file of its own. Setup, as an admin:

```bash
API="${ROCKETVAULT_URL:-http://127.0.0.1:8774}/api/v1/vaults/${VAULT:-default}"

# An exportable key and an exportable certificate issued over it.
KEY_ID=$(curl -sS -X POST "$API/keys" -H "Authorization: Bearer $ADMIN_JWT" \
  -H "Content-Type: application/json" \
  -d '{"name":"rocket-client-key","type":"ECDSA","curve":"P-256","exportable":true}' | jq -r .id)
CERT_ID=$(curl -sS -X POST "$API/certificates" -H "Authorization: Bearer $ADMIN_JWT" \
  -H "Content-Type: application/json" \
  -d "{\"name\":\"rocket-client\",\"key_id\":\"$KEY_ID\",\"validity_days\":365,\"exportable\":true}" | jq -r .id)

# Only a global admin can grant the exporter role.
curl -sS -X POST "$API/role-assignments" -H "Authorization: Bearer $ADMIN_JWT" \
  -H "Content-Type: application/json" \
  -d "{\"principal\":\"$SA_ID\",\"principal_type\":\"service_account\",\"role\":\"Key Vault Certificate Exporter\"}"
```

The same from the CLI: `rocketvault keys create --name rocket-client-key --type ECDSA --curve P-256 --exportable --vault "$VAULT"` and
`rocketvault certificate create --name rocket-client --key-id "$KEY_ID" --validity-days 365 --exportable --vault "$VAULT"`.

At send time, as the service principal (`$SA_TOKEN` from the OAuth2
client-credentials grant), fetch the identity and use it in memory only:

```bash
#!/usr/bin/env bash
# mtls_call.sh - fetch an exported client identity and make one mTLS call.
set -euo pipefail
API="${ROCKETVAULT_URL:-http://127.0.0.1:8774}/api/v1/vaults/${VAULT:-default}"

BODY=$(curl -sS -X POST "$API/certificates/$CERT_ID/export" \
  -H "Authorization: Bearer $SA_TOKEN" -H "Content-Type: application/json" \
  -d '{"format":"pem"}')

# Process substitution avoids writing the key to a file of our own.
curl -sS https://mtls.example.internal/health \
  --cert <(jq -r .certificate_pem <<<"$BODY") \
  --key <(jq -r .private_key_pem <<<"$BODY")
```

Avoid `set -x` while the identity is in a variable, and `unset BODY` after
the call.

In Go, build the identity straight from the response:

```go
pair, err := tls.X509KeyPair([]byte(resp.CertificatePEM), []byte(resp.PrivateKeyPEM))
if err != nil {
	return err
}
client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
	Certificates: []tls.Certificate{pair},
	MinVersion:   tls.VersionTLS12,
}}}
```

A client that stores the certificate by name resolves it to the id from the
list response, which carries `exportable` and `key_algorithm` for exactly that
purpose. A certificate that is not exportable answers `403` with code
`certificate_not_exportable`; recreate it with `"exportable": true`.

## CI/CD Pipeline Integration

### GitHub Actions Integration

```yaml
# .github/workflows/secrets-management.yml
name: Secrets Management

on:
  schedule:
    # Run daily at 2 AM UTC
    - cron: "0 2 * * *"
  workflow_dispatch:
    inputs:
      action:
        description: "Action to perform"
        required: true
        default: "backup"
        type: choice
        options:
          - backup
          - rotate
          - validate

env:
  API_URL: https://api.rocketvault.local/api/v1

jobs:
  secrets-management:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Setup Go
        uses: actions/setup-go@v4
        with:
          go-version: "1.21"

      - name: Download RocketVault CLI
        run: |
          wget https://github.com/snehal1112/rocketvault/releases/latest/download/rocketvault-linux-amd64
          chmod +x rocketvault-linux-amd64
          sudo mv rocketvault-linux-amd64 /usr/local/bin/rocketvault

      - name: Authenticate
        id: auth
        run: |
          # Get JWT token
          TOKEN=$(rocketvault login \
            --username ${{ secrets.PM_USERNAME }} \
            --password ${{ secrets.PM_PASSWORD }} \
            --totp-code ${{ secrets.PM_TOTP_CODE }} \
            2>/dev/null | jq -r '.token')

          echo "token=$TOKEN" >> $GITHUB_OUTPUT

      - name: Backup Secrets
        if: github.event.inputs.action == 'backup' || github.event.schedule == '0 2 * * *'
        run: |
          TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

          # Export secrets
          curl -X POST \
            -H "Authorization: Bearer ${{ steps.auth.outputs.token }}" \
            -H "Content-Type: application/json" \
            -d '{
              "format": "json",
              "encrypt": true,
              "passphrase": "${{ secrets.BACKUP_PASSPHRASE }}",
              "include_tags": true
            }' \
            "${{ env.API_URL }}/secrets/export" \
            -o secrets_backup_$TIMESTAMP.json

          # Upload backup as artifact
          echo "secrets_backup_$TIMESTAMP.json" >> backup_files.txt

      - name: Upload Backup Artifacts
        if: github.event.inputs.action == 'backup' || github.event.schedule == '0 2 * * *'
        uses: actions/upload-artifact@v3
        with:
          name: secrets-backup
          path: secrets_backup_*.json

      - name: Validate Secrets
        if: github.event.inputs.action == 'validate'
        run: |
          # Check if secrets are accessible
          HEALTH=$(curl -s "${{ env.API_URL }}/health" | jq -r '.status')

          if [ "$HEALTH" != "healthy" ]; then
            echo "Password manager is not healthy"
            exit 1
          fi

          # Validate authentication
          AUTH_TEST=$(curl -s -o /dev/null -w "%{http_code}" \
            -H "Authorization: Bearer ${{ steps.auth.outputs.token }}" \
            "${{ env.API_URL }}/secrets/export" \
            -X POST \
            -H "Content-Type: application/json" \
            -d '{"format": "json"}')

          if [ "$AUTH_TEST" != "200" ]; then
            echo "Authentication failed"
            exit 1
          fi

          echo "✓ All validations passed"

      - name: Rotate Secrets
        if: github.event.inputs.action == 'rotate'
        run: |
          # This would implement secret rotation logic
          echo "Secret rotation not yet implemented in CI/CD"
          # You could call a script that handles rotation

      - name: Cleanup
        if: always()
        run: |
          # Clean up sensitive files
          rm -f secrets_backup_*.json
          rm -f backup_files.txt
```

### Jenkins Pipeline

```groovy
// Jenkinsfile
pipeline {
    agent any

    environment {
        API_URL = 'https://api.rocketvault.local/api/v1'
        PM_CLI = '/usr/local/bin/rocketvault'
    }

    parameters {
        choice(name: 'ACTION', choices: ['backup', 'validate', 'rotate'], description: 'Action to perform')
    }

    stages {
        stage('Setup') {
            steps {
                script {
                    // Install dependencies if needed
                    sh 'which jq || apt-get update && apt-get install -y jq'
                }
            }
        }

        stage('Authenticate') {
            steps {
                script {
                    // Get JWT token
                    def token = sh(
                        script: """
                            ${PM_CLI} login \
                                --username ${env.PM_USERNAME} \
                                --password ${env.PM_PASSWORD} \
                                --totp-code ${env.PM_TOTP_CODE} \
                                2>/dev/null | jq -r '.token'
                        """,
                        returnStdout: true
                    ).trim()

                    env.JWT_TOKEN = token
                }
            }
        }

        stage('Backup') {
            when {
                expression { params.ACTION == 'backup' }
            }
            steps {
                script {
                    def timestamp = new Date().format('yyyyMMdd_HHmmss')

                    // Export secrets
                    sh """
                        curl -X POST \
                            -H "Authorization: Bearer ${env.JWT_TOKEN}" \
                            -H "Content-Type: application/json" \
                            -d '{
                                "format": "json",
                                "encrypt": true,
                                "passphrase": "${env.BACKUP_PASSPHRASE}",
                                "include_tags": true
                            }' \
                            "${env.API_URL}/secrets/export" \
                            -o secrets_backup_${timestamp}.json
                    """

                    // Archive backup
                    archiveArtifacts artifacts: "secrets_backup_${timestamp}.json", fingerprint: true
                }
            }
        }

        stage('Validate') {
            when {
                expression { params.ACTION == 'validate' }
            }
            steps {
                script {
                    // Check health
                    def health = sh(
                        script: "curl -s ${env.API_URL}/health | jq -r '.status'",
                        returnStdout: true
                    ).trim()

                    if (health != 'healthy') {
                        error("Password manager is not healthy")
                    }

                    // Test authentication
                    def authTest = sh(
                        script: """
                            curl -s -o /dev/null -w "%{http_code}" \
                                -H "Authorization: Bearer ${env.JWT_TOKEN}" \
                                "${env.API_URL}/secrets/export" \
                                -X POST \
                                -H "Content-Type: application/json" \
                                -d '{"format": "json"}'
                        """,
                        returnStdout: true
                    ).trim()

                    if (authTest != '200') {
                        error("Authentication failed")
                    }

                    echo "✓ All validations passed"
                }
            }
        }

        stage('Rotate') {
            when {
                expression { params.ACTION == 'rotate' }
            }
            steps {
                script {
                    // Implement rotation logic here
                    echo "Secret rotation would be implemented here"
                }
            }
        }
    }

    post {
        always {
            // Cleanup
            sh 'rm -f secrets_backup_*.json'
        }
        success {
            echo 'Pipeline completed successfully'
        }
        failure {
            echo 'Pipeline failed'
        }
    }
}
```

## Monitoring and Alerting

### Health Check Monitoring

```bash
#!/bin/bash
# monitor-health.sh - Monitor password manager health and send alerts

API_URL="https://api.rocketvault.local/api/v1"
ALERT_EMAIL="admin@company.com"
LOG_FILE="/var/log/rocketvault/health_monitor.log"

# Function to log messages
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

# Function to send alert
send_alert() {
    local subject="$1"
    local message="$2"

    log "Sending alert: $subject"

    # Send email alert (requires mail command or similar)
    echo "$message" | mail -s "$subject" "$ALERT_EMAIL"

    # You could also integrate with Slack, PagerDuty, etc.
}

# Check health endpoint
check_health() {
    local endpoint="$1"
    local expected_status="${2:-200}"

    log "Checking $endpoint"

    local response=$(curl -s -w "HTTPSTATUS:%{http_code}" "$API_URL$endpoint")
    local body=$(echo "$response" | sed 's/HTTPSTATUS.*//')
    local status=$(echo "$response" | grep "HTTPSTATUS" | cut -d: -f2)

    if [ "$status" != "$expected_status" ]; then
        send_alert "RocketVault Health Check Failed" \
            "Endpoint: $endpoint\nExpected status: $expected_status\nActual status: $status\nResponse: $body"
        return 1
    fi

    log "✓ $endpoint is healthy"
    return 0
}

# Check detailed health metrics
check_detailed_health() {
    log "Checking detailed health metrics"

    local health_data=$(curl -s "$API_URL/health")

    # Check if response is valid JSON
    if ! echo "$health_data" | jq . >/dev/null 2>&1; then
        send_alert "RocketVault Health Check Failed" \
            "Invalid JSON response from health endpoint\nResponse: $health_data"
        return 1
    fi

    local status=$(echo "$health_data" | jq -r '.status')
    local memory_usage=$(echo "$health_data" | jq -r '.memory.percentage // 0')
    local db_status=$(echo "$health_data" | jq -r '.database.status // "unknown"')

    log "Status: $status, Memory: ${memory_usage}%, DB: $db_status"

    # Alert on unhealthy status
    if [ "$status" != "healthy" ]; then
        send_alert "RocketVault Unhealthy" \
            "System status: $status\nMemory usage: ${memory_usage}%\nDatabase status: $db_status"
        return 1
    fi

    # Alert on high memory usage
    if (( $(echo "$memory_usage > 90" | bc -l) )); then
        send_alert "RocketVault High Memory Usage" \
            "Memory usage is ${memory_usage}%, which is above 90% threshold"
    fi

    # Alert on database issues
    if [ "$db_status" != "connected" ]; then
        send_alert "RocketVault Database Issue" \
            "Database status: $db_status"
        return 1
    fi

    return 0
}

# Main monitoring loop
log "Starting health monitoring"

# Check basic endpoints
check_health "/health" "200"
check_health "/health/ready" "200"
check_health "/health/live" "200"

# Check detailed health
check_detailed_health

log "Health monitoring completed"
```

### Prometheus Metrics Exporter

```python
#!/usr/bin/env python3
# prometheus_exporter.py - Export password manager metrics to Prometheus

import requests
import time
from prometheus_client import start_http_server, Gauge, Enum
import json

class PasswordManagerMetricsExporter:
    def __init__(self, api_url, jwt_token, port=8000):
        self.api_url = api_url
        self.headers = {'Authorization': f'Bearer {jwt_token}'}
        self.port = port

        # Define metrics
        self.system_status = Enum(
            'password_manager_status',
            'Overall system status',
            states=['healthy', 'unhealthy']
        )

        self.memory_usage_percent = Gauge(
            'password_manager_memory_usage_percent',
            'Memory usage percentage'
        )

        self.cpu_usage_percent = Gauge(
            'password_manager_cpu_usage_percent',
            'CPU usage percentage'
        )

        self.database_connections_active = Gauge(
            'password_manager_db_connections_active',
            'Number of active database connections'
        )

        self.database_connections_idle = Gauge(
            'password_manager_db_connections_idle',
            'Number of idle database connections'
        )

        self.query_count = Gauge(
            'password_manager_query_count',
            'Total number of database queries'
        )

        self.query_avg_duration_ms = Gauge(
            'password_manager_query_avg_duration_ms',
            'Average query duration in milliseconds'
        )

    def fetch_health_metrics(self):
        """Fetch health metrics from the API"""
        try:
            response = requests.get(
                f"{self.api_url}/health",
                headers=self.headers,
                timeout=10
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"Failed to fetch health metrics: {e}")
            return None

    def update_metrics(self):
        """Update Prometheus metrics"""
        data = self.fetch_health_metrics()

        if not data:
            return

        # Update system status
        status = data.get('status', 'unhealthy')
        self.system_status.state(status)

        # Update memory metrics
        memory = data.get('memory', {})
        memory_percent = memory.get('percentage', 0)
        self.memory_usage_percent.set(memory_percent)

        # Update CPU metrics
        cpu = data.get('cpu', {})
        cpu_percent = cpu.get('usage', 0)
        self.cpu_usage_percent.set(cpu_percent)

        # Update database metrics
        database = data.get('database', {})
        connection_pool = database.get('connection_pool', {})

        self.database_connections_active.set(
            connection_pool.get('active', 0)
        )
        self.database_connections_idle.set(
            connection_pool.get('idle', 0)
        )

        # Update query metrics
        query_metrics = data.get('query_metrics', {})
        self.query_count.set(query_metrics.get('query_count', 0))

        avg_duration_str = query_metrics.get('avg_duration', '0µs')
        # Convert duration string to milliseconds
        avg_duration_ms = self.parse_duration(avg_duration_str)
        self.query_avg_duration_ms.set(avg_duration_ms)

    def parse_duration(self, duration_str):
        """Parse duration string to milliseconds"""
        # Handle formats like "950µs", "1.2s", "150ms"
        if 'µs' in duration_str:
            return float(duration_str.replace('µs', '')) / 1000
        elif 'ms' in duration_str:
            return float(duration_str.replace('ms', ''))
        elif 's' in duration_str:
            return float(duration_str.replace('s', '')) * 1000
        else:
            return 0

    def run(self):
        """Start the metrics exporter"""
        start_http_server(self.port)
        print(f"Metrics server started on port {self.port}")

        while True:
            self.update_metrics()
            time.sleep(30)  # Update every 30 seconds

if __name__ == '__main__':
    exporter = PasswordManagerMetricsExporter(
        api_url='https://api.rocketvault.local/api/v1',
        jwt_token='your-jwt-token',
        port=8000
    )
    exporter.run()
```

## Multi-Environment Management

### Environment-Specific Secret Management

```python
#!/usr/bin/env python3
# multi_env_manager.py - Manage secrets across multiple environments

import requests
import json
import os
from typing import Dict, List, Optional

class MultiEnvironmentManager:
    def __init__(self):
        self.environments = {
            'development': {
                'url': 'https://dev-api.rocketvault.local/api/v1',
                'token': os.getenv('DEV_JWT_TOKEN')
            },
            'staging': {
                'url': 'https://staging-api.rocketvault.local/api/v1',
                'token': os.getenv('STAGING_JWT_TOKEN')
            },
            'production': {
                'url': 'https://api.rocketvault.local/api/v1',
                'token': os.getenv('PROD_JWT_TOKEN')
            }
        }

    def get_client(self, environment: str):
        """Get authenticated client for environment"""
        if environment not in self.environments:
            raise ValueError(f"Unknown environment: {environment}")

        config = self.environments[environment]
        return PasswordManagerClient(config['url'], config['token'])

    def promote_secrets(self, from_env: str, to_env: str, secret_names: List[str] = None, tags: List[str] = None):
        """Promote secrets from one environment to another"""
        print(f"Promoting secrets from {from_env} to {to_env}")

        source_client = self.get_client(from_env)
        target_client = self.get_client(to_env)

        # Export secrets from source
        export_data = source_client.export_secrets(
            format='json',
            encrypt=True,
            tags=tags,
            include_tags=True
        )

        # Parse exported data
        secrets_data = json.loads(export_data.decode('utf-8'))

        # Filter secrets if specific names provided
        if secret_names:
            secrets_data['secrets'] = [
                secret for secret in secrets_data['secrets']
                if secret['name'] in secret_names
            ]

        # Update tags to reflect target environment
        for secret in secrets_data['secrets']:
            secret['tags'] = [
                tag for tag in secret.get('tags', [])
                if not tag.startswith('env:')
            ] + [f'env:{to_env}']

        # Import to target environment
        import_result = target_client.import_secrets(
            json.dumps(secrets_data).encode('utf-8'),
            format='json',
            encrypted=True,
            overwrite=True
        )

        print(f"Promoted {import_result['imported_count']} secrets to {to_env}")
        return import_result

    def validate_environment_sync(self, environments: List[str] = None):
        """Validate that environments have consistent secrets"""
        if environments is None:
            environments = list(self.environments.keys())

        env_secrets = {}

        # Collect secrets from each environment
        for env in environments:
            client = self.get_client(env)
            secrets = client.export_secrets(
                format='json',
                encrypt=False,
                include_tags=True
            )

            data = json.loads(secrets.decode('utf-8'))
            env_secrets[env] = {
                secret['name']: secret
                for secret in data.get('secrets', [])
            }

        # Find inconsistencies
        all_secret_names = set()
        for env_secrets_dict in env_secrets.values():
            all_secret_names.update(env_secrets_dict.keys())

        inconsistencies = []

        for secret_name in all_secret_names:
            versions = {}
            for env in environments:
                secret = env_secrets[env].get(secret_name)
                if secret:
                    versions[env] = secret.get('version', 0)
                else:
                    versions[env] = None

            # Check if versions are consistent
            version_values = [v for v in versions.values() if v is not None]
            if len(set(version_values)) > 1:
                inconsistencies.append({
                    'secret': secret_name,
                    'versions': versions
                })

        return {
            'total_secrets': len(all_secret_names),
            'inconsistencies': inconsistencies,
            'consistent': len(inconsistencies) == 0
        }

    def audit_secret_access(self, environment: str, days: int = 7):
        """Audit secret access patterns"""
        client = self.get_client(environment)

        # This would typically query audit logs
        # For now, we'll return a placeholder
        return {
            'environment': environment,
            'period_days': days,
            'total_accesses': 0,
            'unique_secrets': 0,
            'top_accessed': []
        }

class PasswordManagerClient:
    """Simple client for RocketVault API"""
    def __init__(self, base_url: str, token: str):
        self.base_url = base_url.rstrip('/')
        self.headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }

    def export_secrets(self, format: str = 'json', encrypt: bool = False,
                      tags: List[str] = None, include_tags: bool = True):
        """Export secrets"""
        url = f"{self.base_url}/secrets/export"
        payload = {
            'format': format,
            'encrypt': encrypt,
            'include_tags': include_tags
        }
        if tags:
            payload['tags'] = tags

        response = requests.post(url, json=payload, headers=self.headers)
        response.raise_for_status()
        return response.content

    def import_secrets(self, data: bytes, format: str = 'json',
                      encrypted: bool = False, overwrite: bool = False):
        """Import secrets"""
        url = f"{self.base_url}/secrets/import"

        files = {'file': ('secrets.json', data, 'application/json')}
        form_data = {
            'format': format,
            'encrypted': str(encrypted).lower(),
            'overwrite': str(overwrite).lower()
        }

        response = requests.post(url, files=files, data=form_data, headers={
            'Authorization': self.headers['Authorization']
        })
        response.raise_for_status()
        return response.json()

# Usage examples
if __name__ == '__main__':
    manager = MultiEnvironmentManager()

    # Promote secrets from staging to production
    result = manager.promote_secrets(
        from_env='staging',
        to_env='production',
        tags=['production-ready']
    )

    # Validate environment consistency
    validation = manager.validate_environment_sync()
    if not validation['consistent']:
        print("Environment inconsistencies found:")
        for inconsistency in validation['inconsistencies']:
            print(f"  {inconsistency['secret']}: {inconsistency['versions']}")

    # Audit access patterns
    audit = manager.audit_secret_access('production', days=30)
    print(f"Audit results: {audit}")
```

This comprehensive set of integration examples covers the most common use cases for the RocketVault API, including authentication, backup/restore, rotation, CI/CD integration, monitoring, and multi-environment management. Each example includes error handling, logging, and best practices for production use.
