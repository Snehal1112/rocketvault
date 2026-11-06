/*
Copyright © 2025 Snehal Dangroshiya

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

package api

import (
	"net/http"

	"rocketvault/internal/container"
)

// listSecretVersionsHandler lists all versions of a secret.
func listSecretVersionsHandler(c *Context, w http.ResponseWriter, r *http.Request) {
	secretID, secretOK := resourceID(c, c.Params.SecretID, "secret_id")
	if !secretOK {
		return
	}

	secretService, svcOK := svc(c, container.ServiceContainerInterface.GetSecretService)
	if !svcOK {
		return
	}

	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}

	// Metadata only, and metadata only by construction: this route is
	// authorized by ActionSecretsReadMetadata, which Key Vault Reader holds.
	// It previously called GetSecretVersions, which decrypts every version,
	// so a Reader could read every historical plaintext value of the secret
	// (docs/known-bugs.md § B30). A value is read through
	// GET /secrets/{id}/versions/{n}, which requires ActionSecretsGet.
	versions, err := secretService.GetSecretVersionsMetadata(r.Context(), secretID, scope)
	if err != nil {
		writeSecretError(c, err)
		return
	}
	writeJSON(w, versions)
}

// getSecretVersionHandler retrieves a specific version of a secret.
func getSecretVersionHandler(c *Context, w http.ResponseWriter, r *http.Request) {
	secretID, secretOK := resourceID(c, c.Params.SecretID, "secret_id")
	if !secretOK {
		return
	}
	versionNum := c.Params.Version

	secretService, svcOK := svc(c, container.ServiceContainerInterface.GetSecretService)
	if !svcOK {
		return
	}

	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}

	version, err := secretService.GetSecretVersion(r.Context(), secretID, versionNum, scope)
	if err != nil {
		writeSecretError(c, err)
		return
	}
	writeJSON(w, version)
}

// getLatestSecretVersionHandler retrieves the latest version of a secret.
func getLatestSecretVersionHandler(c *Context, w http.ResponseWriter, r *http.Request) {
	secretID, secretOK := resourceID(c, c.Params.SecretID, "secret_id")
	if !secretOK {
		return
	}

	secretService, svcOK := svc(c, container.ServiceContainerInterface.GetSecretService)
	if !svcOK {
		return
	}

	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}

	version, err := secretService.GetLatestSecretVersion(r.Context(), secretID, scope)
	if err != nil {
		writeSecretError(c, err)
		return
	}
	writeJSON(w, version)
}
