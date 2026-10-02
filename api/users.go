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
	"strings"
	"time"

	"github.com/google/uuid"

	"rocketvault/common"
	"rocketvault/internal/container"
	userService "rocketvault/internal/services/users"
	"rocketvault/model"
)

// InitUsers initializes the routes for users management API.
// It sets up the following endpoints:
// - POST /users/login: Authenticate user and return JWT token (public).
// - POST /users/refresh: Refresh access token using refresh token (public).
// - GET /users/sessions: List current user's sessions (authenticated).
// - DELETE /users/sessions/{session_id}: Revoke a specific session (authenticated).
// - DELETE /users/sessions: Revoke all user sessions (authenticated).
// - POST /users: Create a new user (admin only).
// - GET /users: List all users (admin only).
// - GET /users/{user_id}: Get a specific user by ID.
// - PUT /users/{user_id}: Update a user (admin only or own profile).
// - DELETE /users/{user_id}: Delete a user (admin only).
func (api *API) InitUsers() {
	u := api.BaseRoutes.Users

	// Public endpoints — no authentication required.
	u.Handle("/login", ApiHandler(api.App, loginUser)).Methods("POST")
	u.Handle("/refresh", ApiHandler(api.App, refreshToken)).Methods("POST")

	// Session management endpoints — authenticated.
	u.Handle("/sessions", ApiSessionRequired(api.App, listUserSessions)).Methods("GET")
	u.Handle("/sessions/{session_id:[A-Fa-f0-9-]+}", ApiSessionRequired(api.App, revokeSession)).Methods("DELETE")
	u.Handle("/sessions", ApiSessionRequired(api.App, revokeAllSessions)).Methods("DELETE")

	// Authenticated CRUD endpoints.
	u.Handle("", ApiSessionRequired(api.App, createUser)).Methods("POST")
	u.Handle("", ApiSessionRequired(api.App, listUsers)).Methods("GET")
	u.Handle("/{user_id:[A-Fa-f0-9-]+}", ApiSessionRequired(api.App, getUser)).Methods("GET")
	u.Handle("/{user_id:[A-Fa-f0-9-]+}", ApiSessionRequired(api.App, updateUser)).Methods("PUT")
	u.Handle("/{user_id:[A-Fa-f0-9-]+}", ApiSessionRequired(api.App, deleteUser)).Methods("DELETE")
}

// createUser handles the creation of a new user.
// Only users with admin role can create new users. Role validation (allowed
// values, at-least-one-required) is delegated entirely to UserService — this
// handler only classifies its error messages as client vs server errors.
func createUser(c *Context, w http.ResponseWriter, r *http.Request) {
	if !common.HasAnyRole(c.Claims.Roles, model.RoleAdmin) {
		c.SetPermissionError("admin role required")
		return
	}

	req, err := model.CreateUserRequestFromJson(r.Body)
	if err != nil {
		c.SetInvalidParam("request body")
		return
	}

	// The old "role" string field was replaced by "roles": [...] -- reject it
	// explicitly rather than silently ignoring it (unknown JSON fields are
	// dropped by default, which would otherwise turn this into a no-op).
	if req.DeprecatedRole != "" {
		c.SetInvalidParam(`the "role" field was replaced by "roles": [...] in this API version`)
		return
	}

	if req.Username == "" || len(req.Username) < 3 || len(req.Username) > 50 {
		c.SetInvalidParam("username: must be 3-50 characters")
		return
	}
	if req.Password == "" || len(req.Password) < 8 {
		c.SetInvalidParam("password: must be at least 8 characters")
		return
	}

	userSvc, svcOK := svc(c, container.ServiceContainerInterface.GetUserService)
	if !svcOK {
		return
	}

	result, err := userSvc.CreateUser(r.Context(), userService.CreateUserRequest{
		Username:    req.Username,
		Password:    req.Password,
		Roles:       req.Roles,
		CallerRoles: c.Claims.Roles,
	})
	if err != nil {
		// Role validation errors from UserService ("invalid role: ...",
		// "at least one role is required") are client errors, not server
		// errors -- surface them as 400s instead of masking as 500.
		if strings.Contains(err.Error(), "invalid role") || strings.Contains(err.Error(), "role is required") {
			c.SetInvalidParam(err.Error())
			return
		}
		c.SetInternalError(err)
		return
	}

	response := model.UserResponse{
		ID:         result.UserID.String(),
		Username:   result.Username,
		Roles:      result.Roles,
		CreatedAt:  time.Now().Format(time.RFC3339),
		TOTPSecret: result.TOTPSecret,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	w.Write([]byte(response.ToJson())) //nolint:errcheck,gosec

	c.Logger.Printf("Admin %s created user %s with roles %v", c.Claims.UserID, result.Username, result.Roles)
}

// listUsers handles the HTTP request to retrieve all users.
// Only users with admin role can list all users.
func listUsers(c *Context, w http.ResponseWriter, r *http.Request) {
	// Check admin privileges.
	if !common.HasAnyRole(c.Claims.Roles, model.RoleAdmin) {
		c.SetPermissionError("admin role required")
		return
	}

	userSvc, svcOK := svc(c, container.ServiceContainerInterface.GetUserService)
	if !svcOK {
		return
	}

	users, err := userSvc.ListUsers(r.Context())
	if err != nil {
		c.SetInternalError(err)
		return
	}

	// Apply pagination from params.
	total := len(users)
	offset := c.Params.Page * c.Params.PerPage
	start := offset
	if start > total {
		start = total
	}

	end := start + c.Params.PerPage
	if end > total {
		end = total
	}

	paginatedUsers := users[start:end]

	// Convert to response format.
	userResponses := make([]model.UserResponse, len(paginatedUsers))
	for i, user := range paginatedUsers {
		userResponses[i] = model.UserResponse{
			ID:        user.ID.String(),
			Username:  user.Username,
			Roles:     user.Roles,
			CreatedAt: user.CreatedAt.Format(time.RFC3339),
		}
	}

	response := model.ListUsersResponse{
		Users: userResponses,
		Total: total,
	}

	// Send response.
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(response.ToJson())) //nolint:errcheck,gosec
}

// getUser handles the HTTP request to retrieve a user by its ID.
// Users can get their own profile; admins can get any user profile.
func getUser(c *Context, w http.ResponseWriter, r *http.Request) {
	userID, ok := resourceID(c, c.Params.UserID, "user_id")
	if !ok {
		return
	}

	// Check permissions — admin can get any user, users can get their own profile.
	currentUserID := c.Claims.UserID
	currentRoles := c.Claims.Roles

	if !common.HasAnyRole(currentRoles, model.RoleAdmin) && currentUserID != userID.String() {
		c.SetPermissionError("can only access own profile")
		return
	}

	userSvc, svcOK := svc(c, container.ServiceContainerInterface.GetUserService)
	if !svcOK {
		return
	}

	user, err := userSvc.GetUser(r.Context(), userID)
	if err != nil {
		c.SetNotFound("user")
		return
	}

	// Prepare response.
	response := model.UserResponse{
		ID:        user.ID.String(),
		Username:  user.Username,
		Roles:     user.Roles,
		CreatedAt: user.CreatedAt.Format(time.RFC3339),
	}

	// Send response.
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(response.ToJson())) //nolint:errcheck,gosec
}

// updateUser handles the HTTP request to update a user by its ID.
// Users can update their own profile; admins can update any user.
func updateUser(c *Context, w http.ResponseWriter, r *http.Request) {
	userID, ok := resourceID(c, c.Params.UserID, "user_id")
	if !ok {
		return
	}

	// Parse request body using model type.
	req, err := model.UpdateUserRequestFromJson(r.Body)
	if err != nil {
		c.SetInvalidParam("request body")
		return
	}

	// The old "role" string field was replaced by "roles": [...] -- reject it
	// explicitly rather than silently ignoring it (unknown JSON fields are
	// dropped by default, which would otherwise turn this into a no-op).
	if req.DeprecatedRole != "" {
		c.SetInvalidParam(`the "role" field was replaced by "roles": [...] in this API version`)
		return
	}

	// Validate fields.
	if req.Username != "" && (len(req.Username) < 3 || len(req.Username) > 50) {
		c.SetInvalidParam("username: must be 3-50 characters")
		return
	}
	if req.Password != "" && len(req.Password) < 8 {
		c.SetInvalidParam("password: must be at least 8 characters")
		return
	}

	// Check permissions — admin can update any user, users can update their
	// own profile (except roles).
	currentUserID := c.Claims.UserID
	currentRoles := c.Claims.Roles

	if !common.HasAnyRole(currentRoles, model.RoleAdmin) {
		if currentUserID != userID.String() {
			c.SetPermissionError("can only update own profile")
			return
		}
		// Non-admin users cannot change their roles.
		if req.Roles != nil {
			c.SetPermissionError("cannot change own role")
			return
		}
	}

	userSvc, svcOK := svc(c, container.ServiceContainerInterface.GetUserService)
	if !svcOK {
		return
	}

	// Convert to optional pointer fields.
	var usernamePtr, passwordPtr *string
	if req.Username != "" {
		usernamePtr = &req.Username
	}
	if req.Password != "" {
		passwordPtr = &req.Password
	}

	// Parse caller ID from claims for service-level enforcement.
	callerID, _ := uuid.Parse(c.Claims.UserID)

	// Update user using service. Role validation (allowed values,
	// at-least-one-required, admin-only-can-change) is delegated entirely
	// to UserService.
	if err := userSvc.UpdateUser(r.Context(), userService.UpdateUserRequest{
		UserID:      userID,
		CallerID:    callerID,
		CallerRoles: currentRoles,
		Username:    usernamePtr,
		Password:    passwordPtr,
		Roles:       req.Roles,
	}); err != nil {
		// Role validation errors from UserService ("invalid role: ...",
		// "at least one role is required") are client errors, not server
		// errors -- surface them as 400s instead of masking as 500.
		if strings.Contains(err.Error(), "invalid role") || strings.Contains(err.Error(), "role is required") {
			c.SetInvalidParam(err.Error())
			return
		}
		c.SetInternalError(err)
		return
	}

	// Get updated user for response.
	user, err := userSvc.GetUser(r.Context(), userID)
	if err != nil {
		c.SetInternalError(err)
		return
	}

	// Prepare response.
	response := model.UserResponse{
		ID:        user.ID.String(),
		Username:  user.Username,
		Roles:     user.Roles,
		CreatedAt: user.CreatedAt.Format(time.RFC3339),
	}

	// Send response.
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(response.ToJson())) //nolint:errcheck,gosec

	c.Logger.Printf("User %s updated user %s", currentUserID, userID.String())
}

// deleteUser handles the HTTP request to delete a user by its ID.
// Only users with admin role can delete users.
func deleteUser(c *Context, w http.ResponseWriter, r *http.Request) {
	// Check admin privileges.
	if !common.HasAnyRole(c.Claims.Roles, model.RoleAdmin) {
		c.SetPermissionError("admin role required")
		return
	}

	userID, ok := resourceID(c, c.Params.UserID, "user_id")
	if !ok {
		return
	}

	// Prevent self-deletion.
	if c.Claims.UserID == userID.String() {
		c.SetInvalidParam("cannot delete own account")
		return
	}

	userSvc, svcOK := svc(c, container.ServiceContainerInterface.GetUserService)
	if !svcOK {
		return
	}

	// Check if user exists.
	if _, err := userSvc.GetUser(r.Context(), userID); err != nil {
		c.SetNotFound("user")
		return
	}

	// Delete user.
	if err := userSvc.DeleteUser(r.Context(), userID); err != nil {
		c.SetInternalError(err)
		return
	}

	ReturnStatusOK(w)

	c.Logger.Printf("Admin %s deleted user %s", c.Claims.UserID, userID.String())
}

// loginUser handles user authentication and returns a JWT token.
// This is a public endpoint that does not require prior authentication.
func loginUser(c *Context, w http.ResponseWriter, r *http.Request) {
	// Parse request body.
	req, err := model.LoginRequestFromJson(r.Body)
	if err != nil {
		c.SetInvalidParam("request body")
		return
	}

	// Validate required fields.
	if req.Username == "" || req.Password == "" || req.TOTPCode == "" {
		c.SetInvalidParam("username, password, and totp_code are required")
		return
	}

	// Use service container for authentication.
	authSvc, svcOK := svc(c, container.ServiceContainerInterface.GetAuthenticationService)
	if !svcOK {
		return
	}
	result, err := authSvc.AuthenticateUser(r.Context(), req.Username, req.Password, req.TOTPCode)
	if err != nil {
		c.Logger.Printf("Login failed for user %s: %v", req.Username, err)
		c.SetPermissionError("authentication failed")
		return
	}

	// Prepare response.
	response := model.LoginResponse{
		Token:        result.Token,
		RefreshToken: result.RefreshToken,
		UserID:       result.UserID.String(),
		Username:     result.Username,
		Roles:        result.Roles,
	}

	// Send response. The body carries tokens, so it must never be cached.
	setNoStore(w)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(response.ToJson())) //nolint:errcheck,gosec

	c.Logger.Printf("User %s (ID: %s) logged in successfully with roles %v",
		result.Username, result.UserID.String(), result.Roles)
}

// refreshToken handles the refresh of an access token using a refresh token.
func refreshToken(c *Context, w http.ResponseWriter, r *http.Request) {
	// Parse request body.
	req, err := model.RefreshTokenRequestFromJson(r.Body)
	if err != nil {
		c.SetInvalidParam("request body")
		return
	}

	// Validate required fields.
	if req.RefreshToken == "" {
		c.SetInvalidParam("refresh_token is required")
		return
	}

	// Use service container for token refresh.
	authSvc, svcOK := svc(c, container.ServiceContainerInterface.GetAuthenticationService)
	if !svcOK {
		return
	}
	result, err := authSvc.RefreshAccessToken(r.Context(), req.RefreshToken)
	if err != nil {
		c.Logger.Printf("Token refresh failed: %v", err)
		c.SetPermissionError("token refresh failed")
		return
	}

	// Prepare response.
	response := model.RefreshTokenResponse{
		Token:        result.Token,
		RefreshToken: result.RefreshToken,
		UserID:       result.UserID.String(),
		Username:     result.Username,
		Roles:        result.Roles,
		ExpiresAt:    result.ExpiresAt,
	}

	// Send response. The body carries tokens, so it must never be cached.
	setNoStore(w)
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(response.ToJson())) //nolint:errcheck,gosec

	c.Logger.Printf("Access token refreshed for user %s (ID: %s)",
		result.Username, result.UserID.String())
}

// listUserSessions handles the HTTP request to list all sessions for the current user.
func listUserSessions(c *Context, w http.ResponseWriter, r *http.Request) {
	// Get current user ID from claims.
	userID, err := uuid.Parse(c.Claims.UserID)
	if err != nil {
		c.SetInvalidParam("user_id")
		return
	}

	authSvc, svcOK := svc(c, container.ServiceContainerInterface.GetAuthenticationService)
	if !svcOK {
		return
	}
	sessions, err := authSvc.ListActiveSessions(r.Context(), userID)
	if err != nil {
		c.SetInternalError(err)
		return
	}

	// Convert to response format.
	type sessionItem struct {
		ID         string `json:"id"`
		DeviceInfo string `json:"device_info"`
		IPAddress  string `json:"ip_address"`
		UserAgent  string `json:"user_agent"`
		ExpiresAt  string `json:"expires_at"`
		LastUsedAt string `json:"last_used_at"`
		CreatedAt  string `json:"created_at"`
		Revoked    bool   `json:"revoked"`
	}
	items := make([]sessionItem, len(sessions))
	for i, session := range sessions {
		items[i] = sessionItem{
			ID:         session.ID.String(),
			DeviceInfo: session.DeviceInfo,
			IPAddress:  session.IPAddress,
			UserAgent:  session.UserAgent,
			ExpiresAt:  session.ExpiresAt.Format(time.RFC3339),
			LastUsedAt: session.LastUsedAt.Format(time.RFC3339),
			CreatedAt:  session.CreatedAt.Format(time.RFC3339),
			Revoked:    session.Revoked,
		}
	}

	// Send response using json encoder for non-model map type.
	writeJSON(w, map[string]any{"sessions": items, "total": len(items)})
}

// revokeSession handles the HTTP request to revoke a specific session.
func revokeSession(c *Context, w http.ResponseWriter, r *http.Request) {
	sessionID := c.Params.SessionID

	// Use service container for session revocation.
	authSvc, svcOK := svc(c, container.ServiceContainerInterface.GetAuthenticationService)
	if !svcOK {
		return
	}
	if err := authSvc.RevokeSession(r.Context(), sessionID, "User requested revocation"); err != nil {
		c.SetInternalError(err)
		return
	}

	ReturnStatusOK(w)

	c.Logger.Printf("User %s revoked session %s", c.Claims.UserID, sessionID)
}

// revokeAllSessions handles the HTTP request to revoke all sessions for the current user.
func revokeAllSessions(c *Context, w http.ResponseWriter, r *http.Request) {
	// Get current user ID from claims.
	userID, err := uuid.Parse(c.Claims.UserID)
	if err != nil {
		c.SetInvalidParam("user_id")
		return
	}

	// Use service container for revoking all sessions.
	authSvc, svcOK := svc(c, container.ServiceContainerInterface.GetAuthenticationService)
	if !svcOK {
		return
	}
	if err := authSvc.RevokeAllUserSessions(r.Context(), userID, "User requested revocation of all sessions"); err != nil {
		c.SetInternalError(err)
		return
	}

	ReturnStatusOK(w)

	c.Logger.Printf("User %s revoked all sessions", c.Claims.UserID)
}
