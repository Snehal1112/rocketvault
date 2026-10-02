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

package users

import (
	"fmt"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"rocketvault/common"
	"rocketvault/internal/container"
	userService "rocketvault/internal/services/users"
	"rocketvault/model"
)

// updateCmd represents the update command
var updateCmd = &cobra.Command{
	Use:   "update <id>",
	Short: "Update user information",
	Long: `Update a user's username, password, or role by UUID. At least one of
--new-username, --new-password, or --new-role is required.

Accessible by the account's own owner, or by a caller with the admin role.
Changing --new-role additionally requires the admin role, even when updating
your own account, and is rejected unless the value is one of the built-in
roles (admin, user, secrets_manager, crypto_manager, certificate_manager,
service_account). There is no vault scoping: user accounts are global, not
a vault-scoped resource.`,
	Example: `  # Change your own password
  rocketvault users update <user-id> --new-password <password>

  # Change another user's role (requires admin role)
  rocketvault users update <user-id> --new-role crypto_manager`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		claims, ok := ctx.Value(common.ClaimsKey).(*model.Claims)
		if !ok {
			return fmt.Errorf("unauthorized: missing authentication claims")
		}

		// Get service container from context
		serviceContainer, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
		if !ok || serviceContainer == nil {
			return fmt.Errorf("service container not available in context")
		}

		id, err := uuid.Parse(args[0])
		if err != nil {
			logger := serviceContainer.GetLogger()
			logger.LogAuditError(claims.UserID.String(), "update_user", "failed", fmt.Sprintf("invalid user ID: %s", err), err)
			return fmt.Errorf("invalid user ID: %w", err)
		}

		if claims.UserID != id && !common.HasAnyRole(claims.Roles, model.RoleAdmin) {
			logger := serviceContainer.GetLogger()
			logger.LogAuditError(claims.UserID.String(), "update_user", "failed", "forbidden: cannot update other users", nil)
			return fmt.Errorf("forbidden: cannot update other users")
		}

		// Read flags directly so tests work without viper binding.
		newUsername, _ := cmd.Flags().GetString("new-username")
		newPassword, _ := cmd.Flags().GetString("new-password")
		roles, _ := cmd.Flags().GetStringArray("new-role")

		if newUsername == "" && newPassword == "" && len(roles) == 0 {
			logger := serviceContainer.GetLogger()
			logger.LogAuditError(claims.UserID.String(), "update_user", "failed", "at least one field must be provided", nil)
			return fmt.Errorf("at least one field (new-username, new-password, new-role) must be provided")
		}

		// Only admins may change roles — including changing their own role.
		if len(roles) > 0 && !common.HasAnyRole(claims.Roles, model.RoleAdmin) {
			logger := serviceContainer.GetLogger()
			logger.LogAuditError(claims.UserID.String(), "update_user", "failed", "forbidden: only admins can change roles", nil)
			return fmt.Errorf("forbidden: only admins can change roles")
		}

		// Use user service for update.
		userSvc := serviceContainer.GetUserService()

		// Convert string values to pointers for optional fields.
		var usernamePtr, passwordPtr *string
		if newUsername != "" {
			usernamePtr = &newUsername
		}
		if newPassword != "" {
			passwordPtr = &newPassword
		}

		// GetStringArray returns a non-nil empty slice when --new-role is absent,
		// but UpdateUserRequest.Roles treats non-nil as an explicit (even if
		// empty) role-change request. Convert the absent-flag case to nil so a
		// plain update that doesn't touch roles isn't misclassified as one.
		var rolesArg []string
		if len(roles) > 0 {
			rolesArg = roles
		}

		result, err := userSvc.UpdateUser(ctx, userService.UpdateUserRequest{
			UserID:      id,
			CallerID:    claims.UserID,
			CallerRoles: claims.Roles,
			Username:    usernamePtr,
			Password:    passwordPtr,
			Roles:       rolesArg,
		})
		if err != nil {
			logger := serviceContainer.GetLogger()
			logger.LogAuditError(claims.UserID.String(), "update_user", "failed", fmt.Sprintf("failed to update user: %s", err), err)
			return fmt.Errorf("failed to update user: %w", err)
		}

		logger := serviceContainer.GetLogger()
		logger.LogAuditInfo(claims.UserID.String(), "update_user", "success", fmt.Sprintf("user updated: %s", id))
		out := cmd.OutOrStdout()
		fmt.Fprintf(out, "User %s updated successfully\n", id) //nolint:errcheck
		// The enrollment URL is a credential. It goes to stdout once and never to the log.
		if result != nil && result.TOTPEnrollmentURL != "" {
			fmt.Fprintf(out, "TOTP Secret: %s\n"+ //nolint:errcheck
				"\nThis account had no second factor. Add this TOTP secret to your authenticator app now.\n"+
				"It is shown only once, and local password login requires it.\n",
				result.TOTPEnrollmentURL)
		}
		return nil
	},
}

// InitUsersUpdate initializes the update command for users
// and adds it to the users command. It also sets up the necessary flags
// and configuration settings. The update command allows users to update
// information about a specific user by username. It requires the username
// to be specified.
//
// parameters:
//
// - usersCmd: The parent command under which the update command will be added.
//
// This function is called in the main function of the application to set up the command structure.
// It is part of the Cobra library, which is used for creating command-line applications in Go.
// The update command is a subcommand of the users command and is used to update user information.
// It is part of the Cobra library, which is used for creating command-line applications in Go.
func InitUsersUpdate(usersCmd *cobra.Command) {
	usersCmd.AddCommand(updateCmd)

	updateCmd.Flags().String("new-username", "", "New username for the user")
	updateCmd.Flags().String("new-password", "", "New password for the user")
	updateCmd.Flags().StringArray("new-role", []string{}, "New role(s) for the user (repeatable, e.g. --new-role admin --new-role secrets_manager)")
}
