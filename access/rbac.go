package access

import "context"

type RBAC interface {
	// HasPermission checks if the authenticated user has permission to this resource
	HasPermission(ctx context.Context, resource string, permission Permission) bool
}
