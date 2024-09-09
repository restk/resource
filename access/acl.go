package access

import (
	"context"
)

type ACL interface {
	// HasPermission checks if the authenticated user has permission to this resource
	HasPermission(ctx context.Context, resource string, resourceID any, permission Permission) bool

	// GrantPermissions grants []permissions to the authenticated user
	GrantPermissions(ctx context.Context, resource string, resourceID any, permissions []Permission) error

	// GetIDsWithReadPermission returns all ids that an authenticated user has list permission to for a resource.
	GetIDsWithReadPermission(ctx context.Context, resource string) []any
}
