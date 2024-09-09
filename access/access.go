package access

type Permission string

var (
	PermissionCreate Permission = "create"
	PermissionRead   Permission = "read"
	PermissionUpdate Permission = "update"
	PermissionDelete Permission = "delete"
	PermissionList   Permission = "list"
)

var PermissionAll []Permission = []Permission{
	PermissionCreate,
	PermissionRead,
	PermissionUpdate,
	PermissionDelete,
	PermissionList,
}
