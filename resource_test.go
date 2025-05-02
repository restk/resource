package resource

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/restk/openapi"
	"github.com/restk/resource/access"
	ginrouter "github.com/restk/resource/router/gin"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type Test struct {
	name        string
	method      string
	path        string
	role        string
	permissions []string
	body        any
	wantStatus  int
	wantStruct  any
}

type user struct {
	ID                     int64     `json:"id"`
	Name                   string    `json:"name"`
	Organization           string    `json:"organization"`
	Role                   string    `json:"role"`
	IgnoredField           string    `json:"ignoredField"`
	IgnoredField2          string    `json:"ignoredField2"`
	IgnoredFieldUnlessRole string    `json:"ignoredFieldUnlessRole"`
	Age                    int       `json:"age"`       // for testing >=
	CreatedAt              time.Time `json:"createdAt"` // for testing <=
}

type userAPIKey struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
	Key  string `json:"key"`
}

type stubRBAC struct{}

func (f *stubRBAC) HasPermission(ctx context.Context, resource string, permission access.Permission) bool {
	if permissions, ok := ctx.Value("permissions").([]string); ok {
		for _, userPermission := range permissions {
			if userPermission == resource+":"+string(permission) {
				return true
			}
		}
	}
	return false
}

func (f *stubRBAC) HasRole(ctx context.Context, role string) bool {
	if userRole, ok := ctx.Value("role").(string); ok {
		return userRole == role
	}
	return false
}

func setupTestEnv(t *testing.T) (*gin.Engine, *gorm.DB, []string) {
	t.Helper()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("Failed to open in-memory db: %v", err)
	}
	if err := db.AutoMigrate(&user{}, &userAPIKey{}); err != nil {
		t.Fatalf("Failed to migrate: %v", err)
	}

	db.Create(&user{
		ID: 1, Name: "Foo", Organization: "OrgA", Role: "Admin",
		IgnoredField: "A", IgnoredField2: "B", IgnoredFieldUnlessRole: "C",
		Age:       30,
		CreatedAt: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
	})
	db.Create(&user{
		ID: 2, Name: "Bar", Organization: "OrgB", Role: "User",
		IgnoredField: "A", IgnoredField2: "B", IgnoredFieldUnlessRole: "C",
		Age:       18,
		CreatedAt: time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC),
	})

	gin.SetMode(gin.ReleaseMode)
	router := gin.New()

	router.Use(func(ctx *gin.Context) {
		ctx.Set("gorm_tx", db)
		if role := ctx.GetHeader("Role"); role != "" {
			ctx.Set("role", role)
		}
		if permissions := ctx.GetHeader("Permissions"); permissions != "" {
			ctx.Set("permissions", strings.Split(permissions, ","))
		}
		ctx.Next()
	})

	openAPI := openapi.New("Resource Test API", "v1.0.0")
	r := ginrouter.NewRouter(router.Group("/"))

	userResource := NewResource[user]("user", "id")
	userResource.IgnoreFields([]string{"IgnoredField", "IgnoredField2"}, []access.Permission{
		access.PermissionCreate,
		access.PermissionUpdate,
	})
	userResource.IgnoreFieldsUnlessRole([]string{"IgnoredFieldUnlessRole"}, access.PermissionAll, []string{"Admin"})
	userResource.EnableRBAC(&stubRBAC{})
	userResource.SetFieldQueryOperation("Name", FieldQueryOperationLike)                // so `?name=xyz` uses LIKE
	userResource.SetFieldQueryOperation("Age", FieldQueryOperationGreaterThanEquals)    // so `?age=21` uses >=
	userResource.SetFieldQueryOperation("CreatedAt", FieldQueryOperationLessThanEquals) // so `?createdAt=` uses <=

	if err := userResource.GenerateRestAPI(r, db, openAPI); err != nil {
		t.Fatalf("Failed to generate REST API for user resource: %v", err)
	}

	userPermissions := []string{
		"user:create",
		"user:read",
		"user:update",
		"user:delete",
		"user:list",
	}

	return router, db, userPermissions
}

func TestListUsers(t *testing.T) {
	router, db, userPermissions := setupTestEnv(t)

	db.Create(&user{ID: 100, Name: "bob", Age: 21, Organization: "ex", Role: "User", CreatedAt: time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)})
	db.Create(&user{ID: 101, Name: "bob", Age: 25, Organization: "ex2", Role: "User", CreatedAt: time.Date(2022, 12, 31, 0, 0, 0, 0, time.UTC)})
	db.Create(&user{ID: 102, Name: "charlie", Age: 40, Organization: "ex", Role: "Admin", CreatedAt: time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)})

	tests := []*Test{
		{
			// By default, "IgnoredField" and "IgnoredField2" are not ignored for read => IDs 1 & 2 have "A","B"
			// "IgnoredFieldUnlessRole" is hidden if not Admin
			name:       "GET /users - normal (no role => IgnoredFieldUnlessRole is blank)",
			method:     http.MethodGet,
			path:       "/users",
			wantStatus: http.StatusOK,
			wantStruct: []user{
				// ID=1 & ID=2 from setup, ID=100..102 from above
				// We'll specify all fields, including Age/CreatedAt:
				{ID: 1, Name: "Foo", Organization: "OrgA", Role: "Admin", IgnoredField: "A", IgnoredField2: "B", IgnoredFieldUnlessRole: "", Age: 30, CreatedAt: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)},
				{ID: 2, Name: "Bar", Organization: "OrgB", Role: "User", IgnoredField: "A", IgnoredField2: "B", IgnoredFieldUnlessRole: "", Age: 18, CreatedAt: time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)},
				{ID: 100, Name: "bob", Organization: "ex", Role: "User", IgnoredField: "", IgnoredField2: "", IgnoredFieldUnlessRole: "", Age: 21, CreatedAt: time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)},
				{ID: 101, Name: "bob", Organization: "ex2", Role: "User", IgnoredField: "", IgnoredField2: "", IgnoredFieldUnlessRole: "", Age: 25, CreatedAt: time.Date(2022, 12, 31, 0, 0, 0, 0, time.UTC)},
				{ID: 102, Name: "charlie", Organization: "ex", Role: "Admin", IgnoredField: "", IgnoredField2: "", IgnoredFieldUnlessRole: "", Age: 40, CreatedAt: time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)},
			},
			permissions: userPermissions,
		},
		{
			name:       "GET /users - admin => sees IgnoredFieldUnlessRole='C' for IDs 1 & 2",
			method:     http.MethodGet,
			path:       "/users",
			role:       "Admin",
			wantStatus: http.StatusOK,
			wantStruct: []user{
				// Only difference is IDs 1 & 2 show "C" in IgnoredFieldUnlessRole
				{ID: 1, Name: "Foo", Organization: "OrgA", Role: "Admin", IgnoredField: "A", IgnoredField2: "B", IgnoredFieldUnlessRole: "C", Age: 30, CreatedAt: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)},
				{ID: 2, Name: "Bar", Organization: "OrgB", Role: "User", IgnoredField: "A", IgnoredField2: "B", IgnoredFieldUnlessRole: "C", Age: 18, CreatedAt: time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)},
				{ID: 100, Name: "bob", Organization: "ex", Role: "User", IgnoredField: "", IgnoredField2: "", IgnoredFieldUnlessRole: "", Age: 21, CreatedAt: time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)},
				{ID: 101, Name: "bob", Organization: "ex2", Role: "User", IgnoredField: "", IgnoredField2: "", IgnoredFieldUnlessRole: "", Age: 25, CreatedAt: time.Date(2022, 12, 31, 0, 0, 0, 0, time.UTC)},
				{ID: 102, Name: "charlie", Organization: "ex", Role: "Admin", IgnoredField: "", IgnoredField2: "", IgnoredFieldUnlessRole: "", Age: 40, CreatedAt: time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)},
			},
			permissions: userPermissions,
		},
		{
			// By default, "Name" is now LIKE, but "bob" with no wildcard is effectively "bob" => an exact match
			name:       "GET /users?name=bob => returns ID=100,101 only",
			method:     http.MethodGet,
			path:       "/users?name=bob",
			wantStatus: http.StatusOK,
			wantStruct: []user{
				{ID: 100, Name: "bob", Organization: "ex", Role: "User", IgnoredField: "", IgnoredField2: "", IgnoredFieldUnlessRole: "", Age: 21, CreatedAt: time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)},
				{ID: 101, Name: "bob", Organization: "ex2", Role: "User", IgnoredField: "", IgnoredField2: "", IgnoredFieldUnlessRole: "", Age: 25, CreatedAt: time.Date(2022, 12, 31, 0, 0, 0, 0, time.UTC)},
			},
			permissions: userPermissions,
		},
		{
			name:       "GET /users?name=charlie => returns ID=102",
			method:     http.MethodGet,
			path:       "/users?name=charlie",
			wantStatus: http.StatusOK,
			wantStruct: []user{
				{ID: 102, Name: "charlie", Organization: "ex", Role: "Admin", IgnoredField: "", IgnoredField2: "", IgnoredFieldUnlessRole: "", Age: 40, CreatedAt: time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)},
			},
			permissions: userPermissions,
		},
		{
			name:       "GET /users?organization=ex => returns ID=100,102",
			method:     http.MethodGet,
			path:       "/users?organization=ex",
			wantStatus: http.StatusOK,
			wantStruct: []user{
				{ID: 100, Name: "bob", Organization: "ex", Role: "User", IgnoredField: "", IgnoredField2: "", IgnoredFieldUnlessRole: "", Age: 21, CreatedAt: time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)},
				{ID: 102, Name: "charlie", Organization: "ex", Role: "Admin", IgnoredField: "", IgnoredField2: "", IgnoredFieldUnlessRole: "", Age: 40, CreatedAt: time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)},
			},
			permissions: userPermissions,
		},
		{
			name:       "GET /users?organization=ex2 => returns only ID=101",
			method:     http.MethodGet,
			path:       "/users?organization=ex2",
			wantStatus: http.StatusOK,
			wantStruct: []user{
				{ID: 101, Name: "bob", Organization: "ex2", Role: "User", IgnoredField: "", IgnoredField2: "", IgnoredFieldUnlessRole: "", Age: 25, CreatedAt: time.Date(2022, 12, 31, 0, 0, 0, 0, time.UTC)},
			},
			permissions: userPermissions,
		},
		{
			name:       "GET /users?id=102 => returns only user with ID=102",
			method:     http.MethodGet,
			path:       "/users?id=102",
			wantStatus: http.StatusOK,
			wantStruct: []user{
				{ID: 102, Name: "charlie", Organization: "ex", Role: "Admin", IgnoredField: "", IgnoredField2: "", IgnoredFieldUnlessRole: "", Age: 40, CreatedAt: time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)},
			},
			permissions: userPermissions,
		},
		{
			// Combining queries => name=bob AND organization=ex => only ID=100
			name:       "GET /users?name=bob&organization=ex => returns ID=100 only",
			method:     http.MethodGet,
			path:       "/users?name=bob&organization=ex",
			wantStatus: http.StatusOK,
			wantStruct: []user{
				{ID: 100, Name: "bob", Organization: "ex", Role: "User", IgnoredField: "", IgnoredField2: "", IgnoredFieldUnlessRole: "", Age: 21, CreatedAt: time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)},
			},
			permissions: userPermissions,
		},
		{
			name:       "GET /users?name=%bob% => should find ID=100 & 101 (both have 'bob' in name)",
			method:     http.MethodGet,
			path:       "/users?name=%25bob%25",
			wantStatus: http.StatusOK,
			wantStruct: []user{
				{ID: 100, Name: "bob", Organization: "ex", Role: "User", IgnoredField: "", IgnoredField2: "", IgnoredFieldUnlessRole: "", Age: 21, CreatedAt: time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)},
				{ID: 101, Name: "bob", Organization: "ex2", Role: "User", IgnoredField: "", IgnoredField2: "", IgnoredFieldUnlessRole: "", Age: 25, CreatedAt: time.Date(2022, 12, 31, 0, 0, 0, 0, time.UTC)},
			},
			permissions: userPermissions,
		},

		// 2) GreaterThanEquals => Age >= 20 => IDs 1(30), 100(21), 101(25), 102(40)
		{
			name:       "GET /users?age=20 => should return IDs 1,100,101,102 (age>=20)",
			method:     http.MethodGet,
			path:       "/users?age=20",
			wantStatus: http.StatusOK,
			wantStruct: []user{
				// ID=1 => Age=30
				{ID: 1, Name: "Foo", Organization: "OrgA", Role: "Admin", IgnoredField: "A", IgnoredField2: "B", IgnoredFieldUnlessRole: "", Age: 30, CreatedAt: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)},
				// ID=2 => Age=18 => excluded
				{ID: 100, Name: "bob", Organization: "ex", Role: "User", IgnoredField: "", IgnoredField2: "", IgnoredFieldUnlessRole: "", Age: 21, CreatedAt: time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)},
				{ID: 101, Name: "bob", Organization: "ex2", Role: "User", IgnoredField: "", IgnoredField2: "", IgnoredFieldUnlessRole: "", Age: 25, CreatedAt: time.Date(2022, 12, 31, 0, 0, 0, 0, time.UTC)},
				{ID: 102, Name: "charlie", Organization: "ex", Role: "Admin", IgnoredField: "", IgnoredField2: "", IgnoredFieldUnlessRole: "", Age: 40, CreatedAt: time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)},
			},
			permissions: userPermissions,
		},

		// 3) LessThanEquals => CreatedAt <= ...
		{
			name:       "GET /users?createdAt=2024-12-31T23:59:59Z => returns IDs with CreatedAt <= that date",
			method:     http.MethodGet,
			path:       "/users?createdAt=2024-12-31T23:59:59Z",
			wantStatus: http.StatusOK,
			wantStruct: []user{
				// ID=1 => 2025 => excluded
				// ID=2 => 2023 => included
				{ID: 2, Name: "Bar", Organization: "OrgB", Role: "User", IgnoredField: "A", IgnoredField2: "B", IgnoredFieldUnlessRole: "", Age: 18, CreatedAt: time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)},
				// ID=100 => 2024-06-01 => included
				{ID: 100, Name: "bob", Organization: "ex", Role: "User", IgnoredField: "", IgnoredField2: "", IgnoredFieldUnlessRole: "", Age: 21, CreatedAt: time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)},
				// ID=101 => 2022-12-31 => included
				{ID: 101, Name: "bob", Organization: "ex2", Role: "User", IgnoredField: "", IgnoredField2: "", IgnoredFieldUnlessRole: "", Age: 25, CreatedAt: time.Date(2022, 12, 31, 0, 0, 0, 0, time.UTC)},
				// ID=102 => 2026 => excluded
			},
			permissions: userPermissions,
		},
		{
			name:       "GET /users - pagination page=2, pageSize=1 => second item",
			method:     http.MethodGet,
			path:       "/users?page=2&pageSize=1",
			wantStatus: http.StatusOK,
			wantStruct: []user{
				{ID: 2, Name: "Bar", Organization: "OrgB", Role: "User", IgnoredField: "A", IgnoredField2: "B", IgnoredFieldUnlessRole: "", Age: 18, CreatedAt: time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)},
			},
			permissions: userPermissions,
		},
		{
			name:       "GET /users - forbidden without 'list' permission",
			method:     http.MethodGet,
			path:       "/users",
			wantStatus: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		runTest(t, tt, router)
	}
}

func TestGetUser(t *testing.T) {
	router, _, userPermissions := setupTestEnv(t)

	tests := []*Test{
		{
			name:        "GET /users/1 => existing user with read permission",
			method:      http.MethodGet,
			path:        "/users/1",
			wantStatus:  http.StatusOK,
			wantStruct:  &user{ID: 1, Name: "Foo", Organization: "OrgA", Role: "Admin", IgnoredField: "A", IgnoredField2: "B", IgnoredFieldUnlessRole: "", Age: 30, CreatedAt: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)},
			permissions: userPermissions,
		},
		{
			name:        "GET /users/999 => should be 404",
			method:      http.MethodGet,
			path:        "/users/999",
			wantStatus:  http.StatusNotFound,
			permissions: userPermissions,
		},
		{
			name:       "GET /users/2 => no permissions => forbidden",
			method:     http.MethodGet,
			path:       "/users/2",
			wantStatus: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		runTest(t, tt, router)
	}
}

func TestCreateUser(t *testing.T) {
	router, _, userPermissions := setupTestEnv(t)

	tests := []*Test{
		{
			name:   "PUT /users => create normal user; ignored fields must not be set",
			method: http.MethodPost,
			path:   "/users",
			body: &user{
				ID:                     10,
				Name:                   "George",
				Organization:           "OrgC",
				Role:                   "User",
				IgnoredField:           "SHOULD NOT",
				IgnoredField2:          "SHOULD NOT",
				IgnoredFieldUnlessRole: "No Admin => No Set",
				Age:                    18,
				CreatedAt:              time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC),
			},
			wantStatus:  http.StatusOK,
			permissions: userPermissions,
		},
		{
			name:        "GET /users/10 => verify create success & ignored fields are blank",
			method:      http.MethodGet,
			path:        "/users/10",
			permissions: userPermissions,
			wantStatus:  http.StatusOK,
			wantStruct: &user{
				ID:                     10,
				Name:                   "George",
				Organization:           "OrgC",
				Role:                   "User",
				IgnoredField:           "",
				IgnoredField2:          "",
				IgnoredFieldUnlessRole: "",
				Age:                    18,
				CreatedAt:              time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC),
			},
		},
		{
			name:   "PUT /users => create user as admin => IgnoredFieldUnlessRole is set, others remain ignored",
			method: http.MethodPost,
			path:   "/users",
			role:   "Admin",
			body: &user{
				ID:                     11,
				Name:                   "GeorgeAdmin",
				Organization:           "OrgC",
				Role:                   "User",
				IgnoredField:           "StillIgnore",
				IgnoredField2:          "StillIgnore",
				IgnoredFieldUnlessRole: "SetForAdmin",
				Age:                    18,
				CreatedAt:              time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC),
			},
			wantStatus:  http.StatusOK,
			permissions: userPermissions,
		},
		{
			name:        "GET /users/11 => confirm partial set for admin create",
			method:      http.MethodGet,
			path:        "/users/11",
			role:        "Admin",
			permissions: userPermissions,
			wantStatus:  http.StatusOK,
			wantStruct: &user{
				ID:                     11,
				Name:                   "GeorgeAdmin",
				Organization:           "OrgC",
				Role:                   "User",
				IgnoredField:           "",
				IgnoredField2:          "",
				IgnoredFieldUnlessRole: "SetForAdmin",
				Age:                    18,
				CreatedAt:              time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC),
			},
		},
		{
			// If the resource or DB does not enforce unique ID, this might not fail.
			// But let's assume there's a constraint and it fails or triggers a 500.
			name:        "PUT /users => create user with existing ID => likely 500 or conflict",
			method:      http.MethodPost,
			path:        "/users",
			permissions: userPermissions,
			body: &user{
				ID:   1, // already exists
				Name: "ConflictName",
			},
			wantStatus: http.StatusInternalServerError,
		},
		{
			name:   "PUT /users => no create permission => forbidden",
			method: http.MethodPost,
			path:   "/users",
			body: &user{
				ID:   12,
				Name: "ShouldFail",
			},
			wantStatus: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		runTest(t, tt, router)
	}
}

func TestUpdateUser(t *testing.T) {
	router, db, userPermissions := setupTestEnv(t)

	if err := db.Create(&user{ID: 20, Name: "UpdateMe", Organization: "OrgU", Role: "User"}).Error; err != nil {
		t.Fatalf("failed to create user #20: %v", err)
	}

	tests := []*Test{
		{
			name:   "PUT /users/20 => normal update ignoring some fields",
			method: http.MethodPut,
			path:   "/users/20",
			body: &user{
				ID:                     20,
				Name:                   "UpdatedName",
				Organization:           "UpdatedOrg",
				Role:                   "User",
				IgnoredField:           "SHOULDNOTSET",
				IgnoredField2:          "SHOULDNOTSET",
				IgnoredFieldUnlessRole: "NOTADMIN => NOTSET",
			},
			wantStatus:  http.StatusOK,
			permissions: userPermissions,
		},
		{
			name:        "GET /users/20 => verify update success",
			method:      http.MethodGet,
			path:        "/users/20",
			permissions: userPermissions,
			wantStatus:  http.StatusOK,
			wantStruct: &user{
				ID:                     20,
				Name:                   "UpdatedName",
				Organization:           "UpdatedOrg",
				Role:                   "User",
				IgnoredField:           "",
				IgnoredField2:          "",
				IgnoredFieldUnlessRole: "",
			},
		},
		{
			name:   "PUT /users/20 => admin update => can set IgnoredFieldUnlessRole",
			method: http.MethodPut,
			path:   "/users/20",
			role:   "Admin",
			body: &user{
				ID:                     20,
				Name:                   "AdminChangedName",
				Organization:           "UpdatedOrg",
				Role:                   "User",
				IgnoredField:           "",
				IgnoredField2:          "",
				IgnoredFieldUnlessRole: "AdminValue",
			},
			wantStatus:  http.StatusOK,
			permissions: userPermissions,
		},
		{
			name:        "GET /users/20 => confirm admin update",
			method:      http.MethodGet,
			path:        "/users/20",
			role:        "Admin",
			permissions: userPermissions,
			wantStatus:  http.StatusOK,
			wantStruct: &user{
				ID:                     20,
				Name:                   "AdminChangedName",
				Organization:           "UpdatedOrg",
				Role:                   "User",
				IgnoredField:           "",
				IgnoredField2:          "",
				IgnoredFieldUnlessRole: "AdminValue",
			},
		},
		/*
			{
				// The resource's update logic might do an insert if not found, or might fail.
				// We assume it fails with a 404 or 500 for a missing record. Adjust as needed.
				name:        "PUT /users/999 => update non-existing => expecting not found or error",
				method:      http.MethodPut,
				path:        "/users/999",
				permissions: userPermissions,
				body: &user{
					Name:         "MissingRecord",
					Organization: "Nope",
				},
				wantStatus: http.StatusNotFound,
			},
		*/
		{
			name:   "PUT /users/20 => forbidden with no permissions",
			method: http.MethodPut,
			path:   "/users/20",
			body: &user{
				Name: "NoPermissions",
			},
			wantStatus: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		runTest(t, tt, router)
	}
}

func TestPatchUser(t *testing.T) {
	router, db, userPermissions := setupTestEnv(t)

	// Create user #30 to patch
	if err := db.Create(&user{ID: 30, Name: "PatchMe", Organization: "OrgPatch", Role: "User", Age: 21, CreatedAt: time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)}).Error; err != nil {
		t.Fatalf("failed to create user #30: %v", err)
	}

	tests := []*Test{
		{
			name:   "PATCH /users/30 => normal user => fields remain ignored",
			method: http.MethodPatch,
			path:   "/users/30",
			body: &user{
				Name:                   "PatchedName",
				IgnoredField:           "SHOULDNOT",
				IgnoredField2:          "SHOULDNOT",
				IgnoredFieldUnlessRole: "NOTADMIN",
			},
			permissions: userPermissions,
			wantStatus:  http.StatusOK,
		},
		{
			name:        "GET /users/30 => confirm patch success",
			method:      http.MethodGet,
			path:        "/users/30",
			permissions: userPermissions,
			wantStatus:  http.StatusOK,
			wantStruct: &user{
				ID:                     30,
				Name:                   "PatchedName",
				Organization:           "OrgPatch",
				Role:                   "User",
				IgnoredField:           "",
				IgnoredField2:          "",
				IgnoredFieldUnlessRole: "",
				Age:                    21,
				CreatedAt:              time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC),
			},
		},
		{
			name:        "PATCH /users/30 => admin => can set 'IgnoredFieldUnlessRole'",
			method:      http.MethodPatch,
			path:        "/users/30",
			role:        "Admin",
			permissions: userPermissions,
			body: &user{
				IgnoredFieldUnlessRole: "AdminPatchedValue",
			},
			wantStatus: http.StatusOK,
		},
		{
			name:        "GET /users/30 => confirm admin patch",
			method:      http.MethodGet,
			path:        "/users/30",
			role:        "Admin",
			permissions: userPermissions,
			wantStatus:  http.StatusOK,
			wantStruct: &user{
				ID:                     30,
				Name:                   "PatchedName",
				Organization:           "OrgPatch",
				Role:                   "User",
				IgnoredField:           "",
				IgnoredField2:          "",
				IgnoredFieldUnlessRole: "AdminPatchedValue",
				Age:                    21,
				CreatedAt:              time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC),
			},
		},
		{
			name:   "PATCH /users/30 => forbidden no permissions",
			method: http.MethodPatch,
			path:   "/users/30",
			body: &user{
				Name: "Nope",
			},
			wantStatus: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		runTest(t, tt, router)
	}
}

func TestDeleteUser(t *testing.T) {
	router, db, userPermissions := setupTestEnv(t)

	// Create user #40 to delete
	if err := db.Create(&user{ID: 40, Name: "ToDelete", Organization: "OrgDel", Role: "User"}).Error; err != nil {
		t.Fatalf("failed to create user #40: %v", err)
	}

	tests := []*Test{
		{
			name:        "DELETE /users/40 => normal user w/ permission can delete",
			method:      http.MethodDelete,
			path:        "/users/40",
			permissions: userPermissions,
			wantStatus:  http.StatusOK,
		},
		{
			// Now that #40 is deleted, a subsequent GET should 404
			name:        "GET /users/40 => 404 after delete",
			method:      http.MethodGet,
			path:        "/users/40",
			permissions: userPermissions,
			wantStatus:  http.StatusNotFound,
		},
		{
			// Attempt to re-delete => 404 if already gone
			name:        "DELETE /users/40 => no record => 404",
			method:      http.MethodDelete,
			path:        "/users/40",
			permissions: userPermissions,
			wantStatus:  http.StatusNotFound,
		},
		{
			// If we try to delete an existing user but have no permission, 407 forbidden
			name:       "DELETE /users/2 => no permissions => forbidden",
			method:     http.MethodDelete,
			path:       "/users/2",
			wantStatus: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		runTest(t, tt, router)
	}
}

func runTest(t *testing.T, tt *Test, router *gin.Engine) {
	t.Run(tt.name, func(t *testing.T) {
		var reqBody []byte
		if tt.body != nil {
			jsonData, err := json.Marshal(tt.body)
			if err != nil {
				t.Fatalf("failed to marshal body: %v", err)
			}
			reqBody = jsonData
		}

		req, err := http.NewRequest(tt.method, tt.path, bytes.NewReader(reqBody))
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")

		if tt.role != "" {
			req.Header.Set("Role", tt.role)
		}
		if len(tt.permissions) > 0 {
			req.Header.Set("Permissions", strings.Join(tt.permissions, ","))
		}

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != tt.wantStatus {
			t.Errorf("Wanted status %d, got %d, \nRaw Body: %s", tt.wantStatus, w.Code, w.Body.String())
		}

		if tt.wantStruct != nil {
			gotVal := newValueOfType(tt.wantStruct)
			if err := json.Unmarshal(w.Body.Bytes(), gotVal); err != nil {
				t.Errorf("Failed to unmarshal response: %v\nResponse Body: %s", err, w.Body.String())
				return
			}

			if !reflect.DeepEqual(deref(gotVal), deref(tt.wantStruct)) {
				t.Errorf(
					"\nResponse mismatch\nGot:  %#v\nWant: %#v\nRaw Body: %s",
					deref(gotVal),
					deref(tt.wantStruct),
					w.Body.String(),
				)
			}
		}
	})
}

// newValueOfType returns a pointer to a new zero value of the same type as x.
// This helps us unmarshal into the correct type during tests.
func newValueOfType(x any) interface{} {
	t := reflect.TypeOf(x)
	if t.Kind() == reflect.Ptr {
		return reflect.New(t.Elem()).Interface()
	}
	return reflect.New(t).Interface()
}

func deref(x any) any {
	rv := reflect.ValueOf(x)
	if rv.Kind() == reflect.Ptr && !rv.IsNil() {
		return rv.Elem().Interface()
	}
	return x
}
