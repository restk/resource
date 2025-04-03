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

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/restk/openapi"
	"github.com/restk/resource/access"
	ginrouter "github.com/restk/resource/router/gin"
	"gorm.io/gorm"
)

type User struct {
	ID                     int64  `json:"id"`
	Name                   string `json:"name"`
	Organization           string `json:"organization"`
	Role                   string `json:"role"`
	IgnoredField           string `json:"ignoredField"`
	IgnoredField2          string `json:"ignoredField2"`
	IgnoredFieldUnlessRole string `json:"ignoredFieldUnlessRole"`
}

type UserAPIKey struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
	Key  string `json:"key"`
}

type StubRBAC struct{}

func (f *StubRBAC) HasPermission(ctx context.Context, resource string, permission access.Permission) bool {
	if permissions, ok := ctx.Value("permissions").([]string); ok {
		for _, userPermission := range permissions {
			if userPermission == resource+":"+string(permission) {
				return true
			}
		}
	}

	return false
}

func (f *StubRBAC) HasRole(ctx context.Context, role string) bool {
	if userRole, ok := ctx.Value("role").(string); ok {
		if userRole != "" {
			return userRole == role
		}
	}

	return false
}

// TestBasic runs basic sanity checks for pkg/resource
func TestBasic(t *testing.T) {
	openAPI := openapi.New("Resource Test API", "v1.0.0")

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("Failed to open in-memory db: %v", err)
	}

	if err := db.AutoMigrate(&User{}, &UserAPIKey{}); err != nil {
		t.Fatalf("Failed to migrate: %v", err)
	}

	db.Create(&User{ID: 1, Name: "Foo", Organization: "OrgA", Role: "Admin", IgnoredField: "A", IgnoredField2: "B", IgnoredFieldUnlessRole: "C"})
	db.Create(&User{ID: 2, Name: "Bar", Organization: "OrgB", Role: "User", IgnoredField: "A", IgnoredField2: "B", IgnoredFieldUnlessRole: "C"})

	router := gin.Default()
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
	unauthGroup := router.Group("/")
	// authGroup := router.Group("/")

	unauthRouter := ginrouter.NewRouter(unauthGroup)
	// authRouter := ginrouter.NewRouter(authGroup)

	user := NewResource[User]("user", "id")
	user.IgnoreFields([]string{"IgnoredField", "IgnoredField2"}, []access.Permission{
		access.PermissionCreate,
		access.PermissionUpdate,
	})
	user.IgnoreFieldsUnlessRole([]string{"IgnoredFieldUnlessRole"}, access.PermissionAll, []string{"Admin"})
	user.EnableRBAC(&StubRBAC{})
	user.GenerateRestAPI(unauthRouter, db, openAPI)

	userPermissions := []string{
		"user:create",
		"user:read",
		"user:update",
		"user:delete",
		"user:list",
	}

	tests := []struct {
		name        string
		method      string
		path        string
		role        string
		permissions []string
		body        any
		wantStatus  int
		wantStruct  any
	}{
		{
			name:       "GET /users (list)",
			method:     http.MethodGet,
			path:       "/users",
			wantStatus: http.StatusOK,
			wantStruct: []User{
				{ID: 1, Name: "Foo", Organization: "OrgA", Role: "Admin", IgnoredField: "A", IgnoredField2: "B", IgnoredFieldUnlessRole: ""},
				{ID: 2, Name: "Bar", Organization: "OrgB", Role: "User", IgnoredField: "A", IgnoredField2: "B", IgnoredFieldUnlessRole: ""},
			},
			permissions: userPermissions,
		},
		{
			name:       "GET /users (list with admin role)",
			method:     http.MethodGet,
			path:       "/users",
			wantStatus: http.StatusOK,
			wantStruct: []User{
				{ID: 1, Name: "Foo", Organization: "OrgA", Role: "Admin", IgnoredField: "A", IgnoredField2: "B", IgnoredFieldUnlessRole: "C"},
				{ID: 2, Name: "Bar", Organization: "OrgB", Role: "User", IgnoredField: "A", IgnoredField2: "B", IgnoredFieldUnlessRole: "C"},
			},
			role:        "Admin",
			permissions: userPermissions,
		},
		{
			name:        "GET /users/:id (detail)",
			method:      http.MethodGet,
			path:        "/users/1",
			wantStatus:  http.StatusOK,
			wantStruct:  &User{ID: 1, Name: "Foo", Organization: "OrgA", Role: "Admin", IgnoredField: "A", IgnoredField2: "B", IgnoredFieldUnlessRole: ""},
			permissions: userPermissions,
		},
		{
			name:   "PUT /users (create)",
			method: http.MethodPut,
			path:   "/users",
			body: &User{
				ID:                     3,
				Name:                   "George",
				Organization:           "OrgC",
				Role:                   "User",
				IgnoredField:           "THIS SHOULD NOT SET",
				IgnoredField2:          "THIS ALSO SHOULD NOT SET",
				IgnoredFieldUnlessRole: "THIS SHOULD NOT BE SET",
			},
			wantStatus:  http.StatusOK,
			permissions: userPermissions,
		},
		{
			name:       "created user should not allow updating ignored field",
			method:     http.MethodGet,
			path:       "/users/3",
			wantStatus: http.StatusOK,
			wantStruct: &User{
				ID:                     3,
				Name:                   "George",
				Organization:           "OrgC",
				Role:                   "User",
				IgnoredField:           "",
				IgnoredField2:          "",
				IgnoredFieldUnlessRole: "",
			},
			permissions: userPermissions,
		},
		{
			name:   "PUT /users (create as admin)",
			method: http.MethodPut,
			path:   "/users",
			role:   "Admin",
			body: &User{
				ID:                     4,
				Name:                   "George",
				Organization:           "OrgC",
				Role:                   "User",
				IgnoredField:           "THIS SHOULD NOT SET",
				IgnoredField2:          "THIS ALSO SHOULD NOT SET",
				IgnoredFieldUnlessRole: "THIS SHOULD BE SET",
			},
			wantStatus:  http.StatusOK,
			permissions: userPermissions,
		},
		{
			name:       "created user if admin should allow updating ignored fields",
			method:     http.MethodGet,
			path:       "/users/4",
			role:       "Admin",
			wantStatus: http.StatusOK,
			wantStruct: &User{
				ID:                     4,
				Name:                   "George",
				Organization:           "OrgC",
				Role:                   "User",
				IgnoredField:           "",
				IgnoredField2:          "",
				IgnoredFieldUnlessRole: "THIS SHOULD BE SET",
			},
			permissions: userPermissions,
		},
		{
			name:        "GET /users/:id (should return 404 for non existing user)",
			method:      http.MethodGet,
			path:        "/users/5",
			wantStatus:  http.StatusNotFound,
			permissions: userPermissions,
		},
		{
			name:       "GET /users/:id (should return 407 Forbidden without permissions)",
			method:     http.MethodGet,
			path:       "/users/4",
			wantStatus: http.StatusForbidden,
		},
		{
			name:   "PUT /users/ (should return 407 Forbidden without permissions)",
			method: http.MethodPut,
			path:   "/users",
			body: &User{
				ID:                     5,
				Name:                   "George",
				Organization:           "OrgC",
				Role:                   "User",
				IgnoredField:           "",
				IgnoredField2:          "",
				IgnoredFieldUnlessRole: "",
			},
			wantStatus: http.StatusForbidden,
		},
		{
			name:   "PUT /users/4 (should return 407 Forbidden without permissions)",
			method: http.MethodPut,
			path:   "/users/4",
			body: &User{
				ID:                     4,
				Name:                   "George",
				Organization:           "OrgC",
				Role:                   "User",
				IgnoredField:           "",
				IgnoredField2:          "",
				IgnoredFieldUnlessRole: "",
			},
			wantStatus: http.StatusForbidden,
		},
		{
			name:   "PATCH /users/4 (should return 407 Forbidden without permissions)",
			method: http.MethodPatch,
			path:   "/users/4",
			body: &User{
				ID:                     4,
				Name:                   "George",
				Organization:           "OrgC",
				Role:                   "User",
				IgnoredField:           "",
				IgnoredField2:          "",
				IgnoredFieldUnlessRole: "",
			},
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "DELETE /users/4 (should return 407 Forbidden without permissions)",
			method:     http.MethodDelete,
			path:       "/users/4",
			wantStatus: http.StatusForbidden,
		},
	}
	for _, tt := range tests {
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
				t.Errorf("Wanted status %d, got %d", tt.wantStatus, w.Code)
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
}

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
