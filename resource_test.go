package resource

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
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
	return true
}

func (f *StubRBAC) HasRole(ctx context.Context, role string) bool {
	if userRole, ok := ctx.Value("role").(string); ok {
		if userRole != "" {
			return userRole == role
		}
	}

	return false
}

// TestBasic runs a basic test
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
	// user.Preload("Organization", "Role.Permissions")
	// user.BeforeSave(access.PermissionCreate, func(c resourcerouter.Context, user *User) error {
	//
	// })

	user.GenerateRestAPI(unauthRouter, db, openAPI)

	tests := []struct {
		name       string
		method     string
		path       string
		role       string
		body       any
		wantStatus int
		wantStruct any
	}{
		{
			name:       "GET /users (list)",
			method:     http.MethodGet,
			path:       "/user",
			wantStatus: http.StatusOK,
			wantStruct: []User{
				{ID: 1, Name: "Foo", Organization: "OrgA", Role: "Admin", IgnoredField: "A", IgnoredField2: "B", IgnoredFieldUnlessRole: ""},
				{ID: 2, Name: "Bar", Organization: "OrgB", Role: "User", IgnoredField: "A", IgnoredField2: "B", IgnoredFieldUnlessRole: ""},
			},
		},
		{
			name:       "GET /users (list with admin role)",
			method:     http.MethodGet,
			path:       "/user",
			wantStatus: http.StatusOK,
			role:       "Admin",
			wantStruct: []User{
				{ID: 1, Name: "Foo", Organization: "OrgA", Role: "Admin", IgnoredField: "A", IgnoredField2: "B", IgnoredFieldUnlessRole: "C"},
				{ID: 2, Name: "Bar", Organization: "OrgB", Role: "User", IgnoredField: "A", IgnoredField2: "B", IgnoredFieldUnlessRole: "C"},
			},
		},
		{
			name:       "GET /users/:id (detail)",
			method:     http.MethodGet,
			path:       "/user/1",
			wantStatus: http.StatusOK,
			wantStruct: &User{ID: 1, Name: "Foo", Organization: "OrgA", Role: "Admin", IgnoredField: "A", IgnoredField2: "B", IgnoredFieldUnlessRole: ""},
		},
		{
			name:   "PUT /users (create)",
			method: http.MethodPut,
			path:   "/user",
			body: &User{
				ID:                     3,
				Name:                   "George",
				Organization:           "OrgC",
				Role:                   "User",
				IgnoredField:           "THIS SHOULD NOT SET",
				IgnoredField2:          "THIS ALSO SHOULD NOT SET",
				IgnoredFieldUnlessRole: "THIS SHOULD NOT BE SET",
			},
			wantStatus: http.StatusOK,
		},
		{
			name:       "created user should not allow updating ignored field",
			method:     http.MethodGet,
			path:       "/user/3",
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
		},
		{
			name:   "PUT /users (create as admin)",
			method: http.MethodPut,
			path:   "/user",
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
			wantStatus: http.StatusOK,
		},
		{
			name:       "created user if admin should allow updating ignored fields",
			method:     http.MethodGet,
			path:       "/user/4",
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
		},
		{
			name:       "GET /users/:id (should return 404 for non existing user)",
			method:     http.MethodGet,
			path:       "/user/5",
			wantStatus: http.StatusNotFound,
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
