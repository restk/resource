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
	ID           int64  `json:"id"`
	Name         string `json:"name"`
	Organization string `json:"organization"`
	Role         string `json:"role"`
	IgnoredField string `json:"ignoredField"`
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
	return true
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

	db.Create(&User{ID: 1, Name: "Foo", Organization: "OrgA", Role: "Admin", IgnoredField: "IGNORE"})
	db.Create(&User{ID: 2, Name: "Bar", Organization: "OrgB", Role: "User", IgnoredField: "IGNORE"})

	router := gin.Default()
	router.Use(func(ctx *gin.Context) {
		ctx.Set("gorm_tx", db)
		ctx.Next()
	})
	unauthGroup := router.Group("/")
	// authGroup := router.Group("/")

	unauthRouter := ginrouter.NewRouter(unauthGroup)
	// authRouter := ginrouter.NewRouter(authGroup)

	user := NewResource[User]("user", "id")
	user.IgnoreFields([]string{"IgnoredField"}, access.PermissionAll)
	// user.Preload("Organization", "Role.Permissions")
	// user.BeforeSave(access.PermissionCreate, func(c resourcerouter.Context, user *User) error {
	//
	// })

	user.GenerateRestAPI(unauthRouter, db, openAPI)

	tests := []struct {
		name       string
		method     string
		path       string
		body       any
		wantStatus int
		wantStruct any
	}{
		{
			name:       "GET /users (list)",
			method:     http.MethodGet,
			path:       "/user",
			wantStatus: http.StatusOK,
		},
		{
			name:       "GET /users/:id (detail)",
			method:     http.MethodGet,
			path:       "/user/1",
			wantStatus: http.StatusOK,
		},
		{
			name:   "PUT /users (create)",
			method: http.MethodPut,
			path:   "/user",
			body: &User{
				ID:           3,
				Name:         "George",
				Organization: "OrgC",
				Role:         "User",
				IgnoredField: "THIS SHOULD NOT UPDATE",
			},
			wantStatus: http.StatusOK,
		},
		{
			name:       "created user should not allow updating ignored field",
			method:     http.MethodGet,
			path:       "/user/3",
			wantStatus: http.StatusOK,
			wantStruct: &User{
				ID:           3,
				Name:         "George",
				Organization: "OrgC",
				Role:         "User",
				IgnoredField: "",
			},
		},
		{
			name:       "GET /users/:id (should return 404 for non existing user)",
			method:     http.MethodGet,
			path:       "/user/4",
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

				if !reflect.DeepEqual(gotVal, tt.wantStruct) {
					t.Errorf(
						"\nResponse mismatch\nGot:  %#v\nWant: %#v\nRaw Body: %s",
						gotVal,
						tt.wantStruct,
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
