# resource

[![Go Reference](https://pkg.go.dev/badge/github.com/restk/resource.svg)](https://pkg.go.dev/github.com/restk/resource)
[![Go Report Card](https://goreportcard.com/badge/github.com/restk/resource)](https://goreportcard.com/report/github.com/restk/resource)

`resource` is a Go package that simplifies the creation of REST APIs for your database models. It automatically
generates RESTful endpoints with CRUD operations for your GORM models, with support for multiple router frameworks,
access control, and frontend integration.

## Features

- **Automatic CRUD endpoints** for your GORM models
- **Multiple router integrations**:
    - [Chi](https://github.com/go-chi/chi)
    - [Gin](https://github.com/gin-gonic/gin)
- **Flexible access control**:
    - Role-Based Access Control (RBAC)
    - Access Control Lists (ACL)
- **Field-level control** for showing/hiding fields based on user roles
- **Request validation** with customizable validation rules
- **Custom query operations** for filtering, sorting, and pagination
- **Lifecycle hooks** for customizing behavior at different stages
- **Frontend integration** with JavaScript/React hooks
- **OpenAPI integration** for automatic documentation

## Installation

```bash
go get github.com/restk/resource
```

## Quick Start

If you don't need **Role-Based Access Control**, you can omit the RBAC struct.

```go
package main

import (
	"context"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/restk/openapi"
	"github.com/restk/resource"
	"github.com/restk/resource/access"
	ginRouter "github.com/restk/resource/router/gin"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// RBAC should implement the access.RBAC interface.
type RBAC struct{}

func (r *RBAC) HasPermission(ctx context.Context, resource string, permission access.Permission) bool {
	panic("not implemented")
}

func (r *RBAC) HasRole(ctx context.Context, role string) bool {
	panic("not implemented")
}

type User struct {
	gorm.Model
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password,omitempty"`
}

func main() {
	// Setup your database connection.
	db, err := gorm.Open(postgres.Open("host=127.0.0.1 user=db password=db dbname=db port=5433 sslmode=disable"))
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	// Create a Gin router.
	mux := gin.Default()
	group := mux.Group("/")
	router := ginRouter.NewRouter(group)

	// Initialize OpenAPI for docs.
	oapi := openapi.New("Your Project", "1.0.0")

	// Create a resource definition for the User model.
	users := resource.NewResource[User]("users", "id")

	// Specify RBAC to control access to the resource.
	rbac := &RBAC{}
	users.EnableRBAC(rbac)

	// Generate REST API handlers and documentation for this resource.
	if err = users.GenerateRestAPI(router, db, oapi); err != nil {
		log.Fatalf("Failed to generate rest API for user resource: %v", err)
	}

	// Start the server.
	http.ListenAndServe(":8080", mux)
}
```

This example sets up a REST API for a User model with the following endpoints:

- `GET /users` - List all users
- `GET /users/:id` - Get a specific user
- `POST /users` - Create a new user
- `PUT /users/:id` - Update a user
- `DELETE /users/:id` - Delete a user

## Core Concepts

### Resources

A resource represents a database model with RESTful operations. Create a resource using `resource.New[T]()`:

```go
users := resource.NewResource[User]("users", "id")
```

This will use the `users` table, with `id` as the primary key (utilizing the struct's JSON tags).

### Routing

The package supports multiple router frameworks through adapters.

#### Gin Router

```go
package main

import (
  "github.com/gin-gonic/gin"
  ginRouter "github.com/restk/resource/router/gin"
)

func main() {
  mux := gin.Default()
  group := mux.Group("/")
  ginRouter.NewRouter(group)
}
```

#### Chi Router

```go
package main

import (
  "github.com/go-chi/chi/v5"
  chiRouter "github.com/restk/resource/router/chi"
)

func main() {
  mux := chi.NewRouter()
  chiRouter.NewRouter(mux, "")
}
```

### Lifecycle Hooks

Customize behavior at different lifecycle stages:

```go
package main

import (
  "github.com/restk/resource"
  "github.com/restk/resource/access"
  resourcerouter "github.com/restk/resource/router"
  "golang.org/x/crypto/bcrypt"
  "gorm.io/gorm"
)

type User struct {
  gorm.Model
  Name     string `json:"name"`
  Email    string `json:"email"`
  Password string `json:"password,omitempty"`
}

func main() {
  // Create a resource definition for the User model.
  users := resource.NewResource[User]("users", "id")

  users.BeforeSave(access.PermissionCreate, func(ctx resourcerouter.Context, user *User) error {
    // Hash password before creating user.
    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
    if err != nil {
      return err
    }

    user.Password = string(hashedPassword)

    return nil
  })
}
```

### Relationships

Define relationships between resources:

```go
package main

import (
  "github.com/globalcyberalliance/aide/pkg/model"
  "github.com/restk/resource"
  "gorm.io/gorm"
)

type User struct {
  gorm.Model
  Name     string `json:"name"`
  Email    string `json:"email"`
  Password string `json:"password,omitempty"`
}

type UserAPIKey struct {
  gorm.Model
  Key    string `json:"key"`
  UserID uint   `json:"userID"`
}

func main() {
  // Create a resource definition for the User model.
  users := resource.NewResource[User]("users", "id")

  userAPIKeys := resource.NewResource[model.UserAPIKey]("keys", "id")
  userAPIKeys.BelongsTo(users, "UserID")
}

```

When generating the REST endpoints for `userAPIKeys`, they'll be routed under `/users/:userID/keys/:id`.

### Pagination

Clients can request pages using `?page=2` or `?limit=20&offset=40`.

## Frontend Integration

The package includes a React hook for easy frontend integration:

```javascript
// From the javascript/useResource.js file
import {useResource} from '@restk/resource';

function UserList() {
    const {data, loading, error} = useResource('/users');

    if (loading) return <div>Loading...</div>;
    if (error) return <div>Error: {error.message}</div>;

    return (
        <ul>
            {data.map(user => (
                <li key={user.id}>{user.name}</li>
            ))}
        </ul>
    );
}
```

## License

MIT

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.