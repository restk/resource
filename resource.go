package resource

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/restk/openapi"
	"github.com/restk/resource/access"
	"github.com/restk/resource/pkg/pluralize"
	"github.com/restk/resource/router"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
	"gorm.io/gorm"
)

var (
	caser           = cases.Title(language.English)
	pluralizeClient = pluralize.NewClient()
	SchemaRegistry  = openapi.NewMapRegistry("#/components/schemas/", openapi.DefaultSchemaNamer)

	FieldQueryOperationEquals            FieldQueryOperation = "="
	FieldQueryOperationLike              FieldQueryOperation = "LIKE"
	FieldQueryOperationGreaterThan       FieldQueryOperation = ">"
	FieldQueryOperationGreaterThanEquals FieldQueryOperation = ">="
	FieldQueryOperationLessThan          FieldQueryOperation = "<"
	FieldQueryOperationLessThanEquals    FieldQueryOperation = "<="
	FieldQueryOperationNotEqual          FieldQueryOperation = "!="

	ErrRecordNotFound = errors.New("record not found")
)

var querySuffixToOperator = map[string]FieldQueryOperation{
	"Gt":   FieldQueryOperationGreaterThan,
	"Gte":  FieldQueryOperationGreaterThanEquals,
	"Lt":   FieldQueryOperationLessThan,
	"Lte":  FieldQueryOperationLessThanEquals,
	"Ne":   FieldQueryOperationNotEqual,
	"Like": FieldQueryOperationLike,
}

type FieldQueryOperation string

// UserError is a custom error type that means this error will be shown to the user. The user gets a JSON containing
// the code and the message instead of an InternalServerError.
type UserError struct {
	Code    int
	Message string
}

func (e *UserError) Error() string {
	return fmt.Sprintf("user error (code: %v, message: %v)", e.Code, e.Message)
}

// NewUserError is a custom error type that means this message will be sent to the user instead of an
// InternalServerError (default behaviour.) You should return a UserError in hooks such as BeforeSave / AfterSave / etc
// when you want the user to receive the error.
func NewUserError(code int, message string) error {
	return &UserError{
		Code:    code,
		Message: message,
	}
}

// S is used to easily craft JSON responses, see ResourceNotFound.
type S map[string]any

var (
	BadRequest = func(ctx router.Context) {
		ctx.WriteJSON(http.StatusBadRequest, S{"code": 400, "message": "Invalid request"})
	}
	CustomUserError = func(ctx router.Context, userError *UserError) {
		ctx.WriteJSON(http.StatusInternalServerError, S{"code": userError.Code, "message": userError.Message})
	}
	ForbiddenAccess = func(ctx router.Context) {
		ctx.WriteJSON(http.StatusForbidden, S{"code": 403, "message": "Forbidden access to resource"})
	}
	InternalServerError = func(ctx router.Context, err error) {
		// TODO: accept a logger or find another way to return this outside of Resource.
		fmt.Println("internal server error", err)
		ctx.WriteJSON(http.StatusInternalServerError, S{"code": 500, "message": "Internal Server Error"})
	}
	InvalidInput = func(ctx router.Context, msg string) {
		ctx.WriteJSON(http.StatusBadRequest, S{"code": 400, "message": msg})
	}
	NoResults = func(ctx router.Context) {
		ctx.Writer().WriteHeader(http.StatusNoContent)
	}
	ResourceNotFound = func(ctx router.Context) {
		ctx.WriteJSON(http.StatusNotFound, S{"code": 404, "message": "Resource not found"})
	}
)

type ResourceInterface interface {
	Name() string
	PluralName() string
	PrimaryField() string
	PrimaryFieldURLParam() string
}

type Field struct {
	Name        string
	StructField reflect.StructField
}

type FieldIgnoreRule struct {
	UnlessRoles []string
}

// Resource represents a single REST resource, such as /users. It seeks to auto generate all REST endpoints, API documentation, database fetching,
// database updating, validation (of input), access control (RBAC/ACL) and ownership from a single struct T.
//
// We currently support gorm as a data layer and gin as a REST endpoint. It is easy to extend and change the
// data layer and REST endpoint by implementing the corresponding interfaces. (see pkg/gorm and pkg/gin for an implementation) TODO: make this a fact.
//
// The purpose of Resource is the ability to handle the below problems:
//
// # Data Access
//
// Query:
//
// 1) Query a resource by number, string, fuzzy matching, and date ranges. We support a basic query interface using query params such as /users/?id=3&name="%thoma%"&start_time=""&end_time=""
//
// Fetching:
//
// 1) Fetch a resource (by number, string, fuzzy matching (strings) and date ranges)
// 2) Fetch an array of resources (by number, string, and date ranges and paginate the results)
//
// Creating and Updating:
// 1) Create a resource
// 2) Update a resource or update a list of resources
//
// Deleting:
// 1) Delete a resource
// 2) Delete a list of resources
//
// Access Control:
// 1) Support RBAC
// # Error Codes
//
// 400 Bad Request - This means that client-side input fails validation.
// 401 Unauthorized - This means the user isn't not authorized to access a resource. It usually returns when the user isn't authenticated.
// 403 Forbidden - This means the user is authenticated, but it's not allowed to access a resource.
// 404 Not Found - This indicates that a resource is not found.
// 500 Internal server error - This is a generic server error. It probably shouldn't be thrown explicitly.
// 502 Bad Gateway - This indicates an invalid response from an upstream server.
// 503 Service Unavailable - This indicates that something unexpected happened on server side (It can be anything like server overload, some parts of the system failed, etc.).
type Resource[T any] struct {
	name         string
	pluralName   string // name in plural form, if name is 'user', then this would be 'users'. This should only be used for doc purposes
	path         string
	tags         []string
	primaryField string
	// validator    func(objectToValidate T) bool
	// hasAccess    func(c router.Context, resource string, action AccessAction) bool
	hasOwnership func(c router.Context, resource string, obj *T) bool
	getID        func(obj *T) any
	table        any
	preload      []string
	schema       *openapi.Schema

	// Fields.
	fields                    []*Field
	queryOperatorByField      map[string]FieldQueryOperation
	queryParamByAlias         map[string]string
	columnByField             map[string]string
	fieldByJSON               map[string]string
	ignoredFieldsByPermission map[access.Permission]map[string]*FieldIgnoreRule

	// Hooks.
	beforeSave         map[access.Permission][]func(ctx context.Context, obj *T) error
	afterSave          map[access.Permission][]func(ctx context.Context, obj *T) error
	beforeDelete       []func(ctx context.Context, obj *T) error
	afterDelete        []func(ctx context.Context, obj *T) error
	beforeResponse     map[access.Permission]func(ctx context.Context, obj *T) (any, error)
	beforeListResponse func(ctx context.Context, obj []*T) (any, error)

	// Pagination.
	maxPageSize int
	pageSize    int
	maxLimit    int

	// Access control.
	rbac access.RBAC

	acl                 access.ACL
	aclGrantPermissions []access.Permission

	// Relationships.
	belongsTo      ResourceInterface
	belongsToField string

	// API overrides.
	get    func(c router.Context)
	put    func(c router.Context)
	post   func(c router.Context)
	patch  func(c router.Context)
	delete func(c router.Context)

	disableCreate bool
	disableRead   bool
	disableUpdate bool
	disableDelete bool
	disableList   bool

	disableCreateDocs bool
	disableReadDocs   bool
	disableUpdateDocs bool
	disableDeleteDocs bool
	disableListDocs   bool

	// Other.
	maxInputBytes int64
	txContextKey  string
}

// NewResource creates a new resource. Name is expected to be singular and we attempt to make it plural for doc
// purposes. To override the plural name, call .Plural("").
func NewResource[T any](name string, primaryField string) *Resource[T] {
	var table T

	pluralizedName := pluralizeClient.Pluralize(name, 0, false)
	r := &Resource[T]{
		name:                      name,
		pluralName:                pluralizedName,
		path:                      pluralizedName,
		primaryField:              primaryField,
		table:                     table,
		tags:                      []string{caser.String(pluralizedName)},
		hasOwnership:              DefaultHasOwnership[T],
		beforeSave:                make(map[access.Permission][]func(ctx context.Context, obj *T) error, 0),
		afterSave:                 make(map[access.Permission][]func(ctx context.Context, obj *T) error, 0),
		beforeDelete:              make([]func(ctx context.Context, obj *T) error, 0),
		afterDelete:               make([]func(ctx context.Context, obj *T) error, 0),
		beforeResponse:            make(map[access.Permission]func(ctx context.Context, obj *T) (any, error), 0),
		queryOperatorByField:      make(map[string]FieldQueryOperation, 0),
		queryParamByAlias:         make(map[string]string, 0),
		columnByField:             make(map[string]string, 0),
		preload:                   make([]string, 0),
		fields:                    make([]*Field, 0),
		ignoredFieldsByPermission: make(map[access.Permission]map[string]*FieldIgnoreRule, 0),
		pageSize:                  10,
		maxPageSize:               250,
		maxLimit:                  250,
		maxInputBytes:             10 * 1024 * 1024,
		txContextKey:              "gorm_tx",
		// hasAccess:            DefaultHasAccess[T],
	}

	typeOf := reflect.TypeOf(table)
	visibleFields := reflect.VisibleFields(typeOf)
	r.schema = openapi.SchemaFromType(SchemaRegistry, typeOf)

	for _, field := range visibleFields {
		r.fields = append(r.fields, &Field{
			Name:        field.Name,
			StructField: field,
		})
	}

	if !r.isFieldNameValid(primaryField) {
		panic("field " + primaryField + " does not exist for resource when calling NewResource()" + name)
	}

	return r
}

// Name returns the resource name.
func (r *Resource[T]) Name() string {
	return r.name
}

// PluralName returns the plural name.
func (r *Resource[T]) PluralName() string {
	return r.pluralName
}

// Path sets path for the resource. By default path is the Plural name of a resource, this allows you to override that.
func (r *Resource[T]) Path(path string) {
	r.path = path
}

// Plural sets the plural name for this resource.
func (r *Resource[T]) Plural(pluralName string) {
	r.pluralName = pluralName
}

// AddTag adds a tag.
func (r *Resource[T]) AddTag(tag string) {
	r.tags = append(r.tags, tag)
}

// Tags replaces all tags, see AddTag to add a single tag.
func (r *Resource[T]) Tags(tags []string) {
	r.tags = tags
}

// PrimaryField returns the name of the primary field. The primary field is what is used for REST endpoints such as /users/:id (in this case, id, is the primary field).
func (r *Resource[T]) PrimaryField() string {
	return r.primaryField
}

// EnableRBAC enables Role Based Access Control for a resource. You are expected to implement the access.RBAC interface (see pkg/access/examples). This provides broad access control
// over a resource. If you also want fine-grained control, see EnableACL()
//
// Note: You can EnableRBAC() and EnableACL() at the same time.
func (r *Resource[T]) EnableRBAC(rbac access.RBAC) {
	r.rbac = rbac
}

// EnableACL enables fine-grained access control over a resource. You are expected to implement the access.ACL interface (see pkg/access/examples) and pass it as the first argument.
// grantPermissionsOnCreate is the permissions that will be granted to a resource for the authenticated user on a CREATE.
// f is expected to return the ID of the resource which is what is passed to the acl.ACL interface to verify the authenticated user has access to the resource with that id
//
// Example 1 (where a user (id=1) has sole access to resource user_settings (id=2))
//
// resource_ownership_table (example, actual implementation is up to access.ACL implementation)
//
// owner_id  resource       resource_id    permissions
// --------------------------------------------------------------------------
// 1         user_settings  2              create/read/write/delete/list
//
//	userSettings.EnableACL(acl, access.PermissionAll, func(userSettings *UserSettings) (selfID any, ownerID any) {
//	    return userSettings.ID, userSettings.UserID
//	})
//
// Example 2 (where two users (id=1) and (id=2) have access to the same playlist (id=1) with different permissions)
//
// resource_ownership_table (example, actual implementation is up to access.ACL implementation)
//
// owner_id  resource       resource_id    permissions
// --------------------------------------------------------------------------
// 1         playlist       1              create/read/write/delete/list
// 2         playlist       1              read/list
//
//	playlist.EnableACL(acl, access.PermissionAll, func(playlist *Playlist) (selfID any, ownerID any) {
//	    return playlist.ID, userSettings.UserID
//	})
//
// Note: You can EnableRBAC() and EnableACL() at the same time.
func (r *Resource[T]) EnableACL(acl access.ACL, grantPermissionsOnCreate []access.Permission, f func(obj *T) (selfID any)) {
	r.acl = acl
	r.aclGrantPermissions = grantPermissionsOnCreate
	r.getID = f
}

// PrimaryFieldURLParam returns the URL param for the primary field. This must be unique across resources.
func (r *Resource[T]) PrimaryFieldURLParam() string {
	urlParam := r.name + strings.ToUpper(string(r.primaryField[0]))
	if len(r.name) >= 2 {
		urlParam += r.primaryField[1:]
	}

	return urlParam
}

// SetHasAccess sets a function to check if the caller has access to this resource. You are expected to return true
// if the caller has access and false if they do not. Even if a user has access to a resource, they may not own
// the resource.
/*
func (r *Resource[T]) SetHasAccess(f func(c router.Context, resource string, action AccessAction) bool) {
	r.hasAccess = f
}
*/

// BelongsTo defines that this Resource belongs to T. This will make it so the primary field of the resource we belong to is used in all fetch queries.
//
// Example:
//
// users := Resource[model.User]("users", "id")
// posts := Resource[model.UserPost]("posts", "id")
//
// posts.BelongsTo(users, "UserID")
//
// /users/:userID/posts
// /users/:userID/posts/:postID
//
// All fetches to posts will now include the primary field (userID) in the query.
func (r *Resource[T]) BelongsTo(resource ResourceInterface, field string) {
	r.belongsTo = resource
	r.belongsToField = field

	// First tag is automatically generated when a resource is created, if this resource belongs to another resource we
	// add it to the belongs to resource tag instead.
	if len(r.tags) > 0 {
		r.tags[0] = caser.String(resource.PluralName())
	}
}

// SetHasOwnership sets the function which checks if the resource is owned by the caller making the request.
func (r *Resource[T]) SetHasOwnership(f func(c router.Context, resource string, obj *T) bool) {
	r.hasOwnership = f
}

// Preload loads a resources associations. For example:
//
// Preload("Organization.Roles", "Keys") would load User.Organization, User.Organization.Roles and User.Keys.
func (r *Resource[T]) Preload(association ...string) {
	r.preload = append(r.preload, association...)
}

// BeforeSave adds a function that will be called before a save of a Resource. You can add multiple functions.
func (r *Resource[T]) BeforeSave(permission access.Permission, f func(ctx context.Context, obj *T) error) {
	if _, ok := r.beforeSave[permission]; !ok {
		r.beforeSave[permission] = make([]func(ctx context.Context, obj *T) error, 0)
	}
	r.beforeSave[permission] = append(r.beforeSave[permission], f)
}

// AfterSave is called after the resource is saved to the database successfully. You can add multiple functions.
func (r *Resource[T]) AfterSave(permission access.Permission, f func(ctx context.Context, obj *T) error) {
	if _, ok := r.afterSave[permission]; !ok {
		r.afterSave[permission] = make([]func(ctx context.Context, obj *T) error, 0)
	}

	r.afterSave[permission] = append(r.afterSave[permission], f)
}

// BeforeResponse is called right before we respond to the client and allows you to return a custom response instead
// of the default response.
func (r *Resource[T]) BeforeResponse(permission access.Permission, f func(ctx context.Context, obj *T) (any, error)) {
	r.beforeResponse[permission] = f
}

// BeforeListResponse is called right before we respond to the client and allows you to return a custom response instead
// of the default response.
func (r *Resource[T]) BeforeListResponse(permission access.Permission, f func(ctx context.Context, obj []*T) (any, error)) {
	r.beforeListResponse = f
}

// BeforeDelete is called right before a resource is deleted.
func (r *Resource[T]) BeforeDelete(f func(ctx context.Context, obj *T) error) {
	r.beforeDelete = append(r.beforeDelete, f)
}

// AfterDelete is called after a resource is deleted successfully.
func (r *Resource[T]) AfterDelete(f func(ctx context.Context, obj *T) error) {
	r.afterDelete = append(r.afterDelete, f)
}

// SetFieldQueryOperation sets the query operation for a field
//
// Resource[schema.User].SetFieldQueryOperation("EndTime", FieldOperationLessThanEqual).
func (r *Resource[T]) SetFieldQueryOperation(field string, op FieldQueryOperation) {
	r.queryOperatorByField[field] = op
}

// SetQueryParamAlias sets a specific query param as an alias
//
// Example:
//
//	queryParam: dateGte
//	alias: from
//
// Passing from="2021-12-24 15:04:05" will do a dateGte="2021-12-24 15:04:05"
func (r *Resource[T]) SetQueryParamAlias(queryParam string, alias string) {
	r.queryParamByAlias[alias] = queryParam
}

// DefaultHasOwnership returns true by default and does not handle ownership. Call SetHasOwnership() to add ownership.
func DefaultHasOwnership[T any](c router.Context, resource string, obj *T) bool {
	return true
}

// isFieldNameValid checks if the field exists on the Resource[T].
func (r *Resource[T]) isFieldNameValid(name string) bool {
	for _, field := range r.fields {
		if strings.EqualFold(field.StructField.Name, name) {
			return true
		}
	}

	return false
}

// IgnoreAllFields ignores all fields.
func (r *Resource[T]) IgnoreAllFields() *Resource[T] {
	for _, field := range r.fields {
		r.IgnoreField(field.Name, access.PermissionAll)
	}

	return r
}

// AllowFields will allow the given fields for a specific permission. By default all fields are allowed, call
// IgnoreAllFields() first.
func (r *Resource[T]) AllowFields(fields []string, permissions []access.Permission) *Resource[T] {
	for _, field := range fields {
		r.AllowField(field, permissions)
	}

	return r
}

// AllowField will allow a field for a specific permission. By default Fields are allowed, call IgnoreAllFields() first.
func (r *Resource[T]) AllowField(field string, permissions []access.Permission) *Resource[T] {
	for _, permission := range permissions {
		if ignoredFields, ok := r.ignoredFieldsByPermission[permission]; ok {
			delete(ignoredFields, field)
		}
	}

	return r
}

// IgnoreFields will ignore a list of fields for a specific permission. You can ignore a field for: access.PermissionRead, access.PermissionWrite, access.PermissionList, access.PermissionCreate.
func (r *Resource[T]) IgnoreFields(fields []string, accessMethod []access.Permission) *Resource[T] {
	for _, field := range fields {
		r.IgnoreFieldUnlessRole(field, accessMethod, []string{})
	}

	return r
}

// IgnoreField will ignore a field for a specific permission. You can ignore a field for: access.PermissionRead, access.PermissionWrite, access.PermissionList, access.PermissionCreate.
func (r *Resource[T]) IgnoreField(field string, accessMethod []access.Permission) *Resource[T] {
	return r.IgnoreFieldUnlessRole(field, accessMethod, []string{})
}

// IgnoreFieldsUnlessRole calls IgnoreFieldUnlessRole for each given field.
func (r *Resource[T]) IgnoreFieldsUnlessRole(fields []string, accessMethod []access.Permission, roles []string) *Resource[T] {
	for _, field := range fields {
		r.IgnoreFieldUnlessRole(field, accessMethod, roles)
	}

	return r
}

// IgnoreFieldUnlessRole will ignore the field for all operations unless the requester has the roles provided. This can allow specific fields, such as join fields, to be ignored
// but they can still be updated by admins in tools.
//
// This requires rbac to be enabled, else this will ignore fields for all roles.
func (r *Resource[T]) IgnoreFieldUnlessRole(field string, accessMethod []access.Permission, roles []string) *Resource[T] {
	for _, permission := range accessMethod {
		if _, ok := r.ignoredFieldsByPermission[permission]; !ok {
			r.ignoredFieldsByPermission[permission] = make(map[string]*FieldIgnoreRule, 0)
		}
		ignoredFields := r.ignoredFieldsByPermission[permission]
		if _, ok := ignoredFields[field]; ok {
			return r
		}

		ignoredFields[field] = &FieldIgnoreRule{
			UnlessRoles: roles,
		}
	}

	return r
}

// retrieveQueryFieldOperator retrieves the query operator for a field.
func (r *Resource[T]) retrieveQueryFieldOperator(field string) FieldQueryOperation {
	if op, ok := r.queryOperatorByField[field]; ok {
		return op
	}

	return FieldQueryOperationEquals
}

// generateFieldByJSON returns a field name by its JSON tag.
func generateFieldByJSON(resource any) map[string]string {
	fieldByJSON := make(map[string]string)

	typeOf := reflect.TypeOf(resource)
	fields := reflect.VisibleFields(typeOf)

	for _, field := range fields {
		jsonTag := ""
		if j := field.Tag.Get("json"); j != "" {
			if n := strings.Split(j, ",")[0]; n != "" {
				jsonTag = n
			}
		}

		if jsonTag != "" {
			fieldByJSON[jsonTag] = field.Name
		}
	}

	return fieldByJSON
}

// generateColumnByField generates a mapping (field -> column name) for a resource T.
func generateColumnByField(db *gorm.DB, resource any) (map[string]string, error) {
	columnByField := make(map[string]string, 0)

	// Look up the belongs to field using gorm statement parsing so we can do a where clause lookup.
	stmt := &gorm.Statement{DB: db}
	if err := stmt.Parse(resource); err != nil {
		return nil, errors.Errorf("failed to parse gorm model")
	}

	typeOf := reflect.TypeOf(resource)
	fields := reflect.VisibleFields(typeOf)
	for _, field := range fields {
		if field.Anonymous {
			continue
		}

		gormField := stmt.Schema.LookUpField(field.Name)
		if gormField == nil {
			return nil, errors.Errorf("failed to find field " + field.Name)
		}
		columnByField[field.Name] = gormField.DBName
	}

	return columnByField, nil
}

// parseFieldFromParam takes a URL param (which is always a string), such as :userId, and finds that field on a resource.
// It then converts the URL param (string) to the fields proper type (string -> uint if the field is a uint)
// It also returns the fields column name so it can be used in where clauses.
func parseFieldFromParam(db *gorm.DB, param string, resource any, field string) (string, any, error) {
	if resource == nil {
		return "", nil, errors.Errorf("resource is nil when calling parseFieldFromParam")
	}

	// Look up the belongs to field using gorm statement parsing so we can do a where clause lookup.
	stmt := &gorm.Statement{DB: db}
	if err := stmt.Parse(resource); err != nil {
		return "", nil, errors.Errorf("failed to parse gorm model for parseFieldFromParam")
	}

	gormField := stmt.Schema.LookUpField(field)
	if gormField == nil {
		return "", nil, errors.Errorf("failed to find field" + field)
	}

	columnForWhereClause := gormField.DBName
	var parsedValue any
	switch gormField.StructField.Type.Kind() {
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		parsedUintValue, err := strconv.ParseUint(param, 10, 64)
		if err != nil {
			return "", nil, errors.Wrapf(err, "failed to parseFieldFromParam, not a uint")
		}
		parsedValue = parsedUintValue
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		parsedIntValue, err := strconv.ParseInt(param, 10, 64)
		if err != nil {
			return "", nil, errors.Wrapf(err, "failed to parseFieldFromParam, not an int")
		}
		parsedValue = parsedIntValue
	case reflect.String:
		parsedValue = param
	case reflect.Struct:
		// If it's time.Time, parse the string into a time.Time.
		if gormField.StructField.Type == reflect.TypeOf(time.Time{}) {
			parsedTime, err := time.Parse(time.RFC3339, param)
			if err != nil {
				return "", nil, errors.Wrapf(err, "failed to parse time param")
			}
			parsedValue = parsedTime
		} else {
			return "", nil, errors.Errorf("struct type not supported")
		}
	default:
		// Unhandled type.
		return "", nil, errors.Errorf("type not supported, if you are a developer, you can add a new type")
	}

	return columnForWhereClause, parsedValue, nil
}

// TXContextKey overrides the transaction key used for queries, by default this is "gorm_tx".
func (r *Resource[T]) TXContextKey(txKey string) {
	r.txContextKey = txKey
}

// tx returns a transaction from the resource or panics.
func (r *Resource[T]) tx(ctx context.Context) *gorm.DB {
	// TODO: when implementing the generic model interface, we should have ways for the user to determine where the tx
	// comes from instead of hard pulling it from the context.
	val := ctx.Value(r.txContextKey)
	if tx, ok := val.(*gorm.DB); ok {
		return tx
	}

	// Not being able to find a transaction inside the context is a critical error and everything should stop.
	panic("unable to find tx in context")
}

// omitIgnoredFields calls Omit on gorm to ignore fields.
func (r *Resource[T]) omitIgnoredFields(ctx context.Context, permission access.Permission, table *gorm.DB) {
	var omitFields []string
	if ignoredFields, ok := r.ignoredFieldsByPermission[permission]; ok {
		for fieldName, field := range ignoredFields {
			hasException := false
			if r.rbac != nil {
				for _, role := range field.UnlessRoles {
					if r.rbac.HasRole(ctx, role) {
						hasException = true
						break
					}
				}
			}

			if !hasException {
				omitFields = append(omitFields, fieldName)
			}
		}
	}

	if len(omitFields) > 0 {
		table.Omit(omitFields...)
	}
}

// DELETE overrides the DELETE method with f.
func (r *Resource[T]) DELETE(f func(c router.Context)) {
	r.delete = f
}

// GET overrides the GET method with f.
func (r *Resource[T]) GET(f func(c router.Context)) {
	r.get = f
}

// PATCH overrides the PATCH method with f.
func (r *Resource[T]) PATCH(f func(c router.Context)) {
	r.patch = f
}

// POST overrides the POST method with f.
func (r *Resource[T]) POST(f func(c router.Context)) {
	r.post = f
}

// PUT overrides the PUT method with f.
func (r *Resource[T]) PUT(f func(c router.Context)) {
	r.put = f
}

// Disable disables a list of access methods.
func (r *Resource[T]) Disable(permissions []access.Permission) {
	for _, permission := range permissions {
		switch permission {
		case access.PermissionCreate:
			r.DisableCreate()
		case access.PermissionDelete:
			r.DisableDelete()
		case access.PermissionList:
			r.DisableList()
		case access.PermissionRead:
			r.DisableRead()
		case access.PermissionUpdate:
			r.DisableUpdate()
		}
	}
}

// DisableDocs disables API doc generation for a list of access methods.
func (r *Resource[T]) DisableDocs(permissions []access.Permission) {
	for _, permission := range permissions {
		switch permission {
		case access.PermissionCreate:
			r.DisableCreateDocs()
		case access.PermissionDelete:
			r.DisableDeleteDocs()
		case access.PermissionList:
			r.DisableListDocs()
		case access.PermissionRead:
			r.DisableReadDocs()
		case access.PermissionUpdate:
			r.DisableUpdateDocs()
		}
	}
}

// DisableCreate disables creation on this resource.
func (r *Resource[T]) DisableCreate() {
	r.disableCreate = true
}

// DisableCreateDocs disables create doc generation
func (r *Resource[T]) DisableCreateDocs() {
	r.disableCreateDocs = true
}

// DisableDelete disables deletes on this resource.
func (r *Resource[T]) DisableDelete() {
	r.disableDelete = true
}

// DisableDeleteDocs disables deletes docs on this resource.
func (r *Resource[T]) DisableDeleteDocs() {
	r.disableDeleteDocs = true
}

// DisableList disables listing on this resource.
func (r *Resource[T]) DisableList() {
	r.disableList = true
}

// DisableListDocs disables listing docs  on this resource.
func (r *Resource[T]) DisableListDocs() {
	r.disableListDocs = true
}

// DisableRead disables reads on this resource.
func (r *Resource[T]) DisableRead() {
	r.disableRead = true
}

// disableReadDocs disables read docs on this resource.
func (r *Resource[T]) DisableReadDocs() {
	r.disableReadDocs = true
}

// DisableUpdate disables updates on this resource.
func (r *Resource[T]) DisableUpdate() {
	r.disableUpdate = true
}

// DisableUpdate disables updates on this resource.
func (r *Resource[T]) DisableUpdateDocs() {
	r.disableUpdateDocs = true
}

// DisableAllDocs disables all docs, see DisableDocs() and individual doc disabling such as DisableCreateDocs()
func (r *Resource[T]) DisableAllDocs() {
	r.DisableDocs(access.PermissionAll)
}

// IsValid validates that the value v is a valid resource.
func (r *Resource[T]) IsValid(v any) []error {
	pb := openapi.NewPathBuffer([]byte(""), 0)
	res := &openapi.ValidateResult{}
	openapi.Validate(SchemaRegistry, r.schema, pb, openapi.ModeWriteToServer, v, res)

	return res.Errors
}

// MaxInputBytes sets the maximum bytes when reading a resource from a client. 10MB by default.
func (r *Resource[T]) MaxInputBytes(maxInputBytes int64) {
	r.maxInputBytes = maxInputBytes
}

func valueOfType(t reflect.Type) any {
	if t.Kind() == reflect.Ptr {
		return reflect.New(t.Elem()).Interface()
	}
	return reflect.New(t).Interface()
}

// GenerateRestAPI generates REST API endpoints for a resource. This also handles RBAC and makes sure the calling user
// has permission for an action on a resource.
//
// GET /resources                   -> returns a paginated list of resources (with a max amount per page) and filters
// GET /resources/:primaryField     -> returns a single resource by the primary field
// POST /resources                  -> creates a single resource
// PUT /resources/:primaryField     -> updates a single resource by its primary field
// PATCH /resources/:primaryField   -> patches a single resource by its primary field
// DELETE /resources/:primaryField  -> deletes a single resource by its primary field
func (r *Resource[T]) GenerateRestAPI(routes router.Router, db *gorm.DB, openAPI *openapi.Builder) error {
	// Generate column names.
	// TODO: add a storage interface instead of using gorm directly so Resource can be used for any other storage medium
	groupPath := ""
	permissionName := r.name
	if r.belongsTo != nil {
		groupPath = path.Join(r.belongsTo.PluralName(), "{"+r.belongsTo.PrimaryFieldURLParam()+"}")
		permissionName = r.belongsTo.Name() + "-" + r.name
	}

	// resourceTypeForDoc is used to give type information to OpenAPI
	// TODO: we define this twice, once as a pointer and one that is not, we should unify everything to support both
	//  instead of declaring both
	var resourceTypeForDoc *T
	var resource T

	columnByField, err := generateColumnByField(db, resource)
	if err != nil {
		return err
	}

	r.columnByField = columnByField
	r.fieldByJSON = generateFieldByJSON(resource)

	if !r.disableCreate {
		r.generateCreateEndpoint(routes, groupPath, permissionName, resourceTypeForDoc, openAPI)
	}

	if !r.disableDelete {
		r.generateDeleteEndpoint(routes, groupPath, permissionName, resourceTypeForDoc, openAPI)
	}

	if !r.disableList {
		r.generateListEndpoint(routes, groupPath, permissionName, resourceTypeForDoc, openAPI)
	}

	if !r.disableRead {
		r.generateReadEndpoint(routes, groupPath, permissionName, resourceTypeForDoc, openAPI)
	}

	if !r.disableUpdate {
		r.generateUpdateEndpoint(routes, groupPath, permissionName, resourceTypeForDoc, openAPI)
		r.generateUpdatePatchEndpoint(routes, groupPath, permissionName, resourceTypeForDoc, openAPI)
	}

	return nil
}

// Create creates a resource.
func (r *Resource[T]) Create(ctx context.Context, resource *T) error {
	if err := r.runBeforeSaveHooks(ctx, resource, access.PermissionCreate); err != nil {
		return err
	}

	tx := r.tx(ctx)
	table := tx.Model(resource)
	r.omitIgnoredFields(ctx, access.PermissionCreate, table)

	if result := table.Create(&resource); result.Error != nil {
		return result.Error
	}

	if r.acl != nil {
		if err := r.acl.GrantPermissions(ctx, r.name, r.getID(resource), r.aclGrantPermissions); err != nil {
			return err
		}
	}

	if err := r.runAfterSaveHooks(ctx, resource, access.PermissionCreate); err != nil {
		return err
	}

	return nil
}

func (r *Resource[T]) generateCreateEndpoint(routes router.Router, groupPath string, permissionName string, resourceTypeForDoc *T, openAPI *openapi.Builder) {
	routePath := path.Join(routes.BasePath(), groupPath, r.path)

	if !r.disableCreateDocs {
		createDoc := openAPI.Register(&openapi.Operation{
			OperationID: "create" + r.name,
			Method:      http.MethodPost,
			Path:        routePath,
			Tags:        r.tags,
		}).Summary("Creates a new " + r.name).
			Description("Creates a new " + r.name + ". If the resource already exists, this returns an error.")

		createDoc.Request().Body(resourceTypeForDoc)
	}

	routes.POST(routePath, func(ctx router.Context) {
		if r.rbac != nil && !r.rbac.HasPermission(ctx, permissionName, access.PermissionCreate) {
			ForbiddenAccess(ctx)
			return
		}

		resource, err := r.parseAndValidateRequestBody(ctx)
		if err != nil {
			return
		}

		if err := r.Create(ctx, resource); err != nil {
			r.sendError(ctx, err)
			return
		}

		r.sendResponse(ctx, resource, access.PermissionCreate)
	})
}

// Delete deletes a resource by id
func (r *Resource[T]) Delete(ctx context.Context, primaryId any) error {
	whereClause := fmt.Sprintf("%v = ?", r.primaryField)
	whereArgs := []any{primaryId}
	tx := r.tx(ctx)

	var resource *T
	if result := tx.Model(r.table).Where(whereClause, whereArgs...).First(&resource); result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return ErrRecordNotFound
		}
		return result.Error
	}

	for _, beforeDeleteFunc := range r.beforeDelete {
		if err := beforeDeleteFunc(ctx, resource); err != nil {
			return err
		}
	}

	var deletedResource *T
	if err := tx.Model(r.table).Where(whereClause, whereArgs...).Delete(&deletedResource).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrRecordNotFound
		}
	}

	for _, afterDeleteFunc := range r.afterDelete {
		if err := afterDeleteFunc(ctx, resource); err != nil {
			return err
		}
	}

	return nil
}

func (r *Resource[T]) generateDeleteEndpoint(routes router.Router, groupPath string, permissionName string, resourceTypeForDoc *T, openAPI *openapi.Builder) {
	routePath := path.Join(routes.BasePath(), groupPath, r.path, "{"+r.PrimaryFieldURLParam()+"}")

	if !r.disableDeleteDocs {
		deleteDoc := openAPI.Register(&openapi.Operation{
			OperationID: "delete" + r.name,
			Method:      http.MethodDelete,
			Path:        routePath,
			Tags:        r.tags,
		}).
			Summary("Deletes a single " + r.name).
			Description("Deletes a single " + r.name + ".")
		deleteDoc.Request().PathParam(r.PrimaryFieldURLParam(), r.name).Description("Primary ID of the " + r.name).Required(true)
	}

	routes.DELETE(routePath, func(ctx router.Context) {
		if r.rbac != nil && !r.rbac.HasPermission(ctx, permissionName, access.PermissionDelete) {
			ForbiddenAccess(ctx)
			return
		}

		tx := r.tx(ctx)
		whereClause, whereArgs, err := r.buildResourceWhereClause(ctx, resourceTypeForDoc)
		if err != nil {
			return
		}

		// First load the resource and verify ownership.
		var resource *T
		if result := tx.Model(r.table).Where(whereClause, whereArgs...).First(&resource); result.Error != nil {
			if errors.Is(result.Error, gorm.ErrRecordNotFound) {
				ResourceNotFound(ctx)
				return
			}
			InternalServerError(ctx, result.Error)
			return
		}

		if r.acl != nil && !r.acl.HasPermission(ctx, permissionName, r.getID(resource), access.PermissionDelete) {
			ForbiddenAccess(ctx)
			return
		}

		param := ctx.Param(r.PrimaryFieldURLParam())
		_, primaryFieldValue, err := parseFieldFromParam(r.tx(ctx), param, resourceTypeForDoc, r.primaryField)
		if err != nil {
			r.sendError(ctx, err)
			return
		}

		if err := r.Delete(ctx, primaryFieldValue); err != nil {
			r.sendError(ctx, err)
			return

		}

		r.sendResponse(ctx, resource, access.PermissionDelete)
	})
}

func (r *Resource[T]) generateListEndpoint(routes router.Router, groupPath string, permissionName string, resourceTypeForDoc *T, openAPI *openapi.Builder) {
	routePath := path.Join(routes.BasePath(), groupPath, r.path)

	if !r.disableListDocs {
		listDoc := openAPI.Register(&openapi.Operation{
			OperationID: "list" + r.name,
			Method:      http.MethodGet,
			Path:        routePath,
			Tags:        r.tags,
		}).Summary("Gets a list of " + r.pluralName).
			Description("Get a list of " + r.pluralName + " filtering via query params. This endpoint also supports pagination")

		for _, field := range r.fields {
			if _, ok := r.ignoredFieldsByPermission[access.PermissionList][field.Name]; ok {
				continue
			}

			name := field.Name
			if j := field.StructField.Tag.Get("json"); j != "" {
				if n := strings.Split(j, ",")[0]; n != "" {
					name = n
				}
			}

			if prop, ok := r.schema.Properties[name]; ok {
				listDoc.Request().QueryParam(name, valueOfType(field.StructField.Type)).Description(prop.Description)
			}
		}
	}

	routes.GET(routePath, func(ctx router.Context) {
		if r.rbac != nil && !r.rbac.HasPermission(ctx, permissionName, access.PermissionList) {
			ForbiddenAccess(ctx)
			return
		}

		tx := r.tx(ctx)
		queryParams := ctx.QueryParams()

		limit, offset, err := r.getPaginationParams(queryParams)
		if err != nil {
			InvalidInput(ctx, err.Error())
			return
		}

		table := tx.Model(r.table)
		r.omitIgnoredFields(ctx, access.PermissionList, table)

		// If this is a grouped resource, we add the primary field of the resource this belongs to.
		if r.belongsTo != nil {
			param := ctx.Param(r.belongsTo.PrimaryFieldURLParam())
			columnForWhereClause, parsedValue, err := parseFieldFromParam(tx, param, resourceTypeForDoc, r.belongsToField)
			if err != nil {
				InternalServerError(ctx, err)
				return
			}

			table = table.Where(fmt.Sprintf("%v = ?", columnForWhereClause), parsedValue)
		}

		if len(r.preload) > 0 {
			for _, preload := range r.preload {
				table.Preload(preload)
			}
		}

		// We take the query params from a request such as /resource?id=1&name="%a%" and translate it to a gorm Where
		// clause. We also validate that the query params are actual fields on the resource to prevent users from
		// injecting SQL in query params.
		for _, param := range queryParams.Keys() {
			// Skip pagination parameters
			if param == "page" || param == "pageSize" || param == "limit" || param == "offset" {
				continue
			}

			var paramToLookup string

			// we check queryParamByAlias to see if we have an alias for this param (see SetQueryParamAlias)
			if queryParam, ok := r.queryParamByAlias[param]; ok {
				paramToLookup = queryParam
			} else {
				paramToLookup = param
			}

			paramSuffix := ""
			for suffix := range querySuffixToOperator {
				if strings.HasSuffix(param, suffix) {
					paramToLookup = strings.TrimSuffix(param, suffix)
					paramSuffix = suffix
				}
			}

			// We support lookups by the Field name or the JSON tag, first we attempt JSON.
			field, ok := r.fieldByJSON[paramToLookup]
			if !ok {
				// We then attempt the original param which we assume is a Field instead of a JSON tag (validated
				// below.)
				field = paramToLookup
			}

			if !r.isFieldNameValid(field) {
				continue
			}

			// TODO: validate param based on `doc` tag, how do we call OpenAPI.Validate() on a single field?
			column, parsedValue, err := parseFieldFromParam(tx, queryParams.Get(param), resourceTypeForDoc, field)
			if err != nil {
				InternalServerError(ctx, err)
				continue
			}

			var queryOperator FieldQueryOperation
			if paramSuffix == "" {
				queryOperator = r.retrieveQueryFieldOperator(field)
			} else {
				queryOperator = querySuffixToOperator[paramSuffix]
			}

			table = table.Where(fmt.Sprintf("%v %v ?", column, queryOperator), parsedValue)
		}

		table = table.Offset(offset).Limit(limit)

		var ids []any
		// If ACL is enabled for this resource, restrict the returned results to the resources we have access to.
		if r.acl != nil {
			ids = r.acl.GetIDsWithReadPermission(ctx, permissionName)
			if len(ids) == 0 {
				ForbiddenAccess(ctx)
				return
			}
		}

		var resources []*T
		if err = table.Find(&resources, ids).Error; err != nil {
			InternalServerError(ctx, err)
			return
		}

		if len(resources) == 0 {
			NoResults(ctx)
			return
		}

		if r.beforeListResponse != nil {
			response, err := r.beforeListResponse(ctx, resources)
			if err != nil {
				r.sendError(ctx, err)
				return
			}
			ctx.WriteJSON(http.StatusOK, response)
			return
		}

		ctx.WriteJSON(http.StatusOK, resources)
	})
}

// Get returns the resource by the primary id.
func (r *Resource[T]) Get(ctx context.Context, primaryId any) (*T, error) {
	// TODO: this code is duplicated and not called by the .GET() REST method, can we eventually unify this?
	whereClause := fmt.Sprintf("%v = ?", r.primaryField)
	whereArgs := []any{primaryId}

	tx := r.tx(ctx)
	table := tx.Model(r.table)
	r.omitIgnoredFields(ctx, access.PermissionRead, table)

	query := table.Where(whereClause, whereArgs...)
	if len(r.preload) > 0 {
		for _, preload := range r.preload {
			query.Preload(preload)
		}
	}

	var resource T
	if err := query.First(&resource).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrRecordNotFound
		}
		return nil, err
	}

	return &resource, nil
}

func (r *Resource[T]) generateReadEndpoint(routes router.Router, groupPath string, permissionName string, resourceTypeForDoc *T, openAPI *openapi.Builder) {
	routePath := path.Join(routes.BasePath(), groupPath, r.path, "{"+r.PrimaryFieldURLParam()+"}")

	if !r.disableReadDocs {
		getDoc := openAPI.Register(&openapi.Operation{
			OperationID: "get" + r.name,
			Method:      http.MethodGet,
			Path:        routePath,
			Tags:        r.tags,
		}).
			Summary("Returns a single " + r.name).
			Description("Returns a single " + r.name + " by the primary ID.")

		getDoc.Request().PathParam(r.PrimaryFieldURLParam(), r.name).Description("Primary ID of the " + r.name).Example("1").Required(true)
		getDoc.Response(http.StatusOK).Body(resourceTypeForDoc)
	}

	routes.GET(routePath, func(ctx router.Context) {
		if r.rbac != nil && !r.rbac.HasPermission(ctx, permissionName, access.PermissionRead) {
			ForbiddenAccess(ctx)
			return
		}

		tx := r.tx(ctx)

		whereClause, whereArgs, err := r.buildResourceWhereClause(ctx, resourceTypeForDoc)
		if err != nil {
			return
		}

		var resource T
		table := tx.Model(r.table)
		r.omitIgnoredFields(ctx, access.PermissionRead, table)

		query := table.Where(whereClause, whereArgs...)
		if len(r.preload) > 0 {
			for _, preload := range r.preload {
				query.Preload(preload)
			}
		}

		if err = query.First(&resource).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				ResourceNotFound(ctx)
				return
			}
			InternalServerError(ctx, err)
			return
		}

		if r.acl != nil && !r.acl.HasPermission(ctx, permissionName, r.getID(&resource), access.PermissionRead) {
			ForbiddenAccess(ctx)
			return
		}

		if !r.hasOwnership(ctx, r.name, &resource) {
			ForbiddenAccess(ctx)
			return
		}

		r.sendResponse(ctx, &resource, access.PermissionRead)
	})
}

func (r *Resource[T]) Update(ctx context.Context, primaryId any, resource *T) error {
	whereClause := fmt.Sprintf("%v = ?", r.primaryField)
	whereArgs := []any{primaryId}

	if err := r.runBeforeSaveHooks(ctx, resource, access.PermissionUpdate); err != nil {
		return err
	}

	tx := r.tx(ctx)
	table := tx.Model(resource)
	r.omitIgnoredFields(ctx, access.PermissionUpdate, table)

	if result := table.Where(whereClause, whereArgs).Save(resource); result.Error != nil {
		return result.Error
	}

	if err := r.runAfterSaveHooks(ctx, resource, access.PermissionUpdate); err != nil {
		return err
	}

	return nil
}

func (r *Resource[T]) generateUpdateEndpoint(routes router.Router, groupPath string, permissionName string, resourceTypeForDoc *T, openAPI *openapi.Builder) {
	routePath := path.Join(routes.BasePath(), groupPath, r.path, "{"+r.PrimaryFieldURLParam()+"}")

	if !r.disableUpdateDocs {
		updateDoc := openAPI.Register(&openapi.Operation{
			OperationID: "update" + r.name,
			Method:      http.MethodPut,
			Path:        routePath,
			Tags:        r.tags,
		}).Summary("Updates a single " + r.name).
			Description("Updates a single " + r.name + ".")

		updateDoc.Request().PathParam(r.PrimaryFieldURLParam(), r.name).Description("Primary ID of the " + r.name).Required(true)
		updateDoc.Request().Body(resourceTypeForDoc)
	}

	routes.PUT(routePath, func(ctx router.Context) {
		if r.rbac != nil && !r.rbac.HasPermission(ctx, permissionName, access.PermissionUpdate) {
			ForbiddenAccess(ctx)
			return
		}

		resource, err := r.parseAndValidateRequestBody(ctx)
		if err != nil {
			return
		}

		if r.acl != nil && !r.acl.HasPermission(ctx, r.name, r.getID(resource), access.PermissionUpdate) {
			ForbiddenAccess(ctx)
			return
		}

		param := ctx.Param(r.PrimaryFieldURLParam())
		_, primaryFieldValue, err := parseFieldFromParam(r.tx(ctx), param, resourceTypeForDoc, r.primaryField)
		if err != nil {
			r.sendError(ctx, err)
			return
		}

		if err := r.Update(ctx, primaryFieldValue, resource); err != nil {
			r.sendError(ctx, err)
			return
		}

		r.sendResponse(ctx, resource, access.PermissionUpdate)
	})
}

func (r *Resource[T]) Patch(ctx context.Context, primaryId any, resource *T) error {
	whereClause := fmt.Sprintf("%v = ?", r.primaryField)
	whereArgs := []any{primaryId}

	if err := r.runBeforeSaveHooks(ctx, resource, access.PermissionUpdate); err != nil {
		return err
	}

	tx := r.tx(ctx)
	table := tx.Model(resource)
	r.omitIgnoredFields(ctx, access.PermissionUpdate, table)

	if result := table.Where(whereClause, whereArgs).Updates(resource); result.Error != nil {
		return result.Error
	}

	if err := r.runAfterSaveHooks(ctx, resource, access.PermissionUpdate); err != nil {
		return err
	}

	return nil
}

func (r *Resource[T]) generateUpdatePatchEndpoint(routes router.Router, groupPath string, permissionName string, resourceTypeForDoc *T, openAPI *openapi.Builder) {
	routePath := path.Join(routes.BasePath(), groupPath, r.path, "{"+r.PrimaryFieldURLParam()+"}")

	if !r.disableUpdateDocs {
		patchDoc := openAPI.Register(&openapi.Operation{
			OperationID: "patch" + r.name,
			Method:      http.MethodPatch,
			Path:        routePath,
			Tags:        r.tags,
		}).Summary("Patches a single " + r.name).
			Description("Patches a single " + r.name + ".")

		patchDoc.Request().PathParam(r.PrimaryFieldURLParam(), r.name).Description("Primary ID of the " + r.name).Required(true)
		patchDoc.Request().Body(resourceTypeForDoc)
	}

	routes.PATCH(routePath, func(ctx router.Context) {
		if r.rbac != nil && !r.rbac.HasPermission(ctx, permissionName, access.PermissionUpdate) {
			ForbiddenAccess(ctx)
			return
		}

		resource, err := r.parseAndValidateRequestBody(ctx)
		if err != nil {
			return
		}

		if r.acl != nil && !r.acl.HasPermission(ctx, r.name, r.getID(resource), access.PermissionUpdate) {
			ForbiddenAccess(ctx)
			return
		}

		param := ctx.Param(r.PrimaryFieldURLParam())
		_, primaryFieldValue, err := parseFieldFromParam(r.tx(ctx), param, resourceTypeForDoc, r.primaryField)
		if err != nil {
			r.sendError(ctx, err)
			return
		}

		if err := r.Patch(ctx, primaryFieldValue, resource); err != nil {
			r.sendError(ctx, err)
			return
		}

		r.sendResponse(ctx, resource, access.PermissionUpdate)
	})
}

// parseAndValidateRequestBody reads and validates the request body.
func (r *Resource[T]) parseAndValidateRequestBody(ctx router.Context) (*T, error) {
	defer ctx.Request().Body.Close()
	lr := io.LimitReader(ctx.Request().Body, r.maxInputBytes)
	body, err := io.ReadAll(lr)
	if err != nil {
		InternalServerError(ctx, err)
		return nil, err
	}

	// We double unmarshal here because openapi.Validate() only works with map[string]any for validation.
	var resourceForValidation map[string]any
	if err = json.Unmarshal(body, &resourceForValidation); err != nil {
		InternalServerError(ctx, err)
		return nil, err
	}

	errs := r.IsValid(resourceForValidation)
	if len(errs) > 0 {
		var errStrings []string
		for _, err := range errs {
			errStrings = append(errStrings, err.Error())
		}

		InvalidInput(ctx, strings.Join(errStrings, ", \n"))
		return nil, errors.New("invalid input")
	}

	var resource *T
	if err = json.Unmarshal(body, &resource); err != nil {
		InternalServerError(ctx, err)
		return nil, err
	}

	return resource, nil
}

// runBeforeSaveHooks executes all registered before-save hooks.
func (r *Resource[T]) runBeforeSaveHooks(ctx context.Context, resource *T, permission access.Permission) error {
	if hooks, ok := r.beforeSave[permission]; ok {
		for _, hook := range hooks {
			if err := hook(ctx, resource); err != nil {
				return err
			}
		}
	}
	return nil
}

// runAfterSaveHooks executes all registered after-save hooks.
func (r *Resource[T]) runAfterSaveHooks(ctx context.Context, resource *T, permission access.Permission) error {
	if hooks, ok := r.afterSave[permission]; ok {
		for _, hook := range hooks {
			if err := hook(ctx, resource); err != nil {
				return err
			}
		}
	}
	return nil
}

// buildResourceWhereClause constructs the SQL WHERE clause for resource operations.
func (r *Resource[T]) buildResourceWhereClause(ctx router.Context, resourceTypeForDoc *T) (string, []any, error) {
	primaryParam := ctx.Param(r.PrimaryFieldURLParam())
	_, primaryFieldValue, err := parseFieldFromParam(r.tx(ctx), primaryParam, resourceTypeForDoc, r.primaryField)
	if err != nil {
		InternalServerError(ctx, err)
		return "", nil, err
	}

	whereClause := fmt.Sprintf("%v = ?", r.primaryField)
	whereArgs := []any{primaryFieldValue}

	if r.belongsTo != nil {
		param := ctx.Param(r.belongsTo.PrimaryFieldURLParam())
		columnForWhereClause, parsedValue, err := parseFieldFromParam(r.tx(ctx), param, resourceTypeForDoc, r.belongsToField)
		if err != nil {
			InternalServerError(ctx, err)
			return "", nil, err
		}

		whereClause = fmt.Sprintf("%v = ? AND %v = ?", r.primaryField, columnForWhereClause)
		whereArgs = append(whereArgs, parsedValue)
	}

	return whereClause, whereArgs, nil
}

// getPaginationParams extracts pagination parameters from query params.
func (r *Resource[T]) getPaginationParams(queryParams router.QueryParams) (int, int, error) {
	// Default to max limit with no offset.
	limit := r.maxLimit
	offset := 0

	// Check for page-based pagination.
	if queryParams.Has("page") && queryParams.Has("pageSize") {
		page, _ := strconv.Atoi(queryParams.Get("page"))
		if page <= 0 {
			page = 1
		}

		pageSize, _ := strconv.Atoi(queryParams.Get("pageSize"))
		if pageSize <= 0 {
			pageSize = r.pageSize
		}
		if pageSize > r.maxPageSize {
			pageSize = r.maxPageSize
		}

		limit = pageSize
		offset = (page - 1) * pageSize
		return limit, offset, nil
	}

	// Check for limit/offset pagination.
	if queryParams.Has("limit") && queryParams.Has("offset") {
		var err error
		limit, err = strconv.Atoi(queryParams.Get("limit"))
		if err != nil {
			return 0, 0, fmt.Errorf("invalid limit parameter: %w", err)
		}

		offset, err = strconv.Atoi(queryParams.Get("offset"))
		if err != nil {
			return 0, 0, fmt.Errorf("invalid offset parameter: %w", err)
		}

		if limit > r.maxLimit {
			limit = r.maxLimit
		}

		return limit, offset, nil
	}

	// Check for limit/start pagination. (TODO: remove this)
	if queryParams.Has("limit") && queryParams.Has("start") {
		var err error
		limit, err = strconv.Atoi(queryParams.Get("limit"))
		if err != nil {
			return 0, 0, fmt.Errorf("invalid limit parameter: %w", err)
		}

		offset, err = strconv.Atoi(queryParams.Get("start"))
		if err != nil {
			return 0, 0, fmt.Errorf("invalid offset parameter: %w", err)
		}

		if limit > r.maxLimit {
			limit = r.maxLimit
		}

		return limit, offset, nil
	}

	return limit, offset, nil
}

// sendError sends an error
func (r *Resource[T]) sendError(ctx router.Context, err error) {
	var userError *UserError
	if errors.As(err, &userError) {
		CustomUserError(ctx, userError)
		return
	}
	InternalServerError(ctx, err)
}

// sendResponse prepares and sends the API response.
func (r *Resource[T]) sendResponse(ctx router.Context, resource *T, permission access.Permission) {
	if f, ok := r.beforeResponse[permission]; ok {
		customResponse, err := f(ctx, resource)
		if err != nil {
			var userError *UserError
			if errors.As(err, &userError) {
				CustomUserError(ctx, userError)
				return
			}

			InternalServerError(ctx, err)
			return
		}
		ctx.WriteJSON(http.StatusOK, customResponse)
	} else {
		ctx.WriteJSON(http.StatusOK, resource)
	}
}
