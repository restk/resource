package resource

import (
	"context"
	"fmt"
	"net/http"
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
)

type FieldQueryOperation string

var (
	FieldQueryOperationEquals            FieldQueryOperation = "="
	FieldQueryOperationLike              FieldQueryOperation = "LIKE"
	FieldQueryOperationGreaterThanEquals FieldQueryOperation = ">="
	FieldQueryOperationLessThanEquals    FieldQueryOperation = "<="
)

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
	ResourceNotFound = func(c router.Context) {
		c.WriteJSON(http.StatusNotFound, S{"code": 404, "message": "Resource not found"})
	}
	InternalServerError = func(c router.Context, err error) {
		fmt.Println("internal server error", err)
		c.WriteJSON(http.StatusInternalServerError, S{"code": 500, "message": "Internal Server Error"})
	}
	CustomUserError = func(c router.Context, userError *UserError) {
		c.WriteJSON(http.StatusInternalServerError, S{"code": userError.Code, "message": userError.Message})
	}
	BadRequest = func(c router.Context) {
		c.WriteJSON(http.StatusBadRequest, S{"code": 400, "message": "Invalid request"})
	}
	InvalidInput = func(c router.Context, msg string) {
		c.WriteJSON(http.StatusBadRequest, S{"code": 400, "message": msg})
	}
	ForbiddenAccess = func(c router.Context) {
		c.WriteJSON(http.StatusForbidden, S{"code": 407, "message": "Forbidden access to resource"})
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
	columnByField             map[string]string
	fieldByJSON               map[string]string
	ignoredFieldsByPermission map[access.Permission]map[string]*FieldIgnoreRule

	// Hooks.
	beforeSave     map[access.Permission][]func(c router.Context, obj *T) error
	afterSave      map[access.Permission][]func(c router.Context, obj *T) error
	beforeDelete   []func(c router.Context, obj *T) error
	afterDelete    []func(c router.Context, obj *T) error
	beforeResponse map[access.Permission]func(c router.Context, obj *T) (any, error)

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

	// Docs.
	generateDocs bool

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
		generateDocs:              true,
		hasOwnership:              DefaultHasOwnership[T],
		beforeSave:                make(map[access.Permission][]func(c router.Context, obj *T) error, 0),
		afterSave:                 make(map[access.Permission][]func(c router.Context, obj *T) error, 0),
		beforeDelete:              make([]func(c router.Context, obj *T) error, 0),
		afterDelete:               make([]func(c router.Context, obj *T) error, 0),
		beforeResponse:            make(map[access.Permission]func(c router.Context, obj *T) (any, error), 0),
		queryOperatorByField:      make(map[string]FieldQueryOperation, 0),
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

// DisableDocs disables API doc generation for this specific resource.
func (r *Resource[T]) DisableDocs() {
	r.generateDocs = false
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
func (r *Resource[T]) BeforeSave(permission access.Permission, f func(c router.Context, obj *T) error) {
	if _, ok := r.beforeSave[permission]; !ok {
		r.beforeSave[permission] = make([]func(c router.Context, obj *T) error, 0)
	}
	r.beforeSave[permission] = append(r.beforeSave[permission], f)
}

// AfterSave is called after the resource is saved to the database successfully. You can add multiple functions.
func (r *Resource[T]) AfterSave(permission access.Permission, f func(c router.Context, obj *T) error) {
	if _, ok := r.afterSave[permission]; !ok {
		r.afterSave[permission] = make([]func(c router.Context, obj *T) error, 0)
	}

	r.afterSave[permission] = append(r.afterSave[permission], f)
}

// BeforeResponse is called right before we respond to the client and allows you to return a custom response instead
// of the default response.
func (r *Resource[T]) BeforeResponse(permission access.Permission, f func(c router.Context, obj *T) (any, error)) {
	r.beforeResponse[permission] = f
}

// BeforeDelete is called right before a resource is deleted.
func (r *Resource[T]) BeforeDelete(f func(c router.Context, obj *T) error) {
	r.beforeDelete = append(r.beforeDelete, f)
}

// AfterDelete is called after a resource is deleted successfully.
func (r *Resource[T]) AfterDelete(f func(c router.Context, obj *T) error) {
	r.afterDelete = append(r.afterDelete, f)
}

// SetFieldQueryOperation
//
// Resource[schema.User].SetFieldQueryOperation("EndTime", FieldOperationLessThanEqual).
func (r *Resource[T]) SetFieldQueryOperation(field string, op FieldQueryOperation) {
	r.queryOperatorByField[field] = op
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
func (r *Resource[T]) retrieveQueryFieldOperator(field string) string {
	if op, ok := r.queryOperatorByField[field]; ok {
		return string(op)
	}

	return string(FieldQueryOperationEquals)
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
func (r *Resource[T]) tx(ctx router.Context) *gorm.DB {
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
	omitFields := []string{}
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

// DisableCreate disables creation on this resource.
func (r *Resource[T]) DisableCreate() {
	r.disableCreate = true
}

// DisableDelete disables deletes on this resource.
func (r *Resource[T]) DisableDelete() {
	r.disableDelete = true
}

// DisableList disables listing on this resource.
func (r *Resource[T]) DisableList() {
	r.disableList = true
}

// DisableRead disables reads on this resource.
func (r *Resource[T]) DisableRead() {
	r.disableRead = true
}

// DisableUpdate disables updates on this resource.
func (r *Resource[T]) DisableUpdate() {
	r.disableUpdate = true
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
