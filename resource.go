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
	pluralizeClient = pluralize.NewClient()
	caser           = cases.Title(language.English)
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
// when you want the user to receive the error
func NewUserError(code int, message string) error {
	return &UserError{
		Code:    code,
		Message: message,
	}
}

// S is used to easily craft JSON responses, see ResourceNotFound
type S map[string]interface{}

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
	table        interface{}
	preload      []string
	schema       *openapi.Schema

	// fields
	fields                    []*Field
	queryOperatorByField      map[string]FieldQueryOperation
	columnByField             map[string]string
	fieldByJSON               map[string]string
	ignoredFieldsByPermission map[access.Permission]map[string]*FieldIgnoreRule

	// hooks
	beforeSave     map[access.Permission][]func(c router.Context, obj *T) error
	afterSave      map[access.Permission][]func(c router.Context, obj *T) error
	beforeDelete   []func(c router.Context, obj *T) error
	afterDelete    []func(c router.Context, obj *T) error
	beforeResponse map[access.Permission]func(c router.Context, obj *T) (interface{}, error)

	// pagination
	maxPageSize int
	pageSize    int
	maxLimit    int

	// access control
	rbac access.RBAC

	acl                 access.ACL
	aclGrantPermissions []access.Permission

	// relationships
	belongsTo      ResourceInterface
	belongsToField string

	// API overrides
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

	// docs
	generateDocs bool

	// other
	maxInputBytes int64
}

// NewResource creates a new resource. Name is expected to be singular and we attempt to make it plural for doc purposes. To override the
// plural name, call .Plural("")
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
		beforeResponse:            make(map[access.Permission]func(c router.Context, obj *T) (interface{}, error), 0),
		queryOperatorByField:      make(map[string]FieldQueryOperation, 0),
		columnByField:             make(map[string]string, 0),
		preload:                   make([]string, 0),
		fields:                    make([]*Field, 0),
		ignoredFieldsByPermission: make(map[access.Permission]map[string]*FieldIgnoreRule, 0),
		pageSize:                  10,
		maxPageSize:               250,
		maxLimit:                  250,
		maxInputBytes:             10 * 1024 * 1024,

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

// ADdTag adds a tag
func (r *Resource[T]) AddTag(tag string) {
	r.tags = append(r.tags, tag)
}

// Tags replaces all tags
func (r *Resource[T]) Tags(tags []string) {
	r.tags = tags
}

// DisableDocs disables API doc generation for this specific resource.
func (r *Resource[T]) DisableDocs() {
	r.generateDocs = false
}

// PrimaryField returns the name of the primary field. The primary field is what is used for REST endpoints such as /users/:id (in this case, id, is the primary field)
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

	// first tag is automatically generated when a resource is created, if this resource belongs to another
	// resource we add it to the belongs to resource tag instead.
	if len(r.tags) > 0 {
		r.tags[0] = caser.String(resource.PluralName())
	}
}

// SetOwnsResource sets the function which checks if the resource is owned by the caller making the request.
func (r *Resource[T]) SetHasOwnership(f func(c router.Context, resource string, obj *T) bool) {
	r.hasOwnership = f
}

// Preload loads a resources associations. For example:
//
// Preload("Organization.Roles", "Keys") would load User.Organization, User.Organization.Roles and User.Keys
func (f *Resource[T]) Preload(association ...string) {
	f.preload = append(f.preload, association...)
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

// SetFieldOperation sets the field operation when doing a search query. The field is the name of the struct field (exact name including capital)
//
//	By default all fields use an equal operator and we recommend only adding fields that do not search by a plain equal operator.
//
// Resource[schema.User].SetFieldQueryOperation("Name", FieldOperationLike)
// Resource[schema.User].SetFieldQueryOperation("StartTime", FieldOperationGreaterThanEqual)
// Resource[schema.User].SetFieldQueryOperation("EndTime", FieldOperationLessThanEqual)
func (r *Resource[T]) SetFieldQueryOperation(field string, op FieldQueryOperation) {
	r.queryOperatorByField[field] = op
}

// DefaultHasOwnership returns true by default and does not handle ownership. Call SetHasOwnership() to add ownership
func DefaultHasOwnership[T any](c router.Context, resource string, obj *T) bool {
	return true
}

// isFieldNameValid checks if the field exists on the Resource[T]
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

// AllowField will allow a field for a specific permission. By default Fields are allowed, call IgnoreAllFields() first.
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

// IgnoreFields will ignore a list of fields for a specific permission. You can ignore a field for: access.PermissionRead, access.PermissionWrite, access.PermissionList, access.PermissionCreate
func (r *Resource[T]) IgnoreFields(fields []string, accessMethod []access.Permission) *Resource[T] {
	for _, field := range fields {
		r.IgnoreFieldUnlessRole(field, accessMethod, []string{})
	}

	return r
}

// IgnoreField will ignore a field for a specific permission. You can ignore a field for: access.PermissionRead, access.PermissionWrite, access.PermissionList, access.PermissionCreate
func (r *Resource[T]) IgnoreField(field string, accessMethod []access.Permission) *Resource[T] {
	return r.IgnoreFieldUnlessRole(field, accessMethod, []string{})
}

// see: IgnoreFieldUnlessRole
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

// retrieveQueryFieldOperator retrieves the query operator for a field
func (r *Resource[T]) retrieveQueryFieldOperator(field string) string {
	if op, ok := r.queryOperatorByField[field]; ok {
		return string(op)
	} else {
		return string(FieldQueryOperationEquals)
	}
}

// fieldByJSON returns a field name by its JSON tag
func generateFieldByJSON(resource interface{}) map[string]string {
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

// generateColumnNameByField generates a mapping (field -> column name) for a resource T
func generateColumnByField(db *gorm.DB, resource interface{}) (map[string]string, error) {
	columnByField := make(map[string]string, 0)

	// look up the belongs to field using gorm statement parsing so we can do a where clause lookup
	stmt := &gorm.Statement{DB: db}
	err := stmt.Parse(resource)
	if err != nil {
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
func parseFieldFromParam(db *gorm.DB, param string, resource interface{}, field string) (string, interface{}, error) {
	if resource == nil {
		return "", nil, errors.Errorf("resource is nil when calling parseFieldFromParam")
	}

	// look up the belongs to field using gorm statement parsing so we can do a where clause lookup
	stmt := &gorm.Statement{DB: db}
	err := stmt.Parse(resource)
	if err != nil {
		return "", nil, errors.Errorf("failed to parse gorm model for parseFieldFromParam")
	}

	gormField := stmt.Schema.LookUpField(field)
	if gormField == nil {
		return "", nil, errors.Errorf("failed to find field" + field)
	}

	columnForWhereClause := gormField.DBName
	var parsedValue interface{}
	switch gormField.StructField.Type.Kind() {
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		parseduIntValue, err := strconv.ParseUint(param, 10, 64)
		if err != nil {
			return "", nil, errors.Wrapf(err, "failed to parseFieldFromParam, not a uint")
		}
		parsedValue = parseduIntValue
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		parsedIntValue, err := strconv.ParseInt(param, 10, 64)
		if err != nil {
			return "", nil, errors.Wrapf(err, "failed to parseFieldFromParam, not an int")
		}
		parsedValue = parsedIntValue
	case reflect.String:
		parsedValue = param
	case reflect.Struct:
		// If it's time.Time, parse the string into a time.Time
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
		// unhandled type
		return "", nil, errors.Errorf("type not supported, if you are a developer, you can add a new type")
	}

	return columnForWhereClause, parsedValue, nil
}

// Tx returns a transaction from the resource or panics
// TODO: when implementing the generic model interface, we should have ways for the user to determine where the tx comes from instead of hard pulling it from the context
func (r *Resource[T]) tx(ctx router.Context) *gorm.DB {
	val := ctx.Value("gorm_tx") // TODO: allow user to specify the context key to get the transaction from
	if tx, ok := val.(*gorm.DB); ok {
		return tx
	}

	// not being able to find a transaction inside the context is a critical error and everything should stop
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

// GenerateRESTAPI generates REST API endpoints for a resource. This also handles RBAC and makes sure the calling user has permission for an action on a resource.
//
// GET /resources                  -> returns an array of resources (with a max amount per page) and filters
// GET /resources/:primaryField    -> returns a paginated list of resources (with a max amount per page) and filters
// PUT /resource     -> creates or updates a single resource (with allowable save fields)
// PUT /resources    -> creates or updates a list of resources (with allowable save fields)
// DELETE /resource  -> deletes a single resource
// DELETE /resources -> deletes a list of resources
func (r *Resource[T]) GenerateRestAPI(routes router.Router, dbb *gorm.DB, openAPI *openapi.Builder) error {
	// generate column names
	// TODO: add a storage interface instead of using gorm directly so Resource can be used for any other storage medium
	groupPath := ""
	permissionName := r.name
	if r.belongsTo != nil {
		groupPath = path.Join("/", r.belongsTo.Name(), "/:"+r.belongsTo.PrimaryFieldURLParam())
		permissionName = r.belongsTo.Name() + "-" + r.name
	}

	// resourceTypeForDoc is used to give type information to OpenAPI
	// TODO: we define this twice, once as a pointer and one that is not, we should
	// unify everything to support both instead of declaring both
	var resourceTypeForDoc *T
	var resource T

	columnByField, err := generateColumnByField(dbb, resource)
	if err != nil {
		return err
	}
	r.columnByField = columnByField

	fieldByJSON := generateFieldByJSON(resource)
	r.fieldByJSON = fieldByJSON

	if !r.disableList {
		listPath := path.Join(groupPath, "/", r.path)

		if r.generateDocs {
			listDoc := openAPI.Register(&openapi.Operation{
				OperationID: "list" + r.name,
				Method:      "GET",
				Path:        path.Join(routes.BasePath(), listPath),
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

		routes.GET(listPath, func(c router.Context) {
			if r.rbac != nil {
				if !r.rbac.HasPermission(c, permissionName, access.PermissionList) {
					ForbiddenAccess(c)
					return
				}
			}

			tx := r.tx(c)
			queryParams := c.QueryParams()

			var page int
			var pageSize int
			var pageOffset int
			var paginationIsEnabled bool = false

			if queryParams.Has("page") && queryParams.Has("page_size") {
				page, _ = strconv.Atoi(queryParams.Get("page"))
				if page <= 0 {
					page = 1
				}

				pageSize, _ = strconv.Atoi(queryParams.Get("page_size"))
				if pageSize <= 0 {
					pageSize = r.pageSize
				}

				if pageSize > r.maxPageSize {
					pageSize = r.maxPageSize
				}

				paginationIsEnabled = true
				pageOffset = (page - 1) * pageSize
			}

			var limit int
			var offset int
			var limitOffsetEnabled bool = false

			if queryParams.Has("limit") && queryParams.Has("offset") {
				limit, _ = strconv.Atoi(queryParams.Get("limit"))
				offset, _ = strconv.Atoi(queryParams.Get("offset"))
				if limit > r.maxLimit {
					limit = r.maxLimit
				}
				limitOffsetEnabled = true
			}

			table := tx.Model(r.table)
			r.omitIgnoredFields(c, access.PermissionList, table)

			// if this is a grouped resource, we add the primary field of the resource this belongs to
			if r.belongsTo != nil {
				param := c.Param(r.belongsTo.PrimaryFieldURLParam())
				columnForWhereClause, parsedValue, err := parseFieldFromParam(tx, param, resourceTypeForDoc, r.belongsToField)
				if err != nil {
					InternalServerError(c, err)
					return
				}

				table = table.Where(fmt.Sprintf("%v = ?", columnForWhereClause), parsedValue)
			}

			if len(r.preload) > 0 {
				for _, preload := range r.preload {
					table.Preload(preload)
				}
			}

			// We take the query params from a request such as /resource?id=1&name="%a%" and translate it to a gorm Where clause. We also validate
			// that the query params are actual fields on the resource to prevent users from injecting SQL in query params.
			for _, param := range queryParams.Keys() {
				// We support lookups by the Field name or the JSON tag, first we attempt JSON
				field, ok := r.fieldByJSON[param]
				if !ok {
					// We then attempt the original param which we assume is a Field instead of a JSON tag (validated below.)
					field = param
				}

				if isValid := r.isFieldNameValid(field); !isValid {
					continue
				}

				// TODO: validate param based on `doc` tag, how do we call
				// OpenAPI.Validate() on a single field?
				column, parsedValue, err := parseFieldFromParam(tx, queryParams.Get(param), resourceTypeForDoc, field)
				if err != nil {
					InternalServerError(c, err)
					continue
				}

				queryOperator := r.retrieveQueryFieldOperator(field)
				table = table.Where(fmt.Sprintf("%v %v ?", column, queryOperator), parsedValue)
			}

			// set a global limit if the user does not specifiy pagination or limit offset.
			table.Limit(r.maxLimit)

			if paginationIsEnabled {
				table = table.Offset(pageOffset).Limit(pageSize)
			}
			if limitOffsetEnabled {
				table = table.Offset(offset).Limit(limit)
			}

			var ids []any

			// If ACL is enabled for this resource, restrict the returned results to the resources we have access to
			if r.acl != nil {
				ids = r.acl.GetIDsWithReadPermission(c, permissionName)
				if len(ids) == 0 {
					ForbiddenAccess(c)
					return
				}
			}

			var resources []T
			if err := table.Find(&resources, ids).Error; err != nil {
				return
			}

			if len(resources) == 0 {
				ResourceNotFound(c)
				return
			}

			c.WriteJSON(http.StatusOK, resources)
		})
	}

	if !r.disableRead {
		getPath := path.Join(groupPath, "/", r.path, "/:"+r.PrimaryFieldURLParam())
		if r.generateDocs {
			getDoc := openAPI.Register(&openapi.Operation{
				OperationID: "get" + r.name,
				Method:      "GET",
				Path:        path.Join(routes.BasePath(), getPath),
				Tags:        r.tags,
			}).Summary("Returns a single " + r.name).
				Description("Returns a single " + r.name + " by the primary id.")

			getDoc.Request().PathParam(r.primaryField, r.name).Description("primary id of the " + r.name).Example("1").Required(true)
			getDoc.Response(http.StatusOK).Body(resourceTypeForDoc)

		}

		routes.GET(getPath, func(c router.Context) {
			if r.rbac != nil {
				if !r.rbac.HasPermission(c, permissionName, access.PermissionRead) {
					ForbiddenAccess(c)
					return
				}
			}

			tx := r.tx(c)
			whereClauseQuery := ""
			whereClauseArgs := make([]interface{}, 0)

			primaryFieldValue := c.Param(r.PrimaryFieldURLParam())
			whereClauseQuery = fmt.Sprintf("%v = ?", r.primaryField)
			whereClauseArgs = append(whereClauseArgs, primaryFieldValue)

			if r.belongsTo != nil {
				param := c.Param(r.belongsTo.PrimaryFieldURLParam())
				columnForWhereClause, parsedValue, err := parseFieldFromParam(tx, param, resourceTypeForDoc, r.belongsToField)
				if err != nil {
					InternalServerError(c, err)
					return
				}

				whereClauseQuery = fmt.Sprintf("%v = ? AND %v = ?", r.primaryField, columnForWhereClause)
				whereClauseArgs = append(whereClauseArgs, parsedValue)
			}

			var resource T
			table := tx.Model(r.table)
			r.omitIgnoredFields(c, access.PermissionRead, table)

			query := table.Where(whereClauseQuery, whereClauseArgs...)
			if len(r.preload) > 0 {
				for _, preload := range r.preload {
					query.Preload(preload)
				}
			}
			r.omitIgnoredFields(c, access.PermissionList, query)

			if err := query.First(&resource).Error; err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) {
					ResourceNotFound(c)
					return
				}

				InternalServerError(c, err)
				return
			}

			if r.acl != nil {
				if !r.acl.HasPermission(c, permissionName, r.getID(&resource), access.PermissionRead) {
					ForbiddenAccess(c)
					return
				}
			}

			if !r.hasOwnership(c, r.name, &resource) {
				ForbiddenAccess(c)
				return
			}

			if f, ok := r.beforeResponse[access.PermissionRead]; ok {
				customResponse, err := f(c, &resource)
				if err != nil {
					var userError *UserError
					if errors.As(err, &userError) {
						CustomUserError(c, userError)
						return
					}

					InternalServerError(c, err)
					return
				}
				c.WriteJSON(http.StatusOK, customResponse)
			} else {
				c.WriteJSON(http.StatusOK, resource)
			}
		})
	}

	if !r.disableCreate {
		createPath := path.Join(groupPath, "/", r.path)
		if r.generateDocs {
			createDoc := openAPI.Register(&openapi.Operation{
				OperationID: "create" + r.name,
				Method:      "PUT",
				Path:        path.Join(routes.BasePath(), createPath),
				Tags:        r.tags,
			}).Summary("Creates a new " + r.name).
				Description("Creates a new " + r.name + ". If the resource already exist, this returns an error.")

			createDoc.Request().Body(resourceTypeForDoc)
		}

		routes.POST(createPath, func(c router.Context) {
			if r.rbac != nil {
				if !r.rbac.HasPermission(c, permissionName, access.PermissionCreate) {
					ForbiddenAccess(c)
					return
				}
			}

			tx := r.tx(c)

			defer c.Request().Body.Close()
			lr := io.LimitReader(c.Request().Body, r.maxInputBytes)
			body, err := io.ReadAll(lr)
			if err != nil {
				InternalServerError(c, err)
			}

			// we double unmarshal here because openapi.Validate() only works with
			// map[string]any for validation
			var resourceForValidation map[string]any
			err = json.Unmarshal(body, &resourceForValidation)
			if err != nil {
				InternalServerError(c, err)
				return
			}

			errs := r.Validate(resourceForValidation)
			if len(errs) > 0 {
				errStr := []string{}
				for _, err := range errs {
					errStr = append(errStr, err.Error())
				}

				InvalidInput(c, strings.Join(errStr, ","))
				return
			}

			var resource *T
			err = json.Unmarshal(body, &resource)
			if err != nil {
				InternalServerError(c, err)
				return
			}

			if _, ok := r.beforeSave[access.PermissionCreate]; ok {
				for _, beforeSaveFunc := range r.beforeSave[access.PermissionCreate] {
					if err = beforeSaveFunc(c, resource); err != nil {
						var userError *UserError
						if errors.As(err, &userError) {
							CustomUserError(c, userError)
							return
						}

						InternalServerError(c, err)
						return
					}
				}
			}

			table := tx.Model(r.table)
			r.omitIgnoredFields(c, access.PermissionCreate, table)

			if result := table.Create(&resource); result.Error != nil {
				InternalServerError(c, err)
				return
			}

			if r.acl != nil {
				r.acl.GrantPermissions(c, r.name, r.getID(resource), r.aclGrantPermissions)
			}

			if _, ok := r.afterSave[access.PermissionCreate]; ok {
				for _, afterSaveFunc := range r.afterSave[access.PermissionCreate] {
					if err = afterSaveFunc(c, resource); err != nil {
						var userError *UserError
						if errors.As(err, &userError) {
							CustomUserError(c, userError)
							return
						}

						InternalServerError(c, err)
						return
					}
				}
			}

			if f, ok := r.beforeResponse[access.PermissionCreate]; ok {
				customResponse, err := f(c, resource)
				if err != nil {
					var userError *UserError
					if errors.As(err, &userError) {
						CustomUserError(c, userError)
						return
					}

					InternalServerError(c, err)
					return
				}
				c.WriteJSON(http.StatusOK, customResponse)
			} else {
				c.WriteJSON(http.StatusOK, resource)
			}
		})
	}

	if !r.disableUpdate {
		updatePath := path.Join(groupPath, "/", r.path, "/:"+r.PrimaryFieldURLParam())
		if r.generateDocs {
			updateDoc := openAPI.Register(&openapi.Operation{
				OperationID: "update" + r.name,
				Method:      "PUT",
				Path:        path.Join(routes.BasePath(), updatePath),
				Tags:        r.tags,
			}).Summary("Updates a single " + r.name).
				Description("Updates a single " + r.name + ".")

			updateDoc.Request().PathParam(r.primaryField, r.name).Description("primary id of the " + r.name).Required(true)
			updateDoc.Request().Body(resourceTypeForDoc)
		}

		routes.PUT(updatePath, func(c router.Context) {
			if r.rbac != nil {
				if !r.rbac.HasPermission(c, permissionName, access.PermissionUpdate) {
					ForbiddenAccess(c)
					return
				}
			}

			defer c.Request().Body.Close()
			lr := io.LimitReader(c.Request().Body, r.maxInputBytes)
			body, err := io.ReadAll(lr)
			if err != nil {
				InternalServerError(c, err)
			}

			// we double unmarshal here because openapi.Validate() only works with
			// map[string]any for validation
			var resourceForValidation map[string]any
			err = json.Unmarshal(body, &resourceForValidation)
			if err != nil {
				InternalServerError(c, err)
				return
			}

			errs := r.Validate(resourceForValidation)
			if len(errs) > 0 {
				errStr := []string{}
				for _, err := range errs {
					errStr = append(errStr, err.Error())
				}

				InvalidInput(c, strings.Join(errStr, ","))
				return
			}

			var resource *T
			err = json.Unmarshal(body, &resource)
			if err != nil {
				InternalServerError(c, err)
				return
			}

			if r.acl != nil {
				if !r.acl.HasPermission(c, r.name, r.getID(resource), access.PermissionUpdate) {
					ForbiddenAccess(c)
					return
				}
			}

			if _, ok := r.beforeSave[access.PermissionUpdate]; ok {
				for _, beforeSaveFunc := range r.beforeSave[access.PermissionUpdate] {
					if err = beforeSaveFunc(c, resource); err != nil {
						var userError *UserError
						if errors.As(err, &userError) {
							CustomUserError(c, userError)
							return
						}

						InternalServerError(c, err)
						return
					}
				}
			}

			tx := r.tx(c)
			whereClauseQuery := ""
			whereClauseArgs := make([]interface{}, 0)

			primaryFieldValue := c.Param(r.PrimaryFieldURLParam())
			whereClauseQuery = fmt.Sprintf("%v = ?", r.primaryField)
			whereClauseArgs = append(whereClauseArgs, primaryFieldValue)

			table := tx.Model(r.table)
			r.omitIgnoredFields(c, access.PermissionUpdate, table)

			if r.belongsTo != nil {
				param := c.Param(r.belongsTo.PrimaryFieldURLParam())
				columnForWhereClause, parsedValue, err := parseFieldFromParam(tx, param, resourceTypeForDoc, r.belongsToField)
				if err != nil {
					InternalServerError(c, err)
					return
				}

				whereClauseQuery = fmt.Sprintf("%v = ? AND %v = ?", r.primaryField, columnForWhereClause)
				whereClauseArgs = append(whereClauseArgs, parsedValue)
			}

			if result := table.Where(whereClauseQuery, whereClauseArgs...).Save(&resource); result.Error != nil {
				InternalServerError(c, err)
				return
			}

			if _, ok := r.afterSave[access.PermissionUpdate]; ok {
				for _, afterSaveFunc := range r.afterSave[access.PermissionCreate] {
					if err = afterSaveFunc(c, resource); err != nil {
						var userError *UserError
						if errors.As(err, &userError) {
							CustomUserError(c, userError)
							return
						}

						InternalServerError(c, err)
						return
					}
				}
			}

			if f, ok := r.beforeResponse[access.PermissionUpdate]; ok {
				customResponse, err := f(c, resource)
				if err != nil {
					var userError *UserError
					if errors.As(err, &userError) {
						CustomUserError(c, userError)
						return
					}

					InternalServerError(c, err)
					return
				}
				c.WriteJSON(http.StatusOK, customResponse)
			} else {
				c.WriteJSON(http.StatusOK, resource)
			}

		})
	}

	if !r.disableUpdate {
		patchPath := path.Join(groupPath, "/", r.path, "/:"+r.PrimaryFieldURLParam())

		if r.generateDocs {
			patchDoc := openAPI.Register(&openapi.Operation{
				OperationID: "patch" + r.name,
				Method:      "PATCH",
				Path:        path.Join(routes.BasePath(), patchPath),
				Tags:        r.tags,
			}).Summary("Patches a single " + r.name).
				Description("Patches a single " + r.name + ".")

			patchDoc.Request().PathParam(r.primaryField, r.name).Description("primary id of the " + r.name).Required(true)
			patchDoc.Request().Body(resourceTypeForDoc)
		}

		routes.PATCH(patchPath, func(c router.Context) {
			if r.rbac != nil {
				if !r.rbac.HasPermission(c, permissionName, access.PermissionUpdate) {
					ForbiddenAccess(c)
					return
				}
			}

			defer c.Request().Body.Close()
			lr := io.LimitReader(c.Request().Body, r.maxInputBytes)
			body, err := io.ReadAll(lr)
			if err != nil {
				InternalServerError(c, err)
			}

			// we double unmarshal here because openapi.Validate() only works with
			// map[string]any for validation
			var resourceForValidation map[string]any
			err = json.Unmarshal(body, &resourceForValidation)
			if err != nil {
				InternalServerError(c, err)
				return
			}

			errs := r.Validate(resourceForValidation)
			if len(errs) > 0 {
				errStr := []string{}
				for _, err := range errs {
					errStr = append(errStr, err.Error())
				}

				InvalidInput(c, strings.Join(errStr, ","))
				return
			}

			var resource *T
			err = json.Unmarshal(body, &resource)
			if err != nil {
				InternalServerError(c, err)
				return
			}

			if r.acl != nil {
				if !r.acl.HasPermission(c, permissionName, r.getID(resource), access.PermissionUpdate) {
					ForbiddenAccess(c)
					return
				}
			}

			if _, ok := r.beforeSave[access.PermissionUpdate]; ok {
				for _, beforeSaveFunc := range r.beforeSave[access.PermissionUpdate] {
					if err = beforeSaveFunc(c, resource); err != nil {
						var userError *UserError
						if errors.As(err, &userError) {
							CustomUserError(c, userError)
							return
						}

						InternalServerError(c, err)
						return
					}
				}
			}

			tx := r.tx(c)
			whereClauseQuery := ""
			whereClauseArgs := make([]interface{}, 0)

			primaryFieldValue := c.Param(r.PrimaryFieldURLParam())
			whereClauseQuery = fmt.Sprintf("%v = ?", r.primaryField)
			whereClauseArgs = append(whereClauseArgs, primaryFieldValue)

			if r.belongsTo != nil {
				param := c.Param(r.belongsTo.PrimaryFieldURLParam())
				columnForWhereClause, parsedValue, err := parseFieldFromParam(tx, param, resourceTypeForDoc, r.belongsToField)
				if err != nil {
					InternalServerError(c, err)
					return
				}

				whereClauseQuery = fmt.Sprintf("%v = ? AND %v = ?", r.primaryField, columnForWhereClause)
				whereClauseArgs = append(whereClauseArgs, parsedValue)
			}
			table := tx.Model(r.table)
			r.omitIgnoredFields(c, access.PermissionUpdate, table)

			if result := table.Where(whereClauseQuery, whereClauseArgs...).Updates(&resource); result.Error != nil {
				InternalServerError(c, err)
				return
			}

			if _, ok := r.afterSave[access.PermissionUpdate]; ok {
				for _, afterSaveFunc := range r.afterSave[access.PermissionCreate] {
					if err = afterSaveFunc(c, resource); err != nil {
						var userError *UserError
						if errors.As(err, &userError) {
							CustomUserError(c, userError)
							return
						}

						InternalServerError(c, err)
						return
					}
				}
			}

			if f, ok := r.beforeResponse[access.PermissionUpdate]; ok {
				customResponse, err := f(c, resource)
				if err != nil {
					var userError *UserError
					if errors.As(err, &userError) {
						CustomUserError(c, userError)
						return
					}

					InternalServerError(c, err)
					return
				}
				c.WriteJSON(http.StatusOK, customResponse)
			} else {
				c.WriteJSON(http.StatusOK, resource)
			}
		})
	}

	if !r.disableDelete {
		deletePath := path.Join(groupPath+"/", r.path, "/:"+r.PrimaryFieldURLParam())
		if r.generateDocs {
			deleteDoc := openAPI.Register(&openapi.Operation{
				OperationID: "delete" + r.name,
				Method:      "DELETE",
				Path:        path.Join(routes.BasePath(), deletePath),
				Tags:        r.tags,
			}).Summary("Deletes a single " + r.name).
				Description("Deletes a single " + r.name + ".")
			deleteDoc.Request().PathParam(r.primaryField, r.name).Description("primary id of the " + r.name).Required(true)
		}

		routes.DELETE(deletePath, func(c router.Context) {
			if r.rbac != nil {
				if !r.rbac.HasPermission(c, permissionName, access.PermissionDelete) {
					ForbiddenAccess(c)
					return
				}
			}

			tx := r.tx(c)
			whereClauseQuery := ""
			whereClauseArgs := make([]interface{}, 0)

			primaryFieldValue := c.Param(r.PrimaryFieldURLParam())
			whereClauseQuery = fmt.Sprintf("%v = ?", r.primaryField)
			whereClauseArgs = append(whereClauseArgs, primaryFieldValue)

			if r.belongsTo != nil {
				param := c.Param(r.belongsTo.PrimaryFieldURLParam())
				columnForWhereClause, parsedValue, err := parseFieldFromParam(tx, param, resourceTypeForDoc, r.belongsToField)
				if err != nil {
					InternalServerError(c, err)
					return
				}

				whereClauseQuery = fmt.Sprintf("%v = ? AND %v = ?", r.primaryField, columnForWhereClause)
				whereClauseArgs = append(whereClauseArgs, parsedValue)
			}

			// first load the resource and verify ownership
			var resource *T
			if result := tx.Model(r.table).Where(whereClauseQuery, whereClauseArgs...).First(&resource); result.Error != nil {
				if errors.Is(result.Error, gorm.ErrRecordNotFound) {
					ResourceNotFound(c)
					return
				}

				InternalServerError(c, result.Error)
				return
			}

			if r.acl != nil {
				if !r.acl.HasPermission(c, permissionName, r.getID(resource), access.PermissionDelete) {
					ForbiddenAccess(c)
					return
				}
			}

			for _, beforeDeleteFunc := range r.beforeDelete {
				if err = beforeDeleteFunc(c, resource); err != nil {
					var userError *UserError
					if errors.As(err, &userError) {
						CustomUserError(c, userError)
						return
					}

					InternalServerError(c, err)
					return
				}
			}

			var deletedResource *T
			if err := tx.Model(r.table).Where(whereClauseQuery, whereClauseArgs...).Delete(&deletedResource).Error; err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) {
					ResourceNotFound(c)
					return
				}

				InternalServerError(c, err)
				return
			}

			for _, afterDeleteFunc := range r.afterDelete {
				if err = afterDeleteFunc(c, resource); err != nil {
					var userError *UserError
					if errors.As(err, &userError) {
						CustomUserError(c, userError)
						return
					}

					InternalServerError(c, err)
					return
				}
			}

			if f, ok := r.beforeResponse[access.PermissionDelete]; ok {
				customResponse, err := f(c, resource)
				if err != nil {
					var userError *UserError
					if errors.As(err, &userError) {
						CustomUserError(c, userError)
						return
					}

					InternalServerError(c, err)
					return
				}
				c.WriteJSON(http.StatusOK, customResponse)
			} else {
				c.WriteJSON(http.StatusOK, resource)
			}
		})
	}

	return nil
}

// GET overrides the GET method with f
func (r *Resource[T]) GET(f func(c router.Context)) {
	r.get = f
}

// POST overrides the POST method with f
func (r *Resource[T]) POST(f func(c router.Context)) {
	r.post = f
}

// PUT overrides the PUT method with f
func (r *Resource[T]) PUT(f func(c router.Context)) {
	r.put = f
}

// PATCH overrides the PATCH method with f.
func (r *Resource[T]) PATCH(f func(c router.Context)) {
	r.patch = f
}

// DELETE overrides the DELETE method with f
func (r *Resource[T]) DELETE(f func(c router.Context)) {
	r.delete = f
}

// Disable disables a list of access methods
func (r *Resource[T]) Disable(permissions []access.Permission) {
	for _, permission := range permissions {
		switch permission {
		case access.PermissionCreate:
			r.DisableCreate()
		case access.PermissionRead:
			r.DisableRead()
		case access.PermissionUpdate:
			r.DisableUpdate()
		case access.PermissionDelete:
			r.DisableDelete()
		case access.PermissionList:
			r.DisableList()
		}
	}
}

// DisableCreate disables creation on this resource
func (r *Resource[T]) DisableCreate() {
	r.disableCreate = true
}

// DisableRead disables reads on this resource
func (r *Resource[T]) DisableRead() {
	r.disableRead = true
}

// DisableUpdate disables updates on this resource
func (r *Resource[T]) DisableUpdate() {
	r.disableUpdate = true
}

// DisableDelete disables deletes on this resource
func (r *Resource[T]) DisableDelete() {
	r.disableDelete = true
}

// DisableList disables listing on this resource
func (r *Resource[T]) DisableList() {
	r.disableList = true
}

// Validate validates that the value v is a valid resource
func (r *Resource[T]) Validate(v any) []error {
	pb := openapi.NewPathBuffer([]byte(""), 0)
	res := &openapi.ValidateResult{}
	openapi.Validate(SchemaRegistry, r.schema, pb, openapi.ModeWriteToServer, v, res)

	return res.Errors
}

// MaxInputBytes sets the maximum bytes when reading a resource from a client, by default
// this is 10MB
func (r *Resource[T]) MaxInputBytes(maxInputBytes int64) {
	r.maxInputBytes = maxInputBytes
}

func valueOfType(t reflect.Type) interface{} {
	if t.Kind() == reflect.Ptr {
		return reflect.New(t.Elem()).Interface()
	}
	return reflect.New(t).Interface()
}
