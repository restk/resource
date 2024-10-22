package resource

import (
	"fmt"
	"net/http"
	"reflect"
	"strconv"
	"strings"

	"github.com/pkg/errors"
	"github.com/restk/openapi"
	"github.com/restk/resource/access"
	"github.com/restk/resource/router"
	"gorm.io/gorm"
)

type FieldQueryOperation string

var (
	FieldQueryOperationEquals            FieldQueryOperation = "="
	FieldQueryOperationLike              FieldQueryOperation = "LIKE"
	FieldQueryOperationGreaterThanEquals FieldQueryOperation = ">="
	FieldQueryOperationLessThanEquals    FieldQueryOperation = "<="
)

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
	BadRequest = func(c router.Context) {
		c.WriteJSON(http.StatusBadRequest, S{"code": 500, "message": "Invalid request"})
	}
	ForbiddenAccess = func(c router.Context) {
		c.WriteJSON(http.StatusForbidden, S{"code": 407, "message": "Forbidden access to resource"})
	}
)

type ResourceInterface interface {
	Name() string
	PrimaryField() string
	PrimaryFieldURLParam() string
}

// FieldIgnoreRole contains rules that
type FieldIgnoreRule struct {
	UnlessPermissionsAre []access.Permission
	UnlessRolesAre       []string
}

type Field struct {
	Name string
	Type reflect.Type

	Ignored     bool            // Ignored determines if this field is being ignored
	IgnoreRules FieldIgnoreRule // FieldIgnoreRule contains rules for this field to be ignored
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
	singularName string // name in singular form, if name is 'keys' then this would 'key'. This should only be used for doc purposes
	pluralName   string // name in plural form, if name is 'user', then this would be 'users'. This should only be used for doc purposes
	primaryField string
	validator    func(objectToValidate T) bool
	// hasAccess    func(c router.Context, resource string, action AccessAction) bool
	hasOwnership func(c router.Context, resource string, obj *T) bool
	getID        func(obj *T) any
	table        interface{}
	preload      []string

	// fields
	queryOperatorByField map[string]FieldQueryOperation
	columnByField        map[string]string
	fieldByJSON          map[string]string
	// fieldByExists        map[string]bool

	fields []*Field

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

	//

}

func NewResource[T any](name string, primaryField string) *Resource[T] {
	var table T

	r := &Resource[T]{
		name:         name,
		primaryField: primaryField,
		table:        table,
		// hasAccess:            DefaultHasAccess[T],
		hasOwnership:         DefaultHasOwnership[T],
		beforeSave:           make(map[access.Permission][]func(c router.Context, obj *T) error, 0),
		afterSave:            make(map[access.Permission][]func(c router.Context, obj *T) error, 0),
		beforeDelete:         make([]func(c router.Context, obj *T) error, 0),
		afterDelete:          make([]func(c router.Context, obj *T) error, 0),
		beforeResponse:       make(map[access.Permission]func(c router.Context, obj *T) (interface{}, error), 0),
		queryOperatorByField: make(map[string]FieldQueryOperation, 0),
		columnByField:        make(map[string]string, 0),
		preload:              make([]string, 0),
		pageSize:             10,
		maxPageSize:          250,
		maxLimit:             250,
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

// SetValidator sets the validator function for this object. The function passed is expected to return
// true if the object passes all validation. If the object fails it, it expects to return false.
func (r *Resource[T]) SetValidator(f func(objectToValidate T) bool) {
	r.validator = f
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
	var resource T

	typeOf := reflect.TypeOf(resource)
	fields := reflect.VisibleFields(typeOf)

	for _, field := range fields {
		if strings.EqualFold(field.Name, name) {
			return true
		}
	}

	return false
}

// IgnoreAllFields ignores all fields
func (r *Resource[T]) IgnoreAllFields() *Resource[T] {
	for _, f := range r.fields {
		f.Ignored = true
	}

	return r
}

// AllowAllFields allows all fields. note: by default all fields are already allowed unless you call Ignore methods.
func (r *Resource[T]) AllowAllFields() *Resource[T] {
	for _, f := range r.fields {
		f.Ignored = false
	}

	return r
}

func (r *Resource[T]) AllowField(name string, accessMethod []access.Permission) *Resource[T] {
	panic("not implemented")
}

// IgnoreField will ignore a field for a specific permission. You can ignore a field for: access.PermissionRead, access.PermissionWrite, access.PermissionList, access.PermissionCreate
func (r *Resource[T]) IgnoreField(name string, accessMethod []access.Permission) *Resource[T] {
	panic("not implemented")
}

// IgnoreFieldUnlessRole will ignore the field for all operations unless the requester has the roles provided. This can allow specific fields, such as join fields, to be ignored
// but they can still be updated by admins in tools.
func (r *Resource[T]) IgnoreFieldUnlessRole(name string, accessMethod []access.Permission, roles []string) *Resource[T] {
	panic("not implemented")
}

func (r *Resource[T]) IgnoreAllFieldsUnlessRole(accessMethod []access.Permission, roles []string) *Resource[T] {
	panic("not implemented")
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
		jsonTag := field.Tag.Get("json")
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
	default:
		// unhandled type
		return "", nil, errors.Errorf("type not supported, if you are a developer, you can add a new type")
	}

	return columnForWhereClause, parsedValue, nil
}

// GenerateRESTAPI generates REST API endpoints for a resource. This also handles RBAC and makes sure the calling user has permission for an action on a resource.
//
// GET /resources                  -> returns an array of resources (with a max amount per page) and filters
// GET /resources/:primaryField    -> returns a paginated list of resources (with a max amount per page) and filters
// PUT /resource     -> creates or updates a single resource (with allowable save fields)
// PUT /resources    -> creates or updates a list of resources (with allowable save fields)
// DELETE /resource  -> deletes a single resource
// DELETE /resources -> deletes a list of resources
func (r *Resource[T]) GenerateRestAPI(routes router.Router, db *gorm.DB, openAPI *openapi.Builder) error {
	// generate column names
	// TODO: add a storage interface instead of using gorm directly so Resource can be used for any other storage medium
	groupPath := ""
	permissionName := r.name
	if r.belongsTo != nil {
		groupPath = "/" + r.belongsTo.Name() + "/:" + r.belongsTo.PrimaryFieldURLParam()
		permissionName = r.belongsTo.Name() + "-" + r.name
	}

	// resourceTypeForDoc is used to give type information to OpenAPI
	// TODO: we define this twice, once as a pointer and one that is not, we should
	// unify everything to support both instead of declaring both
	var resourceTypeForDoc *T
	var resource T

	columnByField, err := generateColumnByField(db, resource)
	if err != nil {
		return err
	}
	r.columnByField = columnByField

	fieldByJSON := generateFieldByJSON(resource)
	r.fieldByJSON = fieldByJSON

	if !r.disableList {
		listPath := groupPath + "/" + r.name
		listDoc := openAPI.Register(&openapi.Operation{
			OperationID: "list" + r.name,
			Method:      "GET",
			Path:        listPath,
		}).Summary("Gets a list of " + r.name).
			Description("Get a list of " + r.name + " filtering via query params. This endpoint also supports pagination")

		listDoc.Request().QueryParam("id", r.name).Description("id of the resource")

		routes.GET(listPath, func(c router.Context) {
			if r.rbac != nil {
				if !r.rbac.HasPermission(c, permissionName, access.PermissionList) {
					ForbiddenAccess(c)
					return
				}
			}

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

			table := db.Model(r.table)

			// if this is a grouped resource, we add the primary field of the resource this belongs to
			if r.belongsTo != nil {

				param := c.Param(r.belongsTo.PrimaryFieldURLParam())
				columnForWhereClause, parsedValue, err := parseFieldFromParam(db, param, resourceTypeForDoc, r.belongsToField)
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

				column, parsedValue, err := parseFieldFromParam(db, queryParams.Get(param), resourceTypeForDoc, field)
				if err != nil {
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
		getPath := groupPath + "/" + r.name + "/:" + r.PrimaryFieldURLParam()
		getDoc := openAPI.Register(&openapi.Operation{
			OperationID: "get" + r.name,
			Method:      "GET",
			Path:        getPath,
		}).Summary("Returns a single " + r.name).
			Description("Returns a single " + r.name + " by the primary id.")

		getDoc.Request().PathParam(r.primaryField, r.name).Description("primary id of the " + r.name).Example("1").Required(true)
		getDoc.Response(http.StatusOK).Body(resourceTypeForDoc)

		routes.GET(getPath, func(c router.Context) {
			if r.rbac != nil {
				if !r.rbac.HasPermission(c, permissionName, access.PermissionRead) {
					ForbiddenAccess(c)
					return
				}
			}
			whereClauseQuery := ""
			whereClauseArgs := make([]interface{}, 0)

			primaryFieldValue := c.Param(r.PrimaryFieldURLParam())
			whereClauseQuery = fmt.Sprintf("%v = ?", r.primaryField)
			whereClauseArgs = append(whereClauseArgs, primaryFieldValue)

			if r.belongsTo != nil {
				param := c.Param(r.belongsTo.PrimaryFieldURLParam())
				columnForWhereClause, parsedValue, err := parseFieldFromParam(db, param, resourceTypeForDoc, r.belongsToField)
				if err != nil {
					InternalServerError(c, err)
					return
				}

				whereClauseQuery = fmt.Sprintf("%v = ? AND %v = ?", r.primaryField, columnForWhereClause)
				whereClauseArgs = append(whereClauseArgs, parsedValue)
			}

			var resource T
			query := db.Model(r.table).Where(whereClauseQuery, whereClauseArgs...)
			if len(r.preload) > 0 {
				for _, preload := range r.preload {
					query.Preload(preload)
				}
			}

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
		createPath := groupPath + "/" + r.name
		createDoc := openAPI.Register(&openapi.Operation{
			OperationID: "create" + r.name,
			Method:      "PUT",
			Path:        createPath,
		}).Summary("Creates a new " + r.name).
			Description("Creates a new " + r.name + ". If they already exist, this fails.")

		createDoc.Request().Body(resourceTypeForDoc)

		routes.PUT(createPath, func(c router.Context) {
			if r.rbac != nil {
				if !r.rbac.HasPermission(c, permissionName, access.PermissionCreate) {
					ForbiddenAccess(c)
					return
				}
			}

			var resource *T
			err := c.ReadJSON(&resource)
			if err != nil {
				InternalServerError(c, err)
				return
			}

			if _, ok := r.beforeSave[access.PermissionCreate]; ok {
				for _, beforeSaveFunc := range r.beforeSave[access.PermissionCreate] {
					if err = beforeSaveFunc(c, resource); err != nil {
						InternalServerError(c, err)
						return
					}
				}
			}

			// we can ignore each field that is not allowed to be updated via (db.Model(r.table).Omit("field_1")).Omit("field_2")..etc
			if result := db.Model(r.table).Create(&resource); result.Error != nil {
				InternalServerError(c, err)
				return
			}

			if r.acl != nil {
				r.acl.GrantPermissions(c, r.name, r.getID(resource), r.aclGrantPermissions)
			}

			if _, ok := r.afterSave[access.PermissionCreate]; ok {
				for _, afterSaveFunc := range r.afterSave[access.PermissionCreate] {
					if err = afterSaveFunc(c, resource); err != nil {
						InternalServerError(c, err)
						return
					}
				}
			}

			if f, ok := r.beforeResponse[access.PermissionCreate]; ok {
				customResponse, err := f(c, resource)
				if err != nil {
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
		updatePath := groupPath + "/" + r.name + "/:" + r.PrimaryFieldURLParam()
		updateDoc := openAPI.Register(&openapi.Operation{
			OperationID: "update" + r.name,
			Method:      "PUT",
			Path:        updatePath,
		}).Summary("Updates a single " + r.name).
			Description("Updates a single " + r.name + ".")

		updateDoc.Request().PathParam(r.primaryField, r.name).Description("primary id of the " + r.name).Required(true)
		updateDoc.Request().Body(resourceTypeForDoc)

		routes.PUT(updatePath, func(c router.Context) {
			if r.rbac != nil {
				if !r.rbac.HasPermission(c, permissionName, access.PermissionUpdate) {
					ForbiddenAccess(c)
					return
				}
			}

			var resource *T
			err := c.ReadJSON(&resource)
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
						InternalServerError(c, err)
						return
					}
				}
			}

			whereClauseQuery := ""
			whereClauseArgs := make([]interface{}, 0)

			primaryFieldValue := c.Param(r.PrimaryFieldURLParam())
			whereClauseQuery = fmt.Sprintf("%v = ?", r.primaryField)
			whereClauseArgs = append(whereClauseArgs, primaryFieldValue)

			if r.belongsTo != nil {
				param := c.Param(r.belongsTo.PrimaryFieldURLParam())
				columnForWhereClause, parsedValue, err := parseFieldFromParam(db, param, resourceTypeForDoc, r.belongsToField)
				if err != nil {
					InternalServerError(c, err)
					return
				}

				whereClauseQuery = fmt.Sprintf("%v = ? AND %v = ?", r.primaryField, columnForWhereClause)
				whereClauseArgs = append(whereClauseArgs, parsedValue)
			}

			if result := db.Model(r.table).Where(whereClauseQuery, whereClauseArgs...).Save(&resource); result.Error != nil {
				InternalServerError(c, err)
				return
			}

			if _, ok := r.afterSave[access.PermissionUpdate]; ok {
				for _, afterSaveFunc := range r.afterSave[access.PermissionCreate] {
					if err = afterSaveFunc(c, resource); err != nil {
						InternalServerError(c, err)
						return
					}
				}
			}

			if f, ok := r.beforeResponse[access.PermissionUpdate]; ok {
				customResponse, err := f(c, resource)
				if err != nil {
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
		patchPath := groupPath + "/" + r.name + "/:" + r.PrimaryFieldURLParam()
		patchDoc := openAPI.Register(&openapi.Operation{
			OperationID: "patch" + r.name,
			Method:      "PATCH",
			Path:        patchPath,
		}).Summary("Patches a single " + r.name).
			Description("Patches a single " + r.name + ".")

		patchDoc.Request().PathParam(r.primaryField, r.name).Description("primary id of the " + r.name).Required(true)
		patchDoc.Request().Body(resourceTypeForDoc)

		routes.PATCH(patchPath, func(c router.Context) {
			if r.rbac != nil {
				if !r.rbac.HasPermission(c, permissionName, access.PermissionUpdate) {
					ForbiddenAccess(c)
					return
				}
			}

			var resource *T
			err := c.ReadJSON(&resource)
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
						InternalServerError(c, err)
						return
					}
				}
			}

			whereClauseQuery := ""
			whereClauseArgs := make([]interface{}, 0)

			primaryFieldValue := c.Param(r.PrimaryFieldURLParam())
			whereClauseQuery = fmt.Sprintf("%v = ?", r.primaryField)
			whereClauseArgs = append(whereClauseArgs, primaryFieldValue)

			if r.belongsTo != nil {
				param := c.Param(r.belongsTo.PrimaryFieldURLParam())
				columnForWhereClause, parsedValue, err := parseFieldFromParam(db, param, resourceTypeForDoc, r.belongsToField)
				if err != nil {
					InternalServerError(c, err)
					return
				}

				whereClauseQuery = fmt.Sprintf("%v = ? AND %v = ?", r.primaryField, columnForWhereClause)
				whereClauseArgs = append(whereClauseArgs, parsedValue)
			}
			if result := db.Model(r.table).Where(whereClauseQuery, whereClauseArgs...).Updates(&resource); result.Error != nil {
				InternalServerError(c, err)
				return
			}

			if _, ok := r.afterSave[access.PermissionUpdate]; ok {
				for _, afterSaveFunc := range r.afterSave[access.PermissionCreate] {
					if err = afterSaveFunc(c, resource); err != nil {
						InternalServerError(c, err)
						return
					}
				}
			}

			if f, ok := r.beforeResponse[access.PermissionUpdate]; ok {
				customResponse, err := f(c, resource)
				if err != nil {
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
		deletePath := groupPath + "/" + r.name + "/:" + r.PrimaryFieldURLParam()
		deleteDoc := openAPI.Register(&openapi.Operation{
			OperationID: "delete" + r.name,
			Method:      "DELETE",
			Path:        deletePath,
		}).Summary("Deletes a single " + r.name).
			Description("Deletes a single " + r.name + ".")
		deleteDoc.Request().PathParam(r.primaryField, r.name).Description("primary id of the " + r.name).Required(true)

		routes.DELETE(deletePath, func(c router.Context) {
			if r.rbac != nil {
				if !r.rbac.HasPermission(c, permissionName, access.PermissionDelete) {
					ForbiddenAccess(c)
					return
				}
			}

			whereClauseQuery := ""
			whereClauseArgs := make([]interface{}, 0)

			primaryFieldValue := c.Param(r.PrimaryFieldURLParam())
			whereClauseQuery = fmt.Sprintf("%v = ?", r.primaryField)
			whereClauseArgs = append(whereClauseArgs, primaryFieldValue)

			if r.belongsTo != nil {
				param := c.Param(r.belongsTo.PrimaryFieldURLParam())
				columnForWhereClause, parsedValue, err := parseFieldFromParam(db, param, resourceTypeForDoc, r.belongsToField)
				if err != nil {
					InternalServerError(c, err)
					return
				}

				whereClauseQuery = fmt.Sprintf("%v = ? AND %v = ?", r.primaryField, columnForWhereClause)
				whereClauseArgs = append(whereClauseArgs, parsedValue)
			}

			// first load the resource and verify ownership
			var resource *T
			if result := db.Model(r.table).Where(whereClauseQuery, whereClauseArgs...).First(&resource); result.Error != nil {
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
					InternalServerError(c, err)
					return
				}
			}

			var deletedResource *T
			if err := db.Model(r.table).Where(whereClauseQuery, whereClauseArgs...).Delete(&deletedResource).Error; err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) {
					ResourceNotFound(c)
					return
				}

				InternalServerError(c, err)
				return
			}

			for _, afterDeleteFunc := range r.afterDelete {
				if err = afterDeleteFunc(c, resource); err != nil {
					InternalServerError(c, err)
					return
				}
			}

			if f, ok := r.beforeResponse[access.PermissionDelete]; ok {
				customResponse, err := f(c, resource)
				if err != nil {
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
