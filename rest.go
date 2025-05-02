package resource

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"strconv"
	"strings"

	"github.com/restk/openapi"
	"github.com/restk/resource/access"
	"github.com/restk/resource/router"
	"gorm.io/gorm"
)

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
		groupPath = path.Join("/", r.belongsTo.Name(), "/:"+r.belongsTo.PrimaryFieldURLParam())
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

func (r *Resource[T]) generateCreateEndpoint(routes router.Router, groupPath string, permissionName string, resourceTypeForDoc *T, openAPI *openapi.Builder) {
	createPath := path.Join(groupPath, "/", r.path)

	if r.generateDocs {
		createDoc := openAPI.Register(&openapi.Operation{
			OperationID: "create" + r.name,
			Method:      "PUT",
			Path:        path.Join(routes.BasePath(), createPath),
			Tags:        r.tags,
		}).Summary("Creates a new " + r.name).
			Description("Creates a new " + r.name + ". If the resource already exists, this returns an error.")

		createDoc.Request().Body(resourceTypeForDoc)
	}

	routes.POST(createPath, func(ctx router.Context) {
		if r.rbac != nil && !r.rbac.HasPermission(ctx, permissionName, access.PermissionCreate) {
			ForbiddenAccess(ctx)
			return
		}

		resource, err := r.parseAndValidateRequestBody(ctx)
		if err != nil {
			return
		}

		if err = r.runBeforeSaveHooks(ctx, resource, access.PermissionCreate); err != nil {
			return
		}

		tx := r.tx(ctx)
		table := tx.Model(r.table)
		r.omitIgnoredFields(ctx, access.PermissionCreate, table)

		if result := table.Create(&resource); result.Error != nil {
			InternalServerError(ctx, result.Error)
			return
		}

		if r.acl != nil {
			if err = r.acl.GrantPermissions(ctx, r.name, r.getID(resource), r.aclGrantPermissions); err != nil {
				InternalServerError(ctx, err)
				return
			}
		}

		if err = r.runAfterSaveHooks(ctx, resource, access.PermissionCreate); err != nil {
			return
		}

		r.sendResponse(ctx, resource, access.PermissionCreate)
	})
}

func (r *Resource[T]) generateDeleteEndpoint(routes router.Router, groupPath string, permissionName string, resourceTypeForDoc *T, openAPI *openapi.Builder) {
	deletePath := path.Join(groupPath+"/", r.path, "/{"+r.PrimaryFieldURLParam()+"}")

	if r.generateDocs {
		deleteDoc := openAPI.Register(&openapi.Operation{
			OperationID: "delete" + r.name,
			Method:      "DELETE",
			Path:        path.Join(routes.BasePath(), deletePath),
			Tags:        r.tags,
		}).
			Summary("Deletes a single " + r.name).
			Description("Deletes a single " + r.name + ".")
		deleteDoc.Request().PathParam(r.PrimaryFieldURLParam(), r.name).Description("Primary ID of the " + r.name).Required(true)
	}

	routes.DELETE(deletePath, func(ctx router.Context) {
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

		for _, beforeDeleteFunc := range r.beforeDelete {
			if err = beforeDeleteFunc(ctx, resource); err != nil {
				var userError *UserError
				if errors.As(err, &userError) {
					CustomUserError(ctx, userError)
					return
				}
				InternalServerError(ctx, err)
				return
			}
		}

		var deletedResource *T
		if err = tx.Model(r.table).Where(whereClause, whereArgs...).Delete(&deletedResource).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				ResourceNotFound(ctx)
				return
			}
			InternalServerError(ctx, err)
			return
		}

		for _, afterDeleteFunc := range r.afterDelete {
			if err = afterDeleteFunc(ctx, resource); err != nil {
				var userError *UserError
				if errors.As(err, &userError) {
					CustomUserError(ctx, userError)
					return
				}
				InternalServerError(ctx, err)
				return
			}
		}

		r.sendResponse(ctx, resource, access.PermissionDelete)
	})
}

func (r *Resource[T]) generateListEndpoint(routes router.Router, groupPath string, permissionName string, resourceTypeForDoc *T, openAPI *openapi.Builder) {
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

	routes.GET(listPath, func(ctx router.Context) {
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

			// We support lookups by the Field name or the JSON tag, first we attempt JSON.
			field, ok := r.fieldByJSON[param]
			if !ok {
				// We then attempt the original param which we assume is a Field instead of a JSON tag (validated
				// below.)
				field = param
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

			queryOperator := r.retrieveQueryFieldOperator(field)
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

		var resources []T
		if err = table.Find(&resources, ids).Error; err != nil {
			InternalServerError(ctx, err)
			return
		}

		if len(resources) == 0 {
			ResourceNotFound(ctx)
			return
		}

		ctx.WriteJSON(http.StatusOK, resources)
	})
}

func (r *Resource[T]) generateReadEndpoint(routes router.Router, groupPath string, permissionName string, resourceTypeForDoc *T, openAPI *openapi.Builder) {
	getPath := path.Join(groupPath, "/", r.path, "/{"+r.PrimaryFieldURLParam()+"}")

	if r.generateDocs {
		getDoc := openAPI.Register(&openapi.Operation{
			OperationID: "get" + r.name,
			Method:      "GET",
			Path:        path.Join(routes.BasePath(), getPath),
			Tags:        r.tags,
		}).
			Summary("Returns a single " + r.name).
			Description("Returns a single " + r.name + " by the primary ID.")

		getDoc.Request().PathParam(r.PrimaryFieldURLParam(), r.name).Description("Primary ID of the " + r.name).Example("1").Required(true)
		getDoc.Response(http.StatusOK).Body(resourceTypeForDoc)
	}

	routes.GET(getPath, func(ctx router.Context) {
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
		r.omitIgnoredFields(ctx, access.PermissionList, query)

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

func (r *Resource[T]) generateUpdateEndpoint(routes router.Router, groupPath string, permissionName string, resourceTypeForDoc *T, openAPI *openapi.Builder) {
	updatePath := path.Join(groupPath, "/", r.path, "/{"+r.PrimaryFieldURLParam()+"}")

	if r.generateDocs {
		updateDoc := openAPI.Register(&openapi.Operation{
			OperationID: "update" + r.name,
			Method:      "PUT",
			Path:        path.Join(routes.BasePath(), updatePath),
			Tags:        r.tags,
		}).Summary("Updates a single " + r.name).
			Description("Updates a single " + r.name + ".")

		updateDoc.Request().PathParam(r.PrimaryFieldURLParam(), r.name).Description("Primary ID of the " + r.name).Required(true)
		updateDoc.Request().Body(resourceTypeForDoc)
	}

	routes.PUT(updatePath, func(ctx router.Context) {
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

		if err := r.runBeforeSaveHooks(ctx, resource, access.PermissionUpdate); err != nil {
			return
		}

		tx := r.tx(ctx)
		whereClause, whereArgs, err := r.buildResourceWhereClause(ctx, resourceTypeForDoc)
		if err != nil {
			return
		}

		table := tx.Model(r.table)
		r.omitIgnoredFields(ctx, access.PermissionUpdate, table)

		if result := table.Where(whereClause, whereArgs...).Save(&resource); result.Error != nil {
			InternalServerError(ctx, result.Error)
			return
		}

		if err = r.runAfterSaveHooks(ctx, resource, access.PermissionUpdate); err != nil {
			return
		}

		r.sendResponse(ctx, resource, access.PermissionUpdate)
	})
}

func (r *Resource[T]) generateUpdatePatchEndpoint(routes router.Router, groupPath string, permissionName string, resourceTypeForDoc *T, openAPI *openapi.Builder) {
	patchPath := path.Join(groupPath, "/", r.path, "/{"+r.PrimaryFieldURLParam()+"}")

	if r.generateDocs {
		patchDoc := openAPI.Register(&openapi.Operation{
			OperationID: "patch" + r.name,
			Method:      "PATCH",
			Path:        path.Join(routes.BasePath(), patchPath),
			Tags:        r.tags,
		}).Summary("Patches a single " + r.name).
			Description("Patches a single " + r.name + ".")

		patchDoc.Request().PathParam(r.PrimaryFieldURLParam(), r.name).Description("Primary ID of the " + r.name).Required(true)
		patchDoc.Request().Body(resourceTypeForDoc)
	}

	routes.PATCH(patchPath, func(ctx router.Context) {
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

		if err = r.runBeforeSaveHooks(ctx, resource, access.PermissionUpdate); err != nil {
			return
		}

		whereClause, whereArgs, err := r.buildResourceWhereClause(ctx, resourceTypeForDoc)
		if err != nil {
			return
		}

		tx := r.tx(ctx)
		table := tx.Model(r.table)
		r.omitIgnoredFields(ctx, access.PermissionUpdate, table)

		if result := table.Where(whereClause, whereArgs...).Updates(&resource); result.Error != nil {
			InternalServerError(ctx, result.Error)
			return
		}

		if err = r.runAfterSaveHooks(ctx, resource, access.PermissionUpdate); err != nil {
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

		InvalidInput(ctx, strings.Join(errStrings, ","))
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
func (r *Resource[T]) runBeforeSaveHooks(ctx router.Context, resource *T, permission access.Permission) error {
	if hooks, ok := r.beforeSave[permission]; ok {
		for _, hook := range hooks {
			if err := hook(ctx, resource); err != nil {
				var userError *UserError
				if errors.As(err, &userError) {
					CustomUserError(ctx, userError)
					return err
				}

				InternalServerError(ctx, err)
				return err
			}
		}
	}
	return nil
}

// runAfterSaveHooks executes all registered after-save hooks.
func (r *Resource[T]) runAfterSaveHooks(ctx router.Context, resource *T, permission access.Permission) error {
	if hooks, ok := r.afterSave[permission]; ok {
		for _, hook := range hooks {
			if err := hook(ctx, resource); err != nil {
				var userError *UserError
				if errors.As(err, &userError) {
					CustomUserError(ctx, userError)
					return err
				}

				InternalServerError(ctx, err)
				return err
			}
		}
	}
	return nil
}

// buildResourceWhereClause constructs the SQL WHERE clause for resource operations.
func (r *Resource[T]) buildResourceWhereClause(ctx router.Context, resourceTypeForDoc *T) (string, []any, error) {
	whereClause := fmt.Sprintf("%v = ?", r.primaryField)
	whereArgs := []any{ctx.Param(r.PrimaryFieldURLParam())}

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

	return limit, offset, nil
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
