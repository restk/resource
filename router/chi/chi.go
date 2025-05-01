package chi

import (
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/restk/resource/router"
)

func ChiContext(r router.Context) *http.Request {
	impl := r.ContextImplementation()

	rc, ok := impl.(*http.Request)
	if !ok {
		panic("c is not a chi context")
	}

	return rc
}

type Router struct {
	chi      chi.Router
	basePath string
}

type Context struct {
	chiRequest        *http.Request
	chiResponseWriter http.ResponseWriter
	chiURLParams      chi.RouteParams
}

type QueryParams struct {
	chiRequest *http.Request
}

func (q *QueryParams) Keys() []string {
	keys := make([]string, 0)
	for key := range q.chiRequest.URL.Query() {
		keys = append(keys, key)
	}

	return keys
}

func (q *QueryParams) Get(key string) string {
	query := q.chiRequest.URL.Query()
	return query.Get(key)
}

func (q *QueryParams) Has(key string) bool {
	query := q.chiRequest.URL.Query()
	values, exists := query[key]
	return exists && len(values) > 0
}

func (c *Context) Get(key string) (interface{}, bool) {
	val := c.chiRequest.Context().Value(key)
	return val, val != nil
}

func (c *Context) Request() *http.Request {
	return c.chiRequest
}

func (c *Context) QueryParams() router.QueryParams {
	return &QueryParams{
		chiRequest: c.chiRequest,
	}
}

func (c *Context) Param(key string) string {
	return chi.URLParam(c.chiRequest, key)
}

func (c *Context) WriteJSON(code int, v interface{}) {
	c.chiResponseWriter.Header().Set("Content-Type", "application/json")
	c.chiResponseWriter.WriteHeader(code)

	encoder := json.NewEncoder(c.chiResponseWriter)

	if err := encoder.Encode(v); err != nil {
		// Since we already wrote headers, we can't change the status code now
		// Just log or handle the error as appropriate for your application
		_, _ = c.chiResponseWriter.Write([]byte("Error encoding JSON response"))
		return
	}
}

func (c *Context) ReadJSON(v interface{}) error {
	contentType := c.chiRequest.Header.Get("Content-Type")
	if contentType != "" && contentType != "application/json" && !strings.HasPrefix(contentType, "application/json;") {
		return errors.New("content-type is not application/json")
	}

	return json.NewDecoder(c.chiRequest.Body).Decode(v)
}

func (c *Context) ContextImplementation() any {
	return c.chiRequest
}

func (c *Context) Deadline() (deadline time.Time, ok bool) {
	return c.chiRequest.Context().Deadline()
}

func (c *Context) Done() <-chan struct{} {
	return c.chiRequest.Context().Done()
}

func (c *Context) Err() error {
	return c.chiRequest.Context().Err()
}

func (c *Context) Value(key any) any {
	return c.chiRequest.Context().Value(key)
}

func (c *Context) Cookie(name string) (string, error) {
	cookie, err := c.chiRequest.Cookie(name)
	if err != nil {
		return "", err
	}
	return cookie.Value, nil
}

type cookieOptions struct {
	sameSite http.SameSite
}

var (
	cookieOptionsMap   = make(map[uintptr]*cookieOptions)
	cookieOptionsMutex sync.RWMutex
)

func (c *Context) SetSameSite(sameSite http.SameSite) {
	responseWriterAddr := reflect.ValueOf(c.chiResponseWriter).Pointer()

	cookieOptionsMutex.Lock()
	defer cookieOptionsMutex.Unlock()

	options, exists := cookieOptionsMap[responseWriterAddr]
	if !exists {
		options = &cookieOptions{}
		cookieOptionsMap[responseWriterAddr] = options
	}

	options.sameSite = sameSite
}

func (c *Context) SetCookie(name string, value string, maxAge int, path string, domain string, secure bool, httpOnly bool) {
	cookie := &http.Cookie{
		Name:     name,
		Value:    value,
		MaxAge:   maxAge,
		Path:     path,
		Domain:   domain,
		Secure:   secure,
		HttpOnly: httpOnly,
	}

	responseWriterAddr := reflect.ValueOf(c.chiResponseWriter).Pointer()

	cookieOptionsMutex.RLock()
	options, exists := cookieOptionsMap[responseWriterAddr]
	cookieOptionsMutex.RUnlock()

	if exists {
		cookie.SameSite = options.sameSite
	}

	http.SetCookie(c.chiResponseWriter, cookie)
}

// NewRouter creates a new Router instance that wraps a Chi router.
// It properly handles the basePath by creating a subrouter if needed.
func NewRouter(chiRouter chi.Router, basePath string) *Router {
	var routerToUse chi.Router

	// Check if we already have a subrouter for this path.
	// This handles the case where the router might be passed as a result of a Route() call.
	if mux, ok := chiRouter.(*chi.Mux); ok && basePath != "/" {
		// Check if this is a base router or a subrouter
		if len(mux.Routes()) > 0 && strings.TrimPrefix(mux.Routes()[0].Pattern, "/") == strings.TrimPrefix(basePath, "/") {
			// It's already a subrouter for this path, so use it directly.
			routerToUse = chiRouter
		} else {
			// Mount a new subrouter for the basePath.
			routerToUse = mux.Route(basePath, func(r chi.Router) {})
		}
	} else {
		// Use the provided router directly.
		routerToUse = chiRouter
	}

	return &Router{
		chi:      routerToUse,
		basePath: basePath,
	}
}

func (r *Router) BasePath() string {
	return r.basePath
}

func toChiHandler(handlers ...router.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get route context or create a new one if it doesn't exist
		var routeParams chi.RouteParams

		rctx := chi.RouteContext(r.Context())
		if rctx != nil {
			routeParams = rctx.URLParams
		}

		ctx := &Context{
			chiRequest:        r,
			chiResponseWriter: w,
			chiURLParams:      routeParams,
		}

		for _, handler := range handlers {
			handler(ctx)

			// Check if the handler wrote a response.
			// Content-Length header is set when using http.Error or similar functions.
			if w.Header().Get("Content-Length") != "" || r.Context().Err() != nil {
				break
			}
		}

		// Clean up cookie options.
		responseWriterAddr := reflect.ValueOf(w).Pointer()
		cookieOptionsMutex.Lock()
		delete(cookieOptionsMap, responseWriterAddr)
		cookieOptionsMutex.Unlock()
	}
}

func (r *Router) GET(path string, handlers ...router.Handler) router.Router {
	r.chi.Get(path, toChiHandler(handlers...))
	return r
}

func (r *Router) DELETE(path string, handlers ...router.Handler) router.Router {
	r.chi.Delete(path, toChiHandler(handlers...))
	return r
}

func (r *Router) PUT(path string, handlers ...router.Handler) router.Router {
	r.chi.Put(path, toChiHandler(handlers...))
	return r
}

func (r *Router) PATCH(path string, handlers ...router.Handler) router.Router {
	r.chi.Patch(path, toChiHandler(handlers...))
	return r
}

func (r *Router) POST(path string, handlers ...router.Handler) router.Router {
	r.chi.Post(path, toChiHandler(handlers...))
	return r
}
