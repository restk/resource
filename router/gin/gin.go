package gin

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/restk/resource/router"
)

func GinContext(r router.Context) *gin.Context {
	impl := r.ContextImplementation()

	rc, ok := impl.(*gin.Context)
	if !ok {
		panic("c is not a gin context")
	}

	return rc
}

type Router struct {
	gin *gin.RouterGroup
}

type Context struct {
	ginContext *gin.Context
}

type QueryParams struct {
	ginContext *gin.Context
}

func (q *QueryParams) Keys() []string {
	keys := make([]string, 0)
	for key := range q.ginContext.Request.URL.Query() {
		keys = append(keys, key)
	}

	return keys
}

func (q *QueryParams) Get(key string) string {
	query := q.ginContext.Request.URL.Query()
	return query.Get(key)
}

func (q *QueryParams) Has(key string) bool {
	query := q.ginContext.Request.URL.Query()
	return query.Has(key)
}

func (c *Context) Get(key string) (interface{}, bool) {
	return c.ginContext.Get(key)
}

func (c *Context) Request() *http.Request {
	return c.ginContext.Request
}

func (c *Context) QueryParams() router.QueryParams {
	return &QueryParams{
		ginContext: c.ginContext,
	}
}

func (c *Context) Param(key string) string {
	return c.ginContext.Param(key)
}

func (c *Context) WriteJSON(code int, v interface{}) {
	c.ginContext.IndentedJSON(code, v)
}

func (c *Context) ReadJSON(v interface{}) error {
	return c.ginContext.BindJSON(v)
}

func (c *Context) ContextImplementation() any {
	return c.ginContext
}

func (c *Context) Deadline() (deadline time.Time, ok bool) {
	return c.ginContext.Deadline()
}

func (c *Context) Done() <-chan struct{} {
	return c.ginContext.Done()
}

func (c *Context) Err() error {
	return c.ginContext.Err()
}

func (c *Context) Value(key any) any {
	return c.ginContext.Value(key)
}

func (c *Context) Cookie(name string) (string, error) {
	return c.ginContext.Cookie(name)
}

func (c *Context) SetCookie(name string, value string, maxAge int, path string, domain string, secure bool, httpOnly bool) {
	c.ginContext.SetCookie(name, value, maxAge, path, domain, secure, httpOnly)
}

func (c *Context) SetSameSite(sameSite http.SameSite) {
	c.ginContext.SetSameSite(sameSite)
}

func NewRouter(gin *gin.RouterGroup) *Router {
	return &Router{
		gin: gin,
	}
}

func toGinHandler(handlers ...router.Handler) []gin.HandlerFunc {
	ginHandlers := make([]gin.HandlerFunc, 0)
	for _, handler := range handlers {
		ginHandlers = append(ginHandlers, func(c *gin.Context) {
			handler(&Context{
				ginContext: c,
			})
		})
	}
	return ginHandlers
}

func (r *Router) GET(path string, handlers ...router.Handler) router.Router {
	r.gin.GET(path, toGinHandler(handlers...)...)

	return r
}

func (r *Router) DELETE(path string, handlers ...router.Handler) router.Router {
	r.gin.DELETE(path, toGinHandler(handlers...)...)

	return r
}

func (r *Router) PUT(path string, handlers ...router.Handler) router.Router {
	r.gin.PUT(path, toGinHandler(handlers...)...)

	return r
}

func (r *Router) PATCH(path string, handlers ...router.Handler) router.Router {
	r.gin.PATCH(path, toGinHandler(handlers...)...)

	return r
}

func (r *Router) POST(path string, handlers ...router.Handler) router.Router {
	r.gin.POST(path, toGinHandler(handlers...)...)

	return r
}

func (r *Router) BasePath() string {
	return r.gin.BasePath()
}
