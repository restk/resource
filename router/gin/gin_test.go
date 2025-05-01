package gin

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/restk/resource/router"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func init() {
	gin.SetMode(gin.ReleaseMode)
}

// TestContextAdapter tests the context-conversion function.
func TestContextAdapter(t *testing.T) {
	t.Run("successful conversion", func(t *testing.T) {
		ginCtx, _ := gin.CreateTestContext(httptest.NewRecorder())
		ctx := &Context{ginContext: ginCtx}

		result := GinContext(ctx)

		assert.Equal(t, ginCtx, result, "Should return the original gin context")
	})

	t.Run("panic on wrong context type", func(t *testing.T) {
		mockCtx := &router.MockContext{}

		assert.Panics(t, func() {
			GinContext(mockCtx)
		}, "Should panic when context is not a gin context")
	})
}

// TestQueryParams tests the QueryParams implementation.
func TestQueryParams(t *testing.T) {
	t.Run("Keys returns all query parameter keys", func(t *testing.T) {
		w := httptest.NewRecorder()
		ginCtx, _ := gin.CreateTestContext(w)
		req := httptest.NewRequest(http.MethodGet, "/?key1=value1&key2=value2&key3=value3", nil)
		ginCtx.Request = req
		queryParams := &QueryParams{ginContext: ginCtx}

		keys := queryParams.Keys()
		assert.ElementsMatch(t, []string{"key1", "key2", "key3"}, keys, "Should return all query parameter keys")
	})

	t.Run("Get returns query parameter value", func(t *testing.T) {
		w := httptest.NewRecorder()
		ginCtx, _ := gin.CreateTestContext(w)
		req := httptest.NewRequest(http.MethodGet, "/?key1=value1&key2=value2", nil)
		ginCtx.Request = req
		queryParams := &QueryParams{ginContext: ginCtx}

		value := queryParams.Get("key1")
		assert.Equal(t, "value1", value, "Should return the correct value for the key")
	})

	t.Run("Get returns empty string for non-existent key", func(t *testing.T) {
		w := httptest.NewRecorder()
		ginCtx, _ := gin.CreateTestContext(w)
		req := httptest.NewRequest(http.MethodGet, "/?key1=value1", nil)
		ginCtx.Request = req
		queryParams := &QueryParams{ginContext: ginCtx}

		value := queryParams.Get("nonexistent")
		assert.Equal(t, "", value, "Should return empty string for non-existent key")
	})

	t.Run("Has returns true for existing key", func(t *testing.T) {
		w := httptest.NewRecorder()
		ginCtx, _ := gin.CreateTestContext(w)
		req := httptest.NewRequest(http.MethodGet, "/?key1=value1&key2=value2", nil)
		ginCtx.Request = req
		queryParams := &QueryParams{ginContext: ginCtx}

		exists := queryParams.Has("key1")
		assert.True(t, exists, "Should return true for existing key")
	})

	t.Run("Has returns false for non-existent key", func(t *testing.T) {
		w := httptest.NewRecorder()
		ginCtx, _ := gin.CreateTestContext(w)
		req := httptest.NewRequest(http.MethodGet, "/?key1=value1", nil)
		ginCtx.Request = req
		queryParams := &QueryParams{ginContext: ginCtx}

		exists := queryParams.Has("nonexistent")
		assert.False(t, exists, "Should return false for non-existent key")
	})
}

// TestContext tests the Context wrapper around gin.Context.
func TestContext(t *testing.T) {
	t.Run("Get returns stored value", func(t *testing.T) {
		w := httptest.NewRecorder()
		ginCtx, _ := gin.CreateTestContext(w)
		ginCtx.Set("testKey", "testValue")
		ctx := &Context{ginContext: ginCtx}

		value, exists := ctx.Get("testKey")
		assert.True(t, exists, "Should indicate that the key exists")
		assert.Equal(t, "testValue", value, "Should return the stored value")
	})

	t.Run("Get returns false for non-existent key", func(t *testing.T) {
		w := httptest.NewRecorder()
		ginCtx, _ := gin.CreateTestContext(w)
		ctx := &Context{ginContext: ginCtx}

		_, exists := ctx.Get("nonexistent")
		assert.False(t, exists, "Should indicate that the key does not exist")
	})

	t.Run("Request returns the original request", func(t *testing.T) {
		w := httptest.NewRecorder()
		ginCtx, _ := gin.CreateTestContext(w)
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		ginCtx.Request = req
		ctx := &Context{ginContext: ginCtx}

		result := ctx.Request()
		assert.Equal(t, req, result, "Should return the original request")
	})

	t.Run("QueryParams returns a QueryParams instance", func(t *testing.T) {
		w := httptest.NewRecorder()
		ginCtx, _ := gin.CreateTestContext(w)
		req := httptest.NewRequest(http.MethodGet, "/?key=value", nil)
		ginCtx.Request = req
		ctx := &Context{ginContext: ginCtx}

		queryParams := ctx.QueryParams()
		assert.NotNil(t, queryParams, "Should return a QueryParams instance")
		assert.Equal(t, "value", queryParams.Get("key"), "Should return correct query params")
	})

	t.Run("Param returns route parameter", func(t *testing.T) {
		w := httptest.NewRecorder()
		ginCtx, _ := gin.CreateTestContext(w)
		ginCtx.Params = []gin.Param{{Key: "id", Value: "123"}}
		ctx := &Context{ginContext: ginCtx}

		value := ctx.Param("id")
		assert.Equal(t, "123", value, "Should return the route parameter value")
	})

	t.Run("WriteJSON writes JSON response", func(t *testing.T) {
		w := httptest.NewRecorder()
		ginCtx, _ := gin.CreateTestContext(w)
		ctx := &Context{ginContext: ginCtx}
		data := map[string]string{"key": "value"}

		ctx.WriteJSON(http.StatusOK, data)
		assert.Equal(t, http.StatusOK, w.Code, "Should set the correct status code")

		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err, "Response should be valid JSON")
		assert.Equal(t, data, response, "Should write the correct JSON data")
	})

	t.Run("ReadJSON parses JSON request body", func(t *testing.T) {
		w := httptest.NewRecorder()
		ginCtx, _ := gin.CreateTestContext(w)
		data := map[string]string{"key": "value"}
		body, _ := json.Marshal(data)
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		ginCtx.Request = req
		ctx := &Context{ginContext: ginCtx}

		var result map[string]string
		err := ctx.ReadJSON(&result)
		require.NoError(t, err, "Should parse JSON without error")
		assert.Equal(t, data, result, "Should parse the correct JSON data")
	})

	t.Run("ContextImplementation returns the gin context", func(t *testing.T) {
		w := httptest.NewRecorder()
		ginCtx, _ := gin.CreateTestContext(w)
		ctx := &Context{ginContext: ginCtx}

		result := ctx.ContextImplementation()
		assert.Equal(t, ginCtx, result, "Should return the original gin context")
	})

	t.Run("Context interface methods delegate to gin context", func(t *testing.T) {
		w := httptest.NewRecorder()
		ginCtx, _ := gin.CreateTestContext(w)
		ctx := &Context{ginContext: ginCtx}

		deadline, ok := ctx.Deadline()
		assert.Equal(t, time.Time{}, deadline, "Deadline should match gin context")
		assert.False(t, ok, "Deadline ok should match gin context")

		assert.Nil(t, ctx.Done(), "Done should return a channel")
		require.NoError(t, ctx.Err(), "Err should return nil for new context")
		assert.Nil(t, ctx.Value("test"), "Value should return nil for non-existent key")
	})

	t.Run("Cookie returns cookie value", func(t *testing.T) {
		w := httptest.NewRecorder()
		ginCtx, _ := gin.CreateTestContext(w)
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(&http.Cookie{Name: "testCookie", Value: "testValue"})
		ginCtx.Request = req
		ctx := &Context{ginContext: ginCtx}

		value, err := ctx.Cookie("testCookie")
		require.NoError(t, err, "Should not return error for existing cookie")
		assert.Equal(t, "testValue", value, "Should return correct cookie value")
	})

	t.Run("Cookie returns error for non-existent cookie", func(t *testing.T) {
		w := httptest.NewRecorder()
		ginCtx, _ := gin.CreateTestContext(w)
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		ginCtx.Request = req
		ctx := &Context{ginContext: ginCtx}

		_, err := ctx.Cookie("nonexistent")
		assert.Error(t, err, "Should return error for non-existent cookie")
	})

	t.Run("SetCookie sets cookie", func(t *testing.T) {
		w := httptest.NewRecorder()
		ginCtx, _ := gin.CreateTestContext(w)
		ctx := &Context{ginContext: ginCtx}

		ctx.SetCookie("testCookie", "testValue", 3600, "/", "example.com", true, true)
		cookies := w.Result().Cookies()
		require.Len(t, cookies, 1, "Should set exactly one cookie")
		assert.Equal(t, "testCookie", cookies[0].Name)
		assert.Equal(t, "testValue", cookies[0].Value)
		assert.Equal(t, 3600, cookies[0].MaxAge)
		assert.Equal(t, "/", cookies[0].Path)
		assert.Equal(t, "example.com", cookies[0].Domain)
		assert.True(t, cookies[0].Secure)
		assert.True(t, cookies[0].HttpOnly)
	})

	t.Run("SetSameSite sets SameSite cookie attribute", func(t *testing.T) {
		w := httptest.NewRecorder()
		ginCtx, _ := gin.CreateTestContext(w)
		ctx := &Context{ginContext: ginCtx}

		ctx.SetSameSite(http.SameSiteStrictMode)
		ctx.SetCookie("testCookie", "testValue", 3600, "/", "example.com", true, true)

		cookies := w.Result().Cookies()
		require.Len(t, cookies, 1, "Should set exactly one cookie")
		assert.Equal(t, http.SameSiteStrictMode, cookies[0].SameSite)
	})
}

// TestRouter tests the Router implementation.
func TestRouter(t *testing.T) {
	setupRouter := func() (*gin.Engine, *Router) {
		gin.SetMode(gin.TestMode)
		engine := gin.New()
		group := engine.Group("/api")
		r := NewRouter(group)
		return engine, r
	}

	testHandler := func(method string) router.Handler {
		return func(c router.Context) {
			c.WriteJSON(http.StatusOK, map[string]string{"method": method})
		}
	}

	testEndpoint := func(t *testing.T, engine *gin.Engine, method, path, expectedMethod string) {
		req := httptest.NewRequest(method, path, nil)
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, expectedMethod, response["method"])
	}

	t.Run("GET registers route and processes request", func(t *testing.T) {
		engine, r := setupRouter()
		r.GET("/get", testHandler("GET"))
		testEndpoint(t, engine, "GET", "/api/get", "GET")
	})
	t.Run("DELETE registers route and processes request", func(t *testing.T) {
		engine, r := setupRouter()
		r.DELETE("/delete", testHandler("DELETE"))
		testEndpoint(t, engine, "DELETE", "/api/delete", "DELETE")
	})
	t.Run("PUT registers route and processes request", func(t *testing.T) {
		engine, r := setupRouter()
		r.PUT("/put", testHandler("PUT"))
		testEndpoint(t, engine, "PUT", "/api/put", "PUT")
	})
	t.Run("PATCH registers route and processes request", func(t *testing.T) {
		engine, r := setupRouter()
		r.PATCH("/patch", testHandler("PATCH"))
		testEndpoint(t, engine, "PATCH", "/api/patch", "PATCH")
	})
	t.Run("POST registers route and processes request", func(t *testing.T) {
		engine, r := setupRouter()
		r.POST("/post", testHandler("POST"))
		testEndpoint(t, engine, "POST", "/api/post", "POST")
	})
	t.Run("Router methods return the router for chaining", func(t *testing.T) {
		_, r := setupRouter()
		assert.Equal(t, r, r.GET("/get", testHandler("GET")))
		assert.Equal(t, r, r.DELETE("/delete", testHandler("DELETE")))
		assert.Equal(t, r, r.PUT("/put", testHandler("PUT")))
		assert.Equal(t, r, r.PATCH("/patch", testHandler("PATCH")))
		assert.Equal(t, r, r.POST("/post", testHandler("POST")))
	})
	t.Run("BasePath returns the base path of the router", func(t *testing.T) {
		engine := gin.New()
		group := engine.Group("/api/v1")
		r := NewRouter(group)
		assert.Equal(t, "/api/v1", r.BasePath())
	})
	t.Run("Multiple handlers are executed in order", func(t *testing.T) {
		engine, r := setupRouter()
		var order []string
		chain := []func(c router.Context){
			func(c router.Context) { order = append(order, "first") },
			func(c router.Context) {
				order = append(order, "second")
				c.WriteJSON(http.StatusOK, map[string]interface{}{"order": order})
			},
		}
		r.GET("/multi", chain[0], chain[1])
		req := httptest.NewRequest(http.MethodGet, "/api/multi", nil)
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, []string{"first", "second"}, order)
	})
}

// TestToAdapterHandler tests the handler-conversion function.
func TestToAdapterHandler(t *testing.T) {
	t.Run("converts router.Handler to gin.HandlerFunc", func(t *testing.T) {
		var called bool
		handler := func(c router.Context) {
			called = true
			assert.IsType(t, &Context{}, c)
		}
		ginHandlers := toGinHandler(handler)
		require.Len(t, ginHandlers, 1)
		w := httptest.NewRecorder()
		ginCtx, _ := gin.CreateTestContext(w)
		ginHandlers[0](ginCtx)
		assert.True(t, called)
	})

	t.Run("converts multiple handlers", func(t *testing.T) {
		var callCount int
		h1 := func(c router.Context) { callCount++ }
		h2 := func(c router.Context) { callCount++ }
		h3 := func(c router.Context) { callCount++ }
		ginHandlers := toGinHandler(h1, h2, h3)
		require.Len(t, ginHandlers, 3)
		w := httptest.NewRecorder()
		ginCtx, _ := gin.CreateTestContext(w)
		for _, h := range ginHandlers {
			h(ginCtx)
		}
		assert.Equal(t, 3, callCount)
	})
}
