package chi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/restk/resource/router"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestContextAdapter tests the context-conversion function.
func TestContextAdapter(t *testing.T) {
	t.Run("successful conversion", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		w := httptest.NewRecorder()
		ctx := &Context{chiRequest: req, chiResponseWriter: w}

		result := ChiContext(ctx)
		assert.Equal(t, req, result, "Should return the original http request")
	})

	t.Run("panic on wrong context type", func(t *testing.T) {
		mockCtx := &router.MockContext{}
		assert.Panics(t, func() {
			ChiContext(mockCtx)
		}, "Should panic when context is not a chi context")
	})
}

// TestQueryParams tests the QueryParams implementation.
func TestQueryParams(t *testing.T) {
	t.Run("Keys returns all query parameter keys", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/?key1=value1&key2=value2&key3=value3", nil)
		queryParams := &QueryParams{chiRequest: req}

		keys := queryParams.Keys()
		assert.ElementsMatch(t, []string{"key1", "key2", "key3"}, keys, "Should return all query parameter keys")
	})

	t.Run("Get returns query parameter value", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/?key1=value1&key2=value2", nil)
		queryParams := &QueryParams{chiRequest: req}

		value := queryParams.Get("key1")
		assert.Equal(t, "value1", value, "Should return the correct value for the key")
	})

	t.Run("Get returns empty string for non-existent key", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/?key1=value1", nil)
		queryParams := &QueryParams{chiRequest: req}

		value := queryParams.Get("nonexistent")
		assert.Equal(t, "", value, "Should return empty string for non-existent key")
	})

	t.Run("Has returns true for existing key", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/?key1=value1&key2=value2", nil)
		queryParams := &QueryParams{chiRequest: req}

		exists := queryParams.Has("key1")
		assert.True(t, exists, "Should return true for existing key")
	})

	t.Run("Has returns false for non-existent key", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/?key1=value1", nil)
		queryParams := &QueryParams{chiRequest: req}

		exists := queryParams.Has("nonexistent")
		assert.False(t, exists, "Should return false for non-existent key")
	})
}

// TestContext tests the Context wrapper around chi.Request.
func TestContext(t *testing.T) {
	setup := func() (*Context, *httptest.ResponseRecorder) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		return &Context{chiRequest: req, chiResponseWriter: w}, w
	}

	t.Run("Get returns stored value", func(t *testing.T) {
		ctx, _ := setup()
		ctx.chiRequest = ctx.chiRequest.WithContext(context.WithValue(ctx.chiRequest.Context(), "testKey", "testValue"))

		value, exists := ctx.Get("testKey")
		assert.True(t, exists, "Should indicate that the key exists")
		assert.Equal(t, "testValue", value, "Should return the stored value")
	})

	t.Run("Get returns false for non-existent key", func(t *testing.T) {
		ctx, _ := setup()
		_, exists := ctx.Get("nonexistent")
		assert.False(t, exists, "Should indicate that the key does not exist")
	})

	t.Run("Request returns the original request", func(t *testing.T) {
		ctx, _ := setup()
		req := ctx.chiRequest

		result := ctx.Request()
		assert.Equal(t, req, result, "Should return the original request")
	})

	t.Run("QueryParams returns a QueryParams instance", func(t *testing.T) {
		ctx, _ := setup()
		ctx.chiRequest = httptest.NewRequest(http.MethodGet, "/?key=value", nil)

		queryParams := ctx.QueryParams()
		assert.NotNil(t, queryParams, "Should return a QueryParams instance")
		assert.Equal(t, "value", queryParams.Get("key"), "Should return correct query params")
	})

	t.Run("Param returns route parameter via chi.URLParam", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := chi.NewRouter()
		var paramValue string

		r.Get("/users/{id}", func(w http.ResponseWriter, r *http.Request) {
			ctx := &Context{chiRequest: r, chiResponseWriter: w}
			paramValue = ctx.Param("id")
		})

		req := httptest.NewRequest(http.MethodGet, "/users/123", nil)
		r.ServeHTTP(w, req)
		assert.Equal(t, "123", paramValue, "Should return the route parameter value")
	})

	t.Run("WriteJSON writes JSON response", func(t *testing.T) {
		ctx, w := setup()
		data := map[string]string{"key": "value"}

		ctx.WriteJSON(http.StatusOK, data)
		assert.Equal(t, http.StatusOK, w.Code, "Should set status code")
		assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

		var response map[string]string
		err := json.NewDecoder(w.Body).Decode(&response)
		require.NoError(t, err)
		assert.Equal(t, data, response)
	})

	t.Run("ReadJSON parses JSON request body", func(t *testing.T) {
		_, w := setup()
		data := map[string]string{"key": "value"}
		body, _ := json.Marshal(data)
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		ctx := &Context{chiRequest: req, chiResponseWriter: w}

		var result map[string]string
		err := ctx.ReadJSON(&result)
		require.NoError(t, err)
		assert.Equal(t, data, result)
	})

	t.Run("ContextImplementation returns the http request", func(t *testing.T) {
		ctx, _ := setup()
		req := ctx.chiRequest
		result := ctx.ContextImplementation()
		assert.Equal(t, req, result, "Should return the http request")
	})

	t.Run("Context interface methods delegate to request context", func(t *testing.T) {
		ctx, _ := setup()
		cancelCtx, cancel := context.WithCancel(ctx.chiRequest.Context())
		ctx.chiRequest = ctx.chiRequest.WithContext(cancelCtx)

		assert.NotNil(t, ctx.Done())
		require.NoError(t, ctx.Err())

		cancel()
		assert.Equal(t, context.Canceled, ctx.Err())

		deadline, ok := ctx.Deadline()
		assert.Equal(t, time.Time{}, deadline)
		assert.False(t, ok)
		assert.Nil(t, ctx.Value("test"))
	})

	t.Run("Cookie returns cookie value", func(t *testing.T) {
		ctx, _ := setup()
		req := ctx.chiRequest
		req.AddCookie(&http.Cookie{Name: "testCookie", Value: "testValue"})

		value, err := ctx.Cookie("testCookie")
		require.NoError(t, err)
		assert.Equal(t, "testValue", value)
	})

	t.Run("Cookie returns error for non-existent cookie", func(t *testing.T) {
		ctx, _ := setup()
		_, err := ctx.Cookie("nonexistent")
		assert.Error(t, err)
	})

	t.Run("SetCookie sets cookie", func(t *testing.T) {
		ctx, w := setup()
		ctx.SetCookie("testCookie", "testValue", 3600, "/", "example.com", true, true)

		cookies := w.Result().Cookies()
		require.Len(t, cookies, 1)
		assert.Equal(t, "testCookie", cookies[0].Name)
		assert.Equal(t, "testValue", cookies[0].Value)
		assert.Equal(t, 3600, cookies[0].MaxAge)
		assert.Equal(t, "/", cookies[0].Path)
		assert.Equal(t, "example.com", cookies[0].Domain)
		assert.True(t, cookies[0].Secure)
		assert.True(t, cookies[0].HttpOnly)
	})

	t.Run("SetSameSite sets SameSite cookie attribute", func(t *testing.T) {
		ctx, w := setup()
		ctx.SetSameSite(http.SameSiteStrictMode)
		ctx.SetCookie("testCookie", "testValue", 3600, "/", "example.com", true, true)

		cookies := w.Result().Cookies()
		require.Len(t, cookies, 1)
		assert.Equal(t, http.SameSiteStrictMode, cookies[0].SameSite)
	})
}

// TestRouter tests the Router implementation.
func TestRouter(t *testing.T) {
	setupRouter := func() (*chi.Mux, *Router) {
		mux := chi.NewRouter()
		r := NewRouter(mux, "/api")
		return mux, r
	}

	testHandler := func(method string) router.Handler {
		return func(c router.Context) {
			c.WriteJSON(http.StatusOK, map[string]string{"method": method})
		}
	}

	testEndpoint := func(t *testing.T, mux *chi.Mux, method, path, expected string) {
		req := httptest.NewRequest(method, path, nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var resp map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, expected, resp["method"])
	}

	t.Run("GET registers route and processes request", func(t *testing.T) {
		mux, r := setupRouter()
		r.GET("/get", testHandler("GET"))
		testEndpoint(t, mux, "GET", "/api/get", "GET")
	})
	t.Run("DELETE registers route and processes request", func(t *testing.T) {
		mux, r := setupRouter()
		r.DELETE("/delete", testHandler("DELETE"))
		testEndpoint(t, mux, "DELETE", "/api/delete", "DELETE")
	})
	t.Run("PUT registers route and processes request", func(t *testing.T) {
		mux, r := setupRouter()
		r.PUT("/put", testHandler("PUT"))
		testEndpoint(t, mux, "PUT", "/api/put", "PUT")
	})
	t.Run("PATCH registers route and processes request", func(t *testing.T) {
		mux, r := setupRouter()
		r.PATCH("/patch", testHandler("PATCH"))
		testEndpoint(t, mux, "PATCH", "/api/patch", "PATCH")
	})
	t.Run("POST registers route and processes request", func(t *testing.T) {
		mux, r := setupRouter()
		r.POST("/post", testHandler("POST"))
		testEndpoint(t, mux, "POST", "/api/post", "POST")
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
		mux := chi.NewRouter()
		r := NewRouter(mux, "/api/v1")
		assert.Equal(t, "/api/v1", r.BasePath())
	})
	t.Run("Multiple handlers are executed in order", func(t *testing.T) {
		mux, r := setupRouter()
		var order []string
		r.GET("/multi",
			func(c router.Context) { order = append(order, "first") },
			func(c router.Context) {
				order = append(order, "second")
				c.WriteJSON(http.StatusOK, map[string]interface{}{"order": order})
			},
		)
		req := httptest.NewRequest(http.MethodGet, "/api/multi", nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, []string{"first", "second"}, order)
	})
}

// TestToAdapterHandler tests the handler-conversion function.
func TestToAdapterHandler(t *testing.T) {
	t.Run("converts router.Handler to http.HandlerFunc", func(t *testing.T) {
		var called bool
		handler := func(c router.Context) {
			called = true
			assert.IsType(t, &Context{}, c)
		}

		chiHandler := toChiHandler(handler)
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/test", nil)

		// Attach chi.RouteCtxKey to avoid nil pointer.
		rctx := chi.NewRouteContext()
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		chiHandler(w, req)
		assert.True(t, called)
	})

	t.Run("converts multiple handlers", func(t *testing.T) {
		var callCount int
		h1 := func(c router.Context) { callCount++ }
		h2 := func(c router.Context) { callCount++ }
		h3 := func(c router.Context) { callCount++ }

		chiHandler := toChiHandler(h1, h2, h3)
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rCtx := chi.NewRouteContext()
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rCtx))

		chiHandler(w, req)
		assert.Equal(t, 3, callCount)
	})
}
