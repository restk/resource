package router

import (
	"net/http"
	"time"
)

type (
	Context interface {
		Param(key string) string
		QueryParams() QueryParams
		WriteJSON(code int, v interface{})
		ReadJSON(v interface{}) error
		Request() *http.Request
		SetSameSite(sameSite http.SameSite)
		Cookie(name string) (string, error)
		SetCookie(name string, value string, maxAge int, path string, domain string, secure bool, httpOnly bool)
		Deadline() (deadline time.Time, ok bool)
		Done() <-chan struct{}
		Err() error
		Value(key any) any

		// ContextImplementation returns the underlying context.
		ContextImplementation() any
	}

	Handler func(c Context)

	QueryParams interface {
		Keys() []string
		Has(key string) bool
		Get(key string) string
	}

	Router interface {
		GET(path string, handlers ...Handler) Router
		DELETE(path string, handlers ...Handler) Router
		PATCH(path string, handlers ...Handler) Router
		PUT(path string, handlers ...Handler) Router
		POST(path string, handlers ...Handler) Router
		BasePath() string
	}
)

// MockContext implements router.Context for testing.
type MockContext struct{}

func (m *MockContext) Param(key string) string            { return "" }
func (m *MockContext) QueryParams() QueryParams           { return nil }
func (m *MockContext) WriteJSON(code int, v interface{})  {}
func (m *MockContext) ReadJSON(v interface{}) error       { return nil }
func (m *MockContext) Request() *http.Request             { return nil }
func (m *MockContext) SetSameSite(sameSite http.SameSite) {}
func (m *MockContext) Cookie(name string) (string, error) { return "", nil }
func (m *MockContext) SetCookie(name string, value string, maxAge int, path string, domain string, secure bool, httpOnly bool) {
}
func (m *MockContext) Deadline() (deadline time.Time, ok bool) { return time.Time{}, false }
func (m *MockContext) Done() <-chan struct{}                   { return nil }
func (m *MockContext) Err() error                              { return nil }
func (m *MockContext) Value(key any) any                       { return nil }
func (m *MockContext) ContextImplementation() any              { return "not a gin context" }
