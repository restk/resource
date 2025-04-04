package router

import (
	"net/http"
	"time"
)

type QueryParams interface {
	Keys() []string
	Has(key string) bool
	Get(key string) string
}

type Context interface {
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

	// ContextImplementation() returns the underlying context.
	ContextImplementation() any
}

type Handler func(c Context)

type Router interface {
	GET(path string, handlers ...Handler) Router
	DELETE(path string, handlers ...Handler) Router
	PATCH(path string, handlers ...Handler) Router
	PUT(path string, handlers ...Handler) Router
	POST(path string, handlers ...Handler) Router
}
