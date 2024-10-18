package handler

import (
	"net/http"
	_ "unsafe"

	_ "github.com/hoppscotch/proxyscotch/libproxy"
)

//go:linkname proxyHandler github.com/hoppscotch/proxyscotch/libproxy.proxyHandler
func proxyHandler(w http.ResponseWriter, r *http.Request)

//go:linkname allowedOrigins github.com/hoppscotch/proxyscotch/libproxy.allowedOrigins
var allowedOrigins []string

func Handler(w http.ResponseWriter, r *http.Request) {
	allowedOrigins = []string{"*"}
	proxyHandler(w, r)
}
