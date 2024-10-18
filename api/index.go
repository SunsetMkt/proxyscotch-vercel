package handler

import (
	"net/http"
	_ "unsafe"

	_ "github.com/hoppscotch/proxyscotch/libproxy"
)

//go:linkname proxyHandler github.com/hoppscotch/proxyscotch/libproxy.proxyHandler
func proxyHandler(w http.ResponseWriter, r *http.Request)

func Handler(w http.ResponseWriter, r *http.Request) {
	proxyHandler(w, r)
}
