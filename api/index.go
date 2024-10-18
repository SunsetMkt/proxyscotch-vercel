package handler

import (
	"net/http"
	_ "unsafe"
)

//go:linkname proxyHandler github.com/hoppscotch/proxyscotch.libproxy.proxyHandler
func proxyHandler(w http.ResponseWriter, r *http.Request)

func Handler(w http.ResponseWriter, r *http.Request) {
	proxyHandler(w, r)
}
