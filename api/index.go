package handler

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

var (
	accessToken    string
	allowedOrigins []string
	bannedOutputs  []string
	bannedDests    []string
)

const maxMemory = int64(32 << 20)

type proxyRequestData struct {
	AccessToken string
	WantsBinary bool
	Method      string
	Url         string
	Auth        struct {
		Username string
		Password string
	}
	Headers map[string]string
	Data    string
	Params  map[string]string
}

type proxyResponseData struct {
	Success    bool              `json:"success"`
	IsBinary   bool              `json:"isBinary"`
	Status     int               `json:"status"`
	Data       string            `json:"data"`
	StatusText string            `json:"statusText"`
	Headers    map[string]string `json:"headers"`
}

const errorBodyInvalidRequest = "{\"success\": false, \"data\":{\"message\":\"(Proxy Error) Invalid request.\"}}"
const errorBodyProxyRequestFailed = "{\"success\": false, \"data\":{\"message\":\"(Proxy Error) Request failed.\"}}"

func isAllowedDest(dest string) bool {
	for _, b := range bannedDests {
		if b == dest {
			return false
		}
	}
	return true
}

func matchWildcard(pattern, str string) bool {
	if !strings.Contains(pattern, "*") {
		return pattern == str
	}
	if strings.HasPrefix(pattern, "*.") {
		domain := strings.TrimPrefix(pattern, "*.")
		if strings.HasSuffix(str, "."+domain) {
			return true
		}
		if str == domain {
			return true
		}
	} else if strings.HasSuffix(pattern, ".*") {
		prefix := strings.TrimSuffix(pattern, ".*")
		if strings.HasPrefix(str, prefix) {
			return true
		}
	} else if pattern == "*" {
		return true
	}
	return false
}

func isAllowedOrigin(origin string) bool {
	if len(allowedOrigins) > 0 && allowedOrigins[0] == "*" {
		return true
	}
	for _, allowedPattern := range allowedOrigins {
		if allowedPattern == origin {
			return true
		}
		if matchWildcard(allowedPattern, origin) {
			return true
		}
	}
	return false
}

func headerToArray(header http.Header) map[string]string {
	res := make(map[string]string)
	for name, values := range header {
		for _, value := range values {
			res[strings.ToLower(name)] = value
		}
	}
	return res
}

func proxyHandler(response http.ResponseWriter, request *http.Request) {
	response.Header().Add("Access-Control-Allow-Headers", "*")

	if request.Method == "OPTIONS" {
		response.Header().Add("Access-Control-Allow-Origin", "*")
		response.WriteHeader(200)
		return
	}

	origin := request.Header.Get("Origin")
	if origin == "" || !isAllowedOrigin(origin) {
		if strings.HasPrefix(request.Header.Get("Content-Type"), "application/json") {
			response.Header().Add("Access-Control-Allow-Headers", "*")
			response.Header().Add("Access-Control-Allow-Origin", "*")
			response.WriteHeader(200)
			_, _ = fmt.Fprintln(response, errorBodyProxyRequestFailed)
			return
		}
		response.Header().Add("Location", "https://hoppscotch.io/")
		response.WriteHeader(301)
		return
	}

	response.Header().Add("Access-Control-Allow-Origin", origin)
	response.Header().Add("Content-Type", "application/json; charset=utf-8")

	if request.Method != "POST" {
		_, _ = fmt.Fprintln(response, "{\"success\": true, \"data\":{\"isProtected\":"+strconv.FormatBool(len(accessToken) > 0)+"}}")
		return
	}

	var reqData proxyRequestData
	isMultipart := strings.HasPrefix(request.Header.Get("content-type"), "multipart/form-data")
	multipartRequestDataKey := request.Header.Get("multipart-part-key")
	if multipartRequestDataKey == "" {
		multipartRequestDataKey = "proxyRequestData"
	}

	if isMultipart {
		err := request.ParseMultipartForm(maxMemory)
		if err != nil {
			_, _ = fmt.Fprintln(response, errorBodyInvalidRequest)
			return
		}
		if request.MultipartForm == nil || request.MultipartForm.Value == nil {
			_, _ = fmt.Fprintln(response, errorBodyInvalidRequest)
			return
		}
		r, exists := request.MultipartForm.Value[multipartRequestDataKey]
		if !exists || len(r) == 0 {
			_, _ = fmt.Fprintln(response, errorBodyInvalidRequest)
			return
		}
		err = json.Unmarshal([]byte(r[0]), &reqData)
		if err != nil || len(reqData.Url) == 0 || len(reqData.Method) == 0 {
			_, _ = fmt.Fprintln(response, errorBodyInvalidRequest)
			return
		}
	} else {
		err := json.NewDecoder(request.Body).Decode(&reqData)
		if err != nil || len(reqData.Url) == 0 || len(reqData.Method) == 0 {
			_, _ = fmt.Fprintln(response, errorBodyInvalidRequest)
			return
		}
	}

	if len(accessToken) > 0 && reqData.AccessToken != accessToken {
		_, _ = fmt.Fprintln(response, "{\"success\": false, \"data\":{\"message\":\"(Proxy Error) Unauthorized request; you may need to set your access token in Settings.\"}}")
		return
	}

	if len(strings.TrimSpace(reqData.Url)) == 0 {
		_, _ = fmt.Fprintln(response, "{\"success\": false, \"data\":{\"message\":\"(Proxy Error) URL cannot be empty\"}}")
		return
	}

	var pr http.Request
	pr.Header = make(http.Header)
	pr.Method = reqData.Method

	parsedURL, err := url.Parse(reqData.Url)
	if err != nil || parsedURL == nil {
		_, _ = fmt.Fprintln(response, "{\"success\": false, \"data\":{\"message\":\"(Proxy Error) Invalid URL.\"}}")
		return
	}
	pr.URL = parsedURL

	if !isAllowedDest(pr.URL.Hostname()) {
		_, _ = fmt.Fprintln(response, "{\"success\": false, \"data\":{\"message\":\"(Proxy Error) Request cannot be to this destination.\"}}")
		return
	}

	params := pr.URL.Query()
	for k, v := range reqData.Params {
		params.Set(k, v)
	}
	pr.URL.RawQuery = params.Encode()

	if len(reqData.Auth.Username) > 0 && len(reqData.Auth.Password) > 0 {
		pr.SetBasicAuth(reqData.Auth.Username, reqData.Auth.Password)
	}

	for k, v := range reqData.Headers {
		pr.Header.Set(k, v)
	}

	if os.Getenv("ENABLE_X_FORWARDED_FOR") != "false" {
		pr.Header.Set("X-Forwarded-For", request.RemoteAddr)
	}
	if os.Getenv("ENABLE_VIA_HEADER") != "false" {
		pr.Header.Set("Via", "Proxyscotch/1.1")
	}

	if len(strings.TrimSpace(pr.Header.Get("User-Agent"))) < 1 {
		pr.Header.Set("User-Agent", "Proxyscotch/1.1")
	}

	if isMultipart {
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)

		for key := range request.MultipartForm.Value {
			if key == multipartRequestDataKey {
				continue
			}
			for _, val := range request.MultipartForm.Value[key] {
				_ = writer.WriteField(key, val)
			}
		}

		for fileKey := range request.MultipartForm.File {
			for _, val := range request.MultipartForm.File[fileKey] {
				f, err := val.Open()
				if err != nil {
					continue
				}
				field, err := writer.CreatePart(val.Header)
				if err != nil {
					_ = f.Close()
					continue
				}
				_, _ = io.Copy(field, f)
				_ = f.Close()
			}
		}

		err := writer.Close()
		if err != nil {
			_, _ = fmt.Fprintln(response, errorBodyProxyRequestFailed)
			return
		}

		pr.Header.Set("content-type", fmt.Sprintf("multipart/form-data; boundary=%v", writer.Boundary()))
		pr.Body = io.NopCloser(bytes.NewReader(body.Bytes()))
		pr.ContentLength = int64(len(body.Bytes()))
	} else if len(reqData.Data) > 0 {
		pr.Body = io.NopCloser(strings.NewReader(reqData.Data))
		pr.ContentLength = int64(len(reqData.Data))
	}

	client := &http.Client{Timeout: 30 * time.Second}
	proxyResp, err := client.Do(&pr)
	if err != nil {
		_, _ = fmt.Fprintln(response, "{\"success\": false, \"data\":{\"message\":\"(Proxy Error) Request failed: "+err.Error()+"\"}}")
		return
	}
	defer proxyResp.Body.Close()

	var respData proxyResponseData
	respData.Success = true
	respData.Status = proxyResp.StatusCode
	respData.StatusText = strings.Join(strings.Split(proxyResp.Status, " ")[1:], " ")

	responseBytes, err := io.ReadAll(proxyResp.Body)
	if err != nil {
		_, _ = fmt.Fprintln(response, errorBodyProxyRequestFailed)
		return
	}

	respData.Headers = headerToArray(proxyResp.Header)

	if reqData.WantsBinary {
		for _, bannedOutput := range bannedOutputs {
			responseBytes = bytes.ReplaceAll(responseBytes, []byte(bannedOutput), []byte("[redacted]"))
		}
		respData.Data = base64.RawStdEncoding.EncodeToString(responseBytes)
		respData.IsBinary = true
	} else {
		respData.Data = string(responseBytes)
		for _, bannedOutput := range bannedOutputs {
			respData.Data = strings.Replace(respData.Data, bannedOutput, "[redacted]", -1)
		}
	}

	_ = json.NewEncoder(response).Encode(respData)
}

func Handler(w http.ResponseWriter, r *http.Request) {
	if os.Getenv("ACCESS_TOKEN") != "" {
		accessToken = os.Getenv("ACCESS_TOKEN")
	}
	if os.Getenv("ALLOWED_ORIGINS") != "" {
		allowedOrigins = strings.Split(os.Getenv("ALLOWED_ORIGINS"), ",")
	} else {
		allowedOrigins = []string{"*"}
	}
	if os.Getenv("BANNED_OUTPUTS") != "" {
		bannedOutputs = strings.Split(os.Getenv("BANNED_OUTPUTS"), ",")
	}
	if os.Getenv("BANNED_DESTINATIONS") != "" {
		bannedDests = strings.Split(os.Getenv("BANNED_DESTINATIONS"), ",")
	}
	proxyHandler(w, r)
}
