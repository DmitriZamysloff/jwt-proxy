package main

import (
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/lestrrat-go/jwx/jwk"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
)

type Header struct {
	name  string
	value string
}

//
//CONSTANTS
//
const version = "0.1"

var static = []string{".jpg", ".png", ".tif", ".gif", ".ico", ".css", ".js", ".htm", ".html", ".json"}

//Environment Variable Names

type EnvVariable struct {
	key          string
	defaultValue string
}

const EnvNextHop = "NEXT_HOP"       //accepting endpoint for authenticated traffic
const EnvCookieName = "COOKIE_NAME" //name of cookie to use by cookie method
const EnvPort = "PORT"              //port to serve
const EnvJwksUrl = "JWKS"           //jwks url
const EnvMethod = "METHOD"          //method to use to search JWT: "header", "cookie" or "auth"
const MethodHeader = "header"
const MethodCookie = "cookie"
const MethodAuth = "auth"
const EnvHeaderName = "HEADER_NAME"         //name of the header to use by header method
const EnvLoginRedirect = "LOGIN_REDIRECT"   //will be sent in Location header by 401
const EnvLoginHeaders = "LOGIN_HEADERS"     //additional headers to be sent by 401. A list like header:value[;header:value]*. Optional
const EnvLogoutPath = "LOGOUT_PATH"         //path to serve logout redirect. Default /logout
const EnvLogoutRedirect = "LOGOUT_REDIRECT" //the url for redirect location
const EnvHealthCheckPath = "HEALTH_PATH"    //path to health check. default /health
const EnvFilterStatic = "FILTER_STATIC"

//
//GLOBALS
//
var keySet *jwk.Set //Cache for JWKS

//Gets environment variable or fallback to standard
func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func getNextHop() string {
	return getEnv(EnvNextHop, "http://SSC-LB-99851668.us-west-2.elb.amazonaws.com")
}

func getMethod() string {
	result := getEnv(EnvMethod, MethodAuth)
	if !strings.EqualFold(MethodHeader, result) && !strings.EqualFold(MethodCookie, result) && !strings.EqualFold(MethodAuth, result) {
		err := fmt.Sprintf("Method parameter shall have %s or %s as value. Found %s.", MethodCookie, MethodHeader, result)
		log.Fatal(err)
		panic(err)
	}
	return result
}

func jwtInHeader() bool {
	return strings.EqualFold(MethodHeader, getMethod()) || strings.EqualFold(MethodAuth, getMethod())
}

func getHeaderName() string {
	return getEnv(EnvHeaderName, "x-ssc-token")
}

func getCookieName() string {
	return getEnv(EnvCookieName, "SSC_JWT")
}

func isFilterStatic() bool {
	strValue := getEnv(EnvFilterStatic, "true")
	return strings.EqualFold("true", strValue)
}

// Get the port to listen on
func getListenAddress() string {
	port := getEnv(EnvPort, "80")
	return ":" + port
}

func getJwksUrl() string {
	return getEnv(EnvJwksUrl, "https://cognito-idp.us-west-2.amazonaws.com/us-west-2_kqd1bmSR8/.well-known/jwks.json")
}

func getLoginRedirectUrl() string {
	return getEnv(EnvLoginRedirect, "https://ssc.auth.us-west-2.amazoncognito.com/login?client_id=35brrudnc7km3k66po6jvoqtaf&response_type=token&scope=openid+email&redirect_uri=https://d1qs7mpwws9qb4.cloudfront.net/")
}

func getHealthCheckPath() string {
	return getEnv(EnvHealthCheckPath, "/health")
}

func getLoginHeaders() []Header {
	var result []Header
	headerStr := getEnv(EnvLoginHeaders, "")
	split := strings.Split(headerStr, ";")
	for _, s := range split {
		splitHeader := strings.Split(s, ":")
		if len(splitHeader) == 2 {
			result = append(result, Header{splitHeader[0], splitHeader[1]})
		}
	}
	return result
}

func getLogoutPath() string {
	return getEnv(EnvLogoutPath, "/logout")
}

func getLogoutRedirectUrl() string {
	return getEnv(EnvLogoutRedirect, "https://ssc.auth.us-west-2.amazoncognito.com/logout?client_id=35brrudnc7km3k66po6jvoqtaf&logout_uri=https://d1qs7mpwws9qb4.cloudfront.net/")
}

func logSetup() {
	log.Printf("SSC Proxy. Version %s\n", version)
	log.Printf("Server run on: %s\n", getListenAddress())
	log.Printf("Redirecting to: %s\n", getNextHop())
	log.Printf("JWKS: %s\n", getJwksUrl())
	log.Printf("Logout path: %s\n", getLogoutPath())
	log.Printf("Login redirect url: %s\n", getLoginRedirectUrl())
	log.Printf("Logout redirect url: %s\n", getLogoutRedirectUrl())
	log.Printf("JWT method: %s\n", getMethod())
	log.Printf("Header name: %s\n", getHeaderName())
	log.Printf("Cookie name: %s\n", getCookieName())
	log.Printf("Health check path: %s\n", getHealthCheckPath())
}

func getJwtFromCookie(req *http.Request) string {
	cookie, err := req.Cookie(getCookieName())
	if err == nil {
		return cookie.Value
	}
	return ""
}

func getJwtFromHeader(req *http.Request) string {
	headerName := getHeaderName()
	if strings.EqualFold(MethodAuth, getMethod()) {
		headerName = "Authorization"
	}
	result := req.Header.Get(headerName)
	log.Printf("Getting header %s from request with value %s.\n", headerName, result)
	if strings.EqualFold(MethodAuth, getMethod()) {
		if !strings.HasPrefix(result, "Bearer ") {
			result = ""
		} else {
			runes := []rune(result)
			result = string(runes[7:])
		}
	}
	return result
}

func handleRequestAndRedirect(res http.ResponseWriter, req *http.Request) {
	//check request has jwt
	everythingIsFine := false
	if checkAuth(req) {
		jwtTokenValue := ""
		if jwtInHeader() {
			jwtTokenValue = getJwtFromHeader(req)
		} else {
			jwtTokenValue = getJwtFromCookie(req)
		}

		if jwtTokenValue != "" {
			_, err := jwt.Parse(jwtTokenValue, getKey)
			if err == nil {
				log.Printf("Valid token found %s\n", jwtTokenValue)
				everythingIsFine = true
			} else {
				log.Printf("Error occurred parsing JWT %s: %s\n", jwtTokenValue, err)
			}
		} else {
			log.Printf("No token found. Or token is empty.\n")
		}
	} else {
		everythingIsFine = true
	}
	if everythingIsFine {
		url, _ := url.Parse(getNextHop())
		proxy := httputil.NewSingleHostReverseProxy(url)
		headerValue := req.Header.Get("X-Forwarded-Host")
		if headerValue == "" {
			req.Header.Set("X-Forwarded-Host", req.Header.Get("Host"))
		}
		req.URL.Host = url.Host
		req.URL.Scheme = url.Scheme
		proxy.ServeHTTP(res, req)
	} else {
		res.Header().Set("Location", getLoginRedirectUrl())
		res.WriteHeader(http.StatusUnauthorized)
		headers := getLoginHeaders()
		if len(headers) > 0 {
			for _, header := range headers {
				res.Header().Set(header.name, header.value)
			}
		}
		res.Write([]byte("No valid token found."))
	}
}

func getKeySet() (*jwk.Set, error) {
	if keySet != nil {
		return keySet, nil
	} else {
		set, err := jwk.FetchHTTP(getJwksUrl())
		if err != nil {
			return nil, err
		} else {
			keySet = set
			return keySet, nil
		}
	}
}

func getKey(token *jwt.Token) (interface{}, error) {
	set, err := getKeySet()
	if err != nil {
		return nil, err
	}
	keyID, ok := token.Header["kid"].(string)
	if !ok {
		return nil, errors.New("expecting JWT header to have string kid")
	}
	if key := set.LookupKeyID(keyID); len(key) == 1 {
		return key[0].Materialize()
	}
	return nil, fmt.Errorf("unable to find key %q", keyID)
}

func checkAuth(req *http.Request) bool {
	if !isFilterStatic() {
		return true
	}
	uri := req.RequestURI
	if strings.Contains(uri, "?") {
		return true
	}
	uri = strings.ToLower(uri)
	for _, s := range static {
		if strings.HasSuffix(uri, s) {
			return false
		}
	}
	return true
}

func main() {
	//Log setup variables
	logSetup()
	//start server
	http.HandleFunc(getHealthCheckPath(), handleHealthRequest)
	logoutPath := getLogoutPath()
	if logoutPath != "" && strings.HasPrefix(logoutPath, "/") {
		http.HandleFunc(logoutPath, handleLogoutRequest)
	}
	http.HandleFunc("/", handleRequestAndRedirect)
	if err := http.ListenAndServe(getListenAddress(), nil); err != nil {
		panic(err)
	}
}

func handleLogoutRequest(res http.ResponseWriter, req *http.Request) {
	res.Header().Set("Location", getLogoutRedirectUrl())
	res.WriteHeader(http.StatusTemporaryRedirect)
}

func handleHealthRequest(writer http.ResponseWriter, request *http.Request) {
	writer.WriteHeader(http.StatusOK)
	writer.Write([]byte("Service is healthy"))
}
