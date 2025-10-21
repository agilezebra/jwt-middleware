package jwt_middleware

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"html"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/agilezebra/jwt-middleware/logger"
	"github.com/danwakefield/fnmatch"
	"github.com/golang-jwt/jwt/v5"
)

// Config is the configuration for the plugin.
type Config struct {
	ValidMethods         []string          `json:"validMethods,omitempty"`
	Issuers              []string          `json:"issuers,omitempty"`
	SkipPrefetch         bool              `json:"skipPrefetch,omitempty"`
	DelayPrefetch        string            `json:"delayPrefetch,omitempty"`
	RefreshKeysInterval  string            `json:"refreshKeysInterval,omitempty"`
	InsecureSkipVerify   []string          `json:"insecureSkipVerify,omitempty"`
	RootCAs              []string          `json:"rootCAs,omitempty"`
	Secret               string            `json:"secret,omitempty"`
	Secrets              map[string]string `json:"secrets,omitempty"`
	Require              map[string]any    `json:"require,omitempty"`
	Optional             bool              `json:"optional,omitempty"`
	RedirectUnauthorized string            `json:"redirectUnauthorized,omitempty"`
	RedirectForbidden    string            `json:"redirectForbidden,omitempty"`
	CookieName           string            `json:"cookieName,omitempty"`
	HeaderName           string            `json:"headerName,omitempty"`
	ParameterName        string            `json:"parameterName,omitempty"`
	HeaderMap            map[string]string `json:"headerMap,omitempty"`
	RemoveMissingHeaders bool              `json:"removeMissingHeaders,omitempty"`
	ForwardToken         bool              `json:"forwardToken,omitempty"`
	Freshness            int64             `json:"freshness,omitempty"`
	LogUnauthorized      string            `json:"logUnauthorized,omitempty"`
}

// JWTPlugin is a traefik middleware plugin that authorizes access based on JWT tokens.
type JWTPlugin struct {
	next                 http.Handler              // The next http.Handler in the chain
	name                 string                    // The name of the plugin
	parser               *jwt.Parser               // A JWT parser instance, which we use for all token parsing
	secret               any                       // A single anonymous fixed public key or HMAC secret, or nil
	issuers              []string                  // A list of valid issuers that we trust to fetch keys from
	clients              map[string]*http.Client   // A map of clients for specific issuers that skip certificate verification
	defaultClient        *http.Client              // A default client for fetching keys with certificate verification, optionally with custom root CAs
	require              Requirement               // A map of requirements for each claim (which we treat simply as a Requirement to be validated)
	lock                 sync.RWMutex              // Read-write lock for the keys and issuerKeys maps
	keys                 map[string]any            // A map of key IDs to public keys or shared HMAC secrets
	issuerKeys           map[string]map[string]any // A map of issuer URLs to key IDs to public keys, for reference counting / purging
	optional             bool                      // If true, requests without a token are allowed but any token provided must still be valid
	redirectUnauthorized *template.Template        // A template for redirecting unauthorized requests
	redirectForbidden    *template.Template        // A template for redirecting forbidden requests
	cookieName           string                    // The name of the cookie to extract the token from
	headerName           string                    // The name of the header to extract the token from
	parameterName        string                    // The name of the query parameter to extract the token from
	headerMap            map[string]string         // A map of claim names to header names to forward to the backend
	removeMissingHeaders bool                      // If true, remove missing headers from the request
	forwardToken         bool                      // If true, the token is forwarded to the backend
	freshness            int64                     // The maximum age of a token in seconds
	environment          map[string]string         // Map of environment variables
	logUnauthorized      string                    // If set, log the details of the failed requirements to the level specified
}

// TemplateVariables are the per-request variables passed to Go templates for interpolation, such as the require and redirect templates.
// This has become a map rather than a struct now because we add the environment variables to it.
type TemplateVariables map[string]string

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		ValidMethods: []string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "HS256", "HS384", "HS512"},
		CookieName:   "Authorization",
		HeaderName:   "Authorization",
		ForwardToken: true,
		Freshness:    3600,
	}
}

// setupKey parses `raw` and returns either the appropriate public key, if it's a PEM, or treats it as a shared HMAC secret.
// Note that we could also use pemContent in here and allow paths to PEMs, as we do for rootCAs,
// but there is no way to know a bad path from an HMAC secret.
func setupKey(raw string) (any, error) {
	// If raw is empty, we don't have a fixed key/secret
	if raw == "" {
		return nil, nil
	}

	// If raw is a PEM-encoded public key, return the public key
	if strings.HasPrefix(raw, "-----BEGIN EC PUBLIC KEY") || strings.HasPrefix(raw, "-----BEGIN PUBLIC KEY") {
		public, err := jwt.ParseECPublicKeyFromPEM([]byte(raw))
		if err == nil || strings.HasPrefix(raw, "-----BEGIN EC PUBLIC KEY") {
			return public, err
		}
		// If it's only marked "BEGIN PUBLIC KEY" and we failed, we fall through to try the RSA key
	}
	if strings.HasPrefix(raw, "-----BEGIN RSA PUBLIC KEY") || strings.HasPrefix(raw, "-----BEGIN PUBLIC KEY") {
		return jwt.ParseRSAPublicKeyFromPEM([]byte(raw))
	}

	// Otherwise, we assume it's a shared HMAC secret
	return []byte(raw), nil
}

// environment returns the environment variables as a map
func environment() map[string]string {
	environment := os.Environ()
	variables := make(map[string]string, len(environment))
	for _, variable := range environment {
		pair := strings.Split(variable, "=")
		variables[pair[0]] = pair[1]
	}
	return variables
}

// New creates a new JWTPlugin.
func New(_ context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	log.SetFlags(0)

	key, err := setupKey(config.Secret)
	if err != nil {
		return nil, err
	}

	for index, pem := range config.RootCAs {
		pem, err := pemContent(pem)
		if err != nil {
			return nil, fmt.Errorf("failed to load root CA: %v", err)
		}
		config.RootCAs[index] = pem
	}

	plugin := JWTPlugin{
		next:                 next,
		name:                 name,
		parser:               jwt.NewParser(jwt.WithValidMethods(config.ValidMethods), jwt.WithJSONNumber()),
		secret:               key,
		issuers:              canonicalizeDomains(config.Issuers),
		clients:              NewClients(config.InsecureSkipVerify),
		defaultClient:        NewDefaultClient(config.RootCAs, true),
		require:              NewRequirement(config.Require, "$and"),
		keys:                 make(map[string]any),
		issuerKeys:           make(map[string]map[string]any),
		optional:             config.Optional,
		redirectUnauthorized: NewTemplate(config.RedirectUnauthorized),
		redirectForbidden:    NewTemplate(config.RedirectForbidden),
		cookieName:           config.CookieName,
		headerName:           config.HeaderName,
		parameterName:        config.ParameterName,
		headerMap:            config.HeaderMap,
		removeMissingHeaders: config.RemoveMissingHeaders,
		forwardToken:         config.ForwardToken,
		freshness:            config.Freshness,
		logUnauthorized:      strings.ToUpper(config.LogUnauthorized),
		environment:          environment(),
	}

	// If we have keys/secrets, add them to the key cache
	for kid, raw := range config.Secrets {
		key, err := setupKey(raw)
		if err != nil {
			return nil, fmt.Errorf("kid %s: %v", kid, err)
		}
		if key == nil {
			return nil, fmt.Errorf("kid %s: invalid key: Key is empty", kid)
		}
		plugin.keys[kid] = key
	}
	plugin.issuerKeys["internal"] = internalIssuerKeys(config.Secrets)

	// Set up the prefetch and refresh intervals and the fetch routine
	var delayPrefetch time.Duration
	if config.SkipPrefetch {
		delayPrefetch = -1
	} else {
		delayPrefetch, err = parseDuration(config.DelayPrefetch)
		if err != nil {
			return nil, fmt.Errorf("invalid delayPrefetch: %v", err)
		}
	}
	refreshKeysInterval, err := parseDuration(config.RefreshKeysInterval)
	if err != nil {
		return nil, fmt.Errorf("invalid refreshKeysInterval: %v", err)
	}

	go plugin.fetchRoutine(delayPrefetch, refreshKeysInterval) // this is a noop if neither are required

	return &plugin, nil
}

// internalIssuerKeys returns a dummy keyset for the keys in config.Secrets
func internalIssuerKeys(secrets map[string]string) map[string]any {
	keys := make(map[string]any, len(secrets))
	for kid := range secrets {
		keys[kid] = nil
	}
	return keys
}

// parseDuration parses a duration string or returns 0 if the string is empty.
func parseDuration(duration string) (time.Duration, error) {
	if duration == "" {
		return 0, nil
	}
	return time.ParseDuration(duration)
}

// fetchRoutine prefetches and refreshes keys for all issuers in the plugin's configuration optionally at the given intervals.
func (plugin *JWTPlugin) fetchRoutine(delayPrefetch time.Duration, refreshKeysInterval time.Duration) {
	// If we have an initial delay, which may be 0, wait for that before the first fetch
	if delayPrefetch != -1 {
		time.Sleep(delayPrefetch)
		plugin.fetchAllKeys()
	}
	// If we have a refresh interval, loop forever fetching keys at that interval
	if refreshKeysInterval != 0 {
		for {
			time.Sleep(refreshKeysInterval)
			plugin.fetchAllKeys()
		}
	}
}

// ServeHTTP is the middleware entry point.
func (plugin *JWTPlugin) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	variables := plugin.NewTemplateVariables(request)
	status, err := plugin.validate(request, variables)
	if err == nil { // if NO error
		// Request is valid, pass to the next handler and we're done
		plugin.next.ServeHTTP(response, request)
	} else {
		// Request is invalid, handle the error appropriately for the configuration and request type
		if plugin.redirectUnauthorized != nil {
			// Interactive clients should be redirected to the login page or unauthorized page.
			var redirectTemplate *template.Template
			if status == http.StatusUnauthorized || plugin.redirectForbidden == nil {
				redirectTemplate = plugin.redirectUnauthorized
			} else {
				redirectTemplate = plugin.redirectForbidden
			}
			url, err := expandTemplate(redirectTemplate, variables)
			if err != nil {
				log.Printf("failed to get redirect URL: %v", err)
				http.Error(response, err.Error(), http.StatusInternalServerError)
				return
			}
			http.Redirect(response, request, url, http.StatusFound)
		} else if hasToken(request.Header.Get("Content-Type"), "application/grpc") {
			// If the request is a GRPC request, we return a GRPC compatible response.
			header := response.Header()
			header.Set("Content-Type", "application/grpc")
			switch status {
			case http.StatusUnauthorized:
				header.Set("grpc-status", "16")
				header.Set("grpc-message", "UNAUTHENTICATED")
			case http.StatusForbidden:
				header.Set("grpc-status", "7")
				header.Set("grpc-message", "PERMISSION_DENIED")
			}
		} else {
			// Non-interactive (i.e. API) clients should get a 401 or 403 response.
			http.Error(response, err.Error(), status)
		}
	}
}

// validate is the entry point for the validation process.
// It validates the request and returns the HTTP status code and an error if the request is not valid (i.e. if not http.StatusOK).
// It also sets any headers that should be forwarded to the backend, as this is where we have the claims at hand.
func (plugin *JWTPlugin) validate(request *http.Request, variables *TemplateVariables) (int, error) {
	token := plugin.extractToken(request)
	if token == "" {
		// No token provided
		if !plugin.optional {
			return http.StatusUnauthorized, fmt.Errorf("no token provided")
		}

		plugin.removeMappedHeaders(request)
	} else {
		// Token provided
		token, err := plugin.parser.Parse(token, plugin.getKey)
		if err != nil {
			return http.StatusUnauthorized, err
		}

		claims := token.Claims.(jwt.MapClaims)
		err = plugin.require.Validate(map[string]any(claims), variables)
		if err != nil {
			if plugin.allowRefresh(claims) {
				return http.StatusUnauthorized, err
			} else {
				return http.StatusForbidden, err
			}
		}

		plugin.mapClaimsToHeaders(claims, request)
	}

	return http.StatusOK, nil
}

// allowRefresh returns true if freshness window is configured and the token has an iat claim that is older than the freshness window.
func (plugin *JWTPlugin) allowRefresh(claims jwt.MapClaims) bool {
	if plugin.freshness == 0 {
		return false
	}
	iat, ok := claims["iat"]
	if !ok {
		return false
	}

	value, err := iat.(json.Number).Int64()
	return err == nil && time.Now().Unix()-value > plugin.freshness
}

// mapClaimsToHeaders maps any claims to headers as specified in the headerMap configuration.
func (plugin *JWTPlugin) mapClaimsToHeaders(claims jwt.MapClaims, request *http.Request) {
	for header, claim := range plugin.headerMap {
		value, ok := claims[claim]
		if ok {
			request.Header.Del(header)
			switch value := value.(type) {
			case []any, map[string]any, nil:
				json, err := json.Marshal(value)
				if err == nil {
					request.Header.Add(header, string(json))
				}
				// Although we check err, we don't have a branch to log an error for err != nil, because it's not possible
				// that the value won't be marshallable to json, given it has already been unmarshalled _from_ json to get here
			default:
				request.Header.Add(header, fmt.Sprint(value))
			}
		} else if plugin.removeMissingHeaders {
			request.Header.Del(header)
		}
	}
}

// removeMappedHeaders arbitrarily removes all target headers named in the headerMap from the request.
func (plugin *JWTPlugin) removeMappedHeaders(request *http.Request) {
	for header := range plugin.headerMap {
		request.Header.Del(header)
	}
}

// getKey gets the key for the given key ID from the plugin's key cache.
// If the key isn't present and the iss is valid according to the plugin's configuration, all keys for the iss are refreshed and the key is looked up again.
func (plugin *JWTPlugin) getKey(token *jwt.Token) (any, error) {
	err := fmt.Errorf("no secret configured")
	if len(plugin.issuers) > 0 || len(plugin.keys) > 0 {
		kid, ok := token.Header["kid"]
		if ok {
			refreshed := ""
			for looped := false; ; looped = true {
				plugin.lock.RLock()
				key, ok := plugin.keys[kid.(string)]
				plugin.lock.RUnlock()
				if ok {
					return key, nil
				}

				if looped {
					if refreshed != "" {
						logger.Log("WARN", "key %s: refreshed keys from %s and still no match", kid, refreshed)
					}
					break
				}

				issuer, ok := token.Claims.(jwt.MapClaims)["iss"].(string)
				if ok {
					issuer = canonicalizeDomain(issuer)
					if plugin.isValidIssuer(issuer) {
						// There is a design choice here: we have determined that the key is not present whilst holding the read lock.
						// fetchKeys will fetch the metadata and key from the issuer before it aquires the write lock, as we don't want
						// to block other requests that are able to immediately read available keys.
						// This means that we may make multiple requests at the same time for the same kid, if it is newly presented concurrently.
						// This is a tradeoff between the cost of the extra requests (more so to the server) vs the cost to other threads of holding the lock.
						err = plugin.fetchKeys(issuer)
						if err == nil {
							refreshed = issuer
						} else {
							log.Printf("failed to fetch keys for %s: %v", issuer, err)
						}
					} else {
						err = fmt.Errorf("issuer %s is not valid", issuer)
					}
				} else {
					break
				}
			}
		}
	}

	// We fall back to any fixed secret or return the error
	if plugin.secret == nil {
		return nil, err
	}

	return plugin.secret, nil
}

// isValidIssuer returns true if the issuer is allowed by the Issers configuration.
func (plugin *JWTPlugin) isValidIssuer(issuer string) bool {
	for _, allowed := range plugin.issuers {
		if fnmatch.Match(allowed, issuer, 0) {
			return true
		}
	}
	return false
}

// hostname returns the hostname for the given URL.
func hostname(address string) string {
	parsed, err := url.Parse(address)
	if err != nil {
		log.Printf("failed to parse url %s: %v", address, err)
		return ""
	}
	return parsed.Hostname()
}

// clientForURL returns the http.Client for the given URL, or the default client if no specific client is configured.
func (plugin *JWTPlugin) clientForURL(address string) *http.Client {
	client, ok := plugin.clients[hostname(address)]
	if ok {
		return client
	} else {
		return plugin.defaultClient
	}
}

// fetchAllKeys fetches all keys for all issuers in the plugin's configuration.
func (plugin *JWTPlugin) fetchAllKeys() {
	for _, issuer := range plugin.issuers {
		if !strings.Contains(issuer, "*") {
			err := plugin.fetchKeys(issuer)
			if err != nil {
				log.Printf("failed to fetch keys for %s: %v", issuer, err)
			}
		}
	}
}

// fetchKeys fetches the keys from well-known jwks endpoint for the given issuer and adds them to the key map.
func (plugin *JWTPlugin) fetchKeys(issuer string) error {
	configURL := issuer + ".well-known/openid-configuration" // issuer has trailing slash
	config, err := FetchOpenIDConfiguration(configURL, plugin.clientForURL(configURL))

	var url string
	if err != nil {
		// Fall back to direct JWKS URL if OpenID configuration fetch fails
		url = issuer + ".well-known/jwks.json"
		logger.Log("WARN", "failed to fetch openid-configuration from url:%s; falling back to direct JWKS URL:%s", configURL, url)
	} else {
		logger.Log("INFO", "fetched openid-configuration from url:%s", configURL)
		url = config.JWKSURI
	}

	jwks, err := FetchJWKS(url, plugin.clientForURL(url))
	if err != nil {
		return err
	}

	plugin.lock.Lock()
	defer plugin.lock.Unlock()

	for keyID, key := range jwks {
		logger.Log("INFO", "fetched key:%s from url:%s", keyID, url)
		plugin.keys[keyID] = key
	}

	plugin.issuerKeys[url] = jwks
	plugin.purgeKeys()

	return nil
}

// isIssuedKey returns true if the key exists in the issuerKeys map
func (plugin *JWTPlugin) isIssuedKey(keyID string) bool {
	for _, issuerKeys := range plugin.issuerKeys {
		if _, ok := issuerKeys[keyID]; ok {
			return true
		}
	}
	return false
}

// purgeKeys purges all keys from plugin.keys that are not in the issuerKeys map.
func (plugin *JWTPlugin) purgeKeys() {
	for keyID := range plugin.keys {
		if !plugin.isIssuedKey(keyID) {
			logger.Log("INFO", "key:%s dropped", keyID)
			delete(plugin.keys, keyID)
		}
	}
}

// canonicalizeDomain adds a trailing slash to the domain
func canonicalizeDomain(domain string) string {
	if !strings.HasSuffix(domain, "/") {
		domain += "/"
	}
	return domain
}

// canonicalizeDomains adds a trailing slash to all domains
func canonicalizeDomains(domains []string) []string {
	for index, domain := range domains {
		domains[index] = canonicalizeDomain(domain)
	}
	return domains
}

// pemContent returns the value if it is alread a PEM or reads the file if it is a filename.
func pemContent(value string) (string, error) {
	if value == "" || strings.HasPrefix(value, "-----BEGIN") {
		return value, nil
	}
	content, err := os.ReadFile(value)
	if err != nil {
		return "", err
	}
	return string(content), nil
}

// NewDefaultClient returns an http.Client with the given root CAs, or a default client if no root CAs are provided.
func NewDefaultClient(pems []string, useSystemCertPool bool) *http.Client {
	if pems == nil {
		return &http.Client{}
	}
	certs, _ := x509.SystemCertPool()
	if certs == nil || !useSystemCertPool {
		// We don't plan an option to set useSystemCertPool=false but it helps with test coverage
		certs = x509.NewCertPool()
	}
	for _, pem := range pems {
		if !certs.AppendCertsFromPEM([]byte(pem)) {
			log.Printf("failed to add root CA:\n%s", pem)
		}
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: certs,
		},
	}
	return &http.Client{Transport: transport}
}

// NewClients reads a list of domains in the InsecureSkipVerify configuration and creates a map of domains to http.Client with InsecureSkipVerify set.
func NewClients(insecureSkipVerify []string) map[string]*http.Client {
	// Create a single client with InsecureSkipVerify set
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: transport}

	// Use it for all issuers in the InsecureSkipVerify configuration
	clients := make(map[string]*http.Client, len(insecureSkipVerify))
	for _, issuer := range insecureSkipVerify {
		clients[issuer] = client
	}
	return clients
}

// NewTemplate creates a template from the given string, or nil if not specified.
func NewTemplate(text string) *template.Template {
	if text == "" {
		return nil
	}
	functions := template.FuncMap{
		"URLQueryEscape": url.QueryEscape,
		"HTMLEscape":     html.EscapeString,
	}
	return template.Must(template.New("template").Funcs(functions).Option("missingkey=error").Parse(text))
}

// NewTemplateVariables creates a template data map for the given request.
// We start with a clone of our environment variables and add the the per-request variables.
// The purpose of environment variables is to allow a easier way to set a configurable but then fixed value for a claim
// requirement in the configuration file (as rewriting the configuration file is harder than setting environment variables).
func (plugin *JWTPlugin) NewTemplateVariables(request *http.Request) *TemplateVariables {
	// copy the environment variables
	variables := make(TemplateVariables, len(plugin.environment)+6)
	for key, value := range plugin.environment {
		variables[key] = value
	}

	variables["Method"] = request.Method
	variables["Host"] = request.Host
	variables["Path"] = request.URL.RequestURI()
	if request.URL.Host != "" {
		// If request.URL.Host is set, we can use all the URL values directly
		variables["Scheme"] = request.URL.Scheme
		variables["URL"] = request.URL.String()
	} else {
		// (In at least some situations) Traefik sets only the path in the request.URL, so we need to reconstruct it
		variables["Scheme"] = request.Header.Get("X-Forwarded-Proto")
		if variables["Scheme"] == "" {
			variables["Scheme"] = "https"
		}
		variables["URL"] = fmt.Sprintf("%s://%s%s", variables["Scheme"], variables["Host"], variables["Path"])
	}

	if plugin.logUnauthorized != "" {
		variables["logUnauthorized"] = plugin.logUnauthorized
	}

	return &variables
}

// expandTemplate returns the redirect URL from the plugin.redirect template and expands it with the given parameters.
func expandTemplate(redirectTemplate *template.Template, variables *TemplateVariables) (string, error) {
	var buffer bytes.Buffer
	err := redirectTemplate.Execute(&buffer, variables)
	if err != nil {
		return "", err
	}
	return buffer.String(), nil

}

// extractToken extracts the token from the request using the first configured method that finds one, in order of cookie, header, query parameter.
func (plugin *JWTPlugin) extractToken(request *http.Request) string {
	token := ""
	if plugin.cookieName != "" {
		token = plugin.extractTokenFromCookie(request)
	}
	if len(token) == 0 && plugin.headerName != "" {
		token = plugin.extractTokenFromHeader(request)
	}
	if len(token) == 0 && plugin.parameterName != "" {
		token = plugin.extractTokenFromQuery(request)
	}
	return token
}

// extractTokenFromCookie extracts the token from the cookie. If the token is found, it is removed from the cookies unless forwardToken is true.
func (plugin *JWTPlugin) extractTokenFromCookie(request *http.Request) string {
	cookie, error := request.Cookie(plugin.cookieName)
	if error != nil {
		return ""
	}
	if !plugin.forwardToken {
		cookies := request.Cookies()
		request.Header.Del("Cookie")
		for _, cookie := range cookies {
			if cookie.Name != plugin.cookieName {
				request.AddCookie(cookie)
			}
		}
	}
	return cookie.Value
}

// extractTokenFromHeader extracts the token from the header. If the token is found, it is removed from the header unless forwardToken is true.
func (plugin *JWTPlugin) extractTokenFromHeader(request *http.Request) string {
	header, ok := request.Header[plugin.headerName]
	if !ok {
		return ""
	}

	token := header[0]

	if !plugin.forwardToken {
		request.Header.Del(plugin.headerName)
	}

	if len(token) >= 7 && strings.EqualFold(token[:7], "Bearer ") {
		return token[7:]
	}
	return token
}

// extractTokenFromQuery extracts the token from the query parameter. If the token is found, it is removed from the query unless forwardToken is true.
func (plugin *JWTPlugin) extractTokenFromQuery(request *http.Request) string {
	if request.URL.Query().Has(plugin.parameterName) {
		token := request.URL.Query().Get(plugin.parameterName)
		if !plugin.forwardToken {
			query := request.URL.Query()
			query.Del(plugin.parameterName)
			request.URL.RawQuery = query.Encode()
			request.RequestURI = request.URL.RequestURI()
		}
		return token
	}
	return ""
}

// The following code is copied from the Go standard library net/http package, as hasToken is not exported.
// We have also added '+' as a token boundary character.

// hasToken returns true if the header contains the token.
// case-insensitive, with space, comma boundaries.
// header may contain mixed cased; token must be all lowercase.
func hasToken(header, token string) bool {
	if len(token) > len(header) || token == "" {
		return false
	}
	if header == token {
		return true
	}
	for start := 0; start <= len(header)-len(token); start++ {
		// Check that first character is good.
		// The token is ASCII, so checking only a single byte
		// is sufficient. We skip this potential starting
		// position if both the first byte and its potential
		// ASCII uppercase equivalent (b|0x20) don't match.
		// False positives ('^' => '~') are caught by EqualFold.
		if character := header[start]; character != token[0] && character|0x20 != token[0] {
			continue
		}
		// Check that start is on a valid token boundary.
		if start > 0 && !isTokenBoundary(header[start-1]) {
			continue
		}
		end := start + len(token)
		// Check that end is on a valid token boundary.
		if end != len(header) && !isTokenBoundary(header[end]) {
			continue
		}
		if strings.EqualFold(header[start:end], token) {
			return true
		}
	}
	return false
}

// isTokenBoundary returns true if the character is a token boundary.
func isTokenBoundary(character byte) bool {
	return character == ' ' || character == ',' || character == '\t' || character == '+'
}
