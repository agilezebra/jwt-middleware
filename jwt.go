package jwt_middleware

import (
	"bytes"
	"context"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/danwakefield/fnmatch"
	"github.com/golang-jwt/jwt/v5"
)

// Config is the configuration for the plugin.
type Config struct {
	ValidMethods         []string
	Issuers              []string
	Secret               string                 `json:"secret,omitempty"`
	Require              map[string]interface{} `json:"require,omitempty"`
	Optional             bool                   `json:"optional,omitempty"`
	RedirectUnauthorized string                 `json:"redirectUnauthorized,omitempty"`
	RedirectForbidden    string                 `json:"redirectForbidden,omitempty"`
	CookieName           string                 `json:"cookieName,omitempty"`
	HeaderName           string                 `json:"headerName,omitempty"`
	ParameterName        string                 `json:"parameterName,omitempty"`
	HeaderMap            map[string]string      `json:"headerMap,omitempty"`
	ForwardToken         bool                   `json:"forwardToken,omitempty"`
	Freshness            int64                  `json:"freshness,omitempty"`
}

// JWTPlugin is a traefik middleware plugin that authorizes access based on JWT tokens.
type JWTPlugin struct {
	next                 http.Handler
	name                 string
	parser               *jwt.Parser
	secret               interface{}
	issuers              []string
	require              map[string][]Requirement
	lock                 sync.RWMutex
	keys                 map[string]interface{}
	issuerKeys           map[string]map[string]interface{}
	optional             bool
	redirectUnauthorized *template.Template
	redirectForbidden    *template.Template
	cookieName           string
	headerName           string
	parameterName        string
	headerMap            map[string]string
	forwardToken         bool
	freshness            int64
}

// TemplateVariables are the per-request variables passed to Go templates for interpolation, such as the require and redirect templates.
type TemplateVariables struct {
	URL    string
	Scheme string
	Host   string
	Path   string
}

// Requirement is a requirement for a claim.
type Requirement interface {
	Validate(value interface{}, variables *TemplateVariables) bool
}

// ValueRequirement is a requirement for a claim that is a known value.
type ValueRequirement struct {
	value  interface{}
	nested interface{}
}

// TemplateRequirement is a dynamic requirement for a claim that uses a template that needs interpolating per request.
type TemplateRequirement struct {
	template *template.Template
	nested   interface{}
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		ValidMethods: []string{"RS256", "RS512", "ES256", "ES384", "ES512", "HS256"},
		CookieName:   "Authorization",
		HeaderName:   "Authorization",
		ForwardToken: true,
		Freshness:    3600,
	}
}

func SetupSecret(secret string) (interface{}, error) {
	// If secret is empty, we don't have a fixed secret
	if secret == "" {
		return nil, nil
	}

	// If plugin.secret is a PEM-encoded public key, return the public key
	if strings.HasPrefix(secret, "-----BEGIN RSA PUBLIC KEY") {
		return jwt.ParseRSAPublicKeyFromPEM([]byte(secret))
	}

	if strings.HasPrefix(secret, "-----BEGIN EC PUBLIC KEY") || strings.HasPrefix(secret, "-----BEGIN PUBLIC KEY") {
		return jwt.ParseECPublicKeyFromPEM([]byte(secret))
	}

	// Otherwise, we assume it's a shared HMAC secret
	return []byte(secret), nil
}

// New creates a new JWTPlugin.
func New(_ context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	log.SetFlags(0)

	secret, err := SetupSecret(config.Secret)
	if err != nil {
		return nil, err
	}

	plugin := JWTPlugin{
		next:                 next,
		name:                 name,
		parser:               jwt.NewParser(jwt.WithValidMethods(config.ValidMethods)),
		secret:               secret,
		issuers:              canonicalizeDomains(config.Issuers),
		require:              convertRequire(config.Require),
		keys:                 make(map[string]interface{}),
		issuerKeys:           make(map[string]map[string]interface{}),
		optional:             config.Optional,
		redirectUnauthorized: createTemplate(config.RedirectUnauthorized),
		redirectForbidden:    createTemplate(config.RedirectForbidden),
		cookieName:           config.CookieName,
		headerName:           config.HeaderName,
		parameterName:        config.ParameterName,
		headerMap:            config.HeaderMap,
		forwardToken:         config.ForwardToken,
		freshness:            config.Freshness,
	}

	for _, issuer := range plugin.issuers {
		if strings.Contains(issuer, "*") {
			continue
		}
		err := plugin.fetchKeys(issuer)
		if err != nil {
			log.Printf("failed to prefetch keys for %s: %v", issuer, err)
		}
	}

	return &plugin, nil
}

// ServeHTTP is the middleware entry point.
func (plugin *JWTPlugin) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	variables := plugin.createTemplateVariables(request)
	status, err := plugin.Validate(request, variables)
	if err != nil {
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
		} else {
			// Non-interactive (i.e. API) clients should get a 401 or 403 response.
			http.Error(response, err.Error(), status)
		}
		return
	}
	plugin.next.ServeHTTP(response, request)
}

// Validate validates the request and returns the HTTP status code or an error if the request is not valid. It also sets any headers that should be forwarded to the backend.
func (plugin *JWTPlugin) Validate(request *http.Request, variables *TemplateVariables) (int, error) {
	token := plugin.extractToken(request)
	if token == "" {
		// No token provided
		if !plugin.optional {
			return http.StatusUnauthorized, fmt.Errorf("no token provided")
		}
	} else {
		// Token provided
		token, err := plugin.parser.Parse(token, plugin.GetKey)
		if err != nil {
			return http.StatusUnauthorized, err
		}

		claims := token.Claims.(jwt.MapClaims)

		// Validate claims
		for claim, requirements := range plugin.require {
			result := plugin.ValidateClaim(claim, claims, requirements, variables)
			if !result {
				err := fmt.Errorf("claim is not valid: %s", claim)
				// If the token is older than out freshness window, we allow that reauthorization might fix it
				iat, ok := claims["iat"]
				if ok && plugin.freshness != 0 && time.Now().Unix()-int64(iat.(float64)) > plugin.freshness {
					return http.StatusUnauthorized, err
				} else {
					return http.StatusForbidden, err
				}
			}
		}

		// Map any require claims to headers
		for header, claim := range plugin.headerMap {
			value, ok := claims[claim]
			if ok {
				request.Header.Add(header, fmt.Sprint(value))
			}
		}
	}

	return http.StatusOK, nil
}

// Validate checks value against the requirement, calling ourself recursively for object and array values.
// variables is required in the interface and passed on recusrively by ultimately ignored bu ValueRequirement
// having been already interpolated by TemplateRequirement
func (requirement ValueRequirement) Validate(value interface{}, variables *TemplateVariables) bool {
	switch value := value.(type) {
	case []interface{}:
		for _, value := range value {
			if requirement.Validate(value, variables) {
				return true
			}
		}
	case map[string]interface{}:
		for value, nested := range value {
			if requirement.Validate(value, variables) && requirement.ValidateNested(nested) {
				return true
			}
		}
	case string:
		required, ok := requirement.value.(string)
		if !ok {
			return false
		}
		return fnmatch.Match(value, required, 0) || value == fmt.Sprintf("*.%s", required)
	}

	return reflect.DeepEqual(value, requirement.value)
}

// ValidateNested checks value against the nested requirement
func (requirement ValueRequirement) ValidateNested(value interface{}) bool {
	// The nested requirement may be a single required value, or an OR choice of acceptable values. Convert to a slice of values.
	var required []interface{}
	switch nested := requirement.nested.(type) {
	case nil:
		// If the nested requirement is nil, we don't care about the nested claims that brought us here and the value is always valid.
		return true
	case []interface{}:
		required = nested
	case interface{}:
		required = []interface{}{nested}
	}

	// Likewise, the value may be a single claim value or an array of several granted claims values. Convert to a slice of values.
	var supplied []interface{}
	switch value := value.(type) {
	case []interface{}:
		supplied = value
	case interface{}:
		supplied = []interface{}{value}
	}

	// If any of the values match any of the nested requirement, the claim is valid.
	for _, required := range required {
		for _, supplied := range supplied {
			if reflect.DeepEqual(required, supplied) {
				return true
			}
		}
	}
	return false
}

// Validate interpolates the requirement template with the given variables and then delegates to ValueRequirement.
func (requirement TemplateRequirement) Validate(value interface{}, variables *TemplateVariables) bool {
	var buffer bytes.Buffer
	err := requirement.template.Execute(&buffer, variables)
	if err != nil {
		log.Printf("Error executing template: %s", err)
		return false
	}
	return ValueRequirement{value: buffer.String(), nested: requirement.nested}.Validate(value, variables)
}

// convertRequire converts the require configuration to a map of requirements.
func convertRequire(require map[string]interface{}) map[string][]Requirement {
	converted := make(map[string][]Requirement, len(require))
	for key, value := range require {
		switch value := value.(type) {
		case []interface{}:
			requirements := make([]Requirement, len(value))
			for index, value := range value {
				requirements[index] = createRequirement(value, nil)
			}
			converted[key] = requirements
		case map[string]interface{}:
			requirements := make([]Requirement, len(value))
			index := 0
			for key, value := range value {
				requirements[index] = createRequirement(key, value)
				index++
			}
			converted[key] = requirements
		default:
			converted[key] = []Requirement{createRequirement(value, nil)}
		}

	}
	return converted
}

// createRequirement creates a Requirement of the correct type from the given value (and any nested value).
func createRequirement(value interface{}, nested interface{}) Requirement {
	switch value := value.(type) {
	case string:
		if strings.Contains(value, "{{") && strings.Contains(value, "}}") {
			return TemplateRequirement{
				template: template.Must(template.New("template").Parse(value)),
				nested:   nested,
			}
		}
	}
	return ValueRequirement{value: value, nested: nested}
}

// ValidateClaim
func (plugin *JWTPlugin) ValidateClaim(claim string, claims jwt.MapClaims, requirements []Requirement, variables *TemplateVariables) bool {
	value, ok := claims[claim]
	if ok {
		for _, requirement := range requirements {
			if requirement.Validate(value, variables) {
				return true
			}
		}
	}
	return false
}

// GetKey gets the key for the given key ID from the plugin's key cache. If the key isn't present and the iss is valid according to the plugin's configuration, all keys for the iss are fetched and the key is looked up again.
func (plugin *JWTPlugin) GetKey(token *jwt.Token) (interface{}, error) {
	kid, ok := token.Header["kid"]
	if ok {
		for fetched := false; ; fetched = true {
			plugin.lock.RLock()
			key, ok := plugin.keys[kid.(string)]
			plugin.lock.RUnlock()
			if ok {
				return key, nil
			}

			if fetched {
				log.Printf("key %s: fetched and no match", kid)
				break
			}

			issuer, ok := token.Claims.(jwt.MapClaims)["iss"].(string)
			if ok {
				issuer = canonicalizeDomain(issuer)
				if plugin.IsValidIssuer(issuer) {
					plugin.lock.Lock()
					if _, ok := plugin.keys[kid.(string)]; !ok {
						err := plugin.fetchKeys(issuer) // issue has trailing slash
						if err != nil {
							log.Printf("failed to fetch keys for %s: %v", issuer, err)
						}
					}
					plugin.lock.Unlock()
				}
			} else {
				break
			}
		}
	}

	// We fall back to any fixed secret
	if plugin.secret == nil {
		return nil, fmt.Errorf("no secret configured")
	}

	return plugin.secret, nil
}

// IsValidIssuer returns true if the issuer is allowed by the Issers configuration.
func (plugin *JWTPlugin) IsValidIssuer(issuer string) bool {
	for _, allowed := range plugin.issuers {
		if fnmatch.Match(allowed, issuer, 0) {
			return true
		}
	}
	return false
}

// fetchKeys fetches the keys from well-known jwks endpoint for the given issuer and adds them to the key map.
func (plugin *JWTPlugin) fetchKeys(issuer string) error {
	configURL := issuer + ".well-known/openid-configuration" // issuer has trailing slash
	config, err := FetchOpenIDConfiguration(configURL)
	if err != nil {
		return err
	}
	log.Printf("fetched openid-configuration from url:%s", configURL)
	jwks, err := FetchJWKS(config.JWKSURI)
	if err != nil {
		return err
	}
	for keyID, key := range jwks {
		log.Printf("fetched key:%s from url:%s", keyID, config.JWKSURI)
		plugin.keys[keyID] = key
	}

	previous := plugin.issuerKeys[config.JWKSURI]
	for keyID := range previous {
		if _, ok := jwks[keyID]; !ok {
			log.Printf("key:%s dropped by url:%s", keyID, config.JWKSURI)
			delete(plugin.keys, keyID)
		}
	}
	plugin.issuerKeys[config.JWKSURI] = jwks

	return nil
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

// createTemplate creates a template from the given redirect string, or nil if no specified.
func createTemplate(text string) *template.Template {
	if text == "" {
		return nil
	}
	return template.Must(template.New("template").Parse(text))
}

// createTemplateVariables creates a template data object for the given request.
func (plugin *JWTPlugin) createTemplateVariables(request *http.Request) *TemplateVariables {
	var variables TemplateVariables

	if request.URL.Host != "" {
		variables.URL = request.URL.String()
		variables.Scheme = request.URL.Scheme
		variables.Host = request.URL.Host
		variables.Path = request.URL.Path
	} else {
		// (In at lease some situations) Traefik set only the path in the request.URL, so we need to reconstruct it
		variables.Scheme = request.Header.Get("X-Forwarded-Proto")
		if variables.Scheme == "" {
			variables.Scheme = "https"
		}
		variables.Host = request.Host
		variables.Path = request.URL.RequestURI()
		variables.URL = fmt.Sprintf("%s://%s%s", variables.Scheme, variables.Host, variables.Path)
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

	if strings.HasPrefix(token, "Bearer ") {
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
