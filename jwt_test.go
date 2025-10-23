package jwt_middleware

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/golang-jwt/jwt/v5"
	"github.com/mitchellh/mapstructure"
	"gopkg.in/yaml.v3"
)

type Test struct {
	Name                  string             // The name of the test
	Allowed               bool               // Whether the request was actually allowed through by the plugin (set by next)
	Expect                int                // Response status code expected
	ExpectCounts          map[string]int     // Map of expected counts
	ExpectPluginError     string             // If set, expect this error message from plugin
	ExpectRedirect        string             // Full URL to expect redirection to
	ExpectHeaders         map[string]string  // Headers to expect in the downstream request as passed to next
	ExpectCookies         map[string]string  // Cookies to expect in the downstream request as passed to next
	ExpectResponseHeaders map[string]string  // Headers to expect in the response
	Config                string             // The dynamic yml configuration to pass to the plugin
	URL                   string             // Used to pass the URL from the server to the handlers (which must exist before the server)
	Keys                  jose.JSONWebKeySet // JWKS used in test server
	Method                jwt.SigningMethod  // Signing method for the token
	Private               string             // Private key to use to sign the token rather than generating one
	Kid                   string             // Kid for private key to use to sign the token rather than generating one
	CookieName            string             // The name of the cookie to use
	HeaderName            string             // The name of the header to use
	ParameterName         string             // The name of the parameter to use
	BearerPrefix          bool               // Whether to use the Bearer prefix or not
	Cookies               map[string]string  // Cookies to set in the incomming request
	Headers               map[string]string  // Headers to set in the incomming request
	Claims                string             // The claims to use in the token as a JSON string
	ClaimsMap             jwt.MapClaims      // claims mapped from `Claims`
	Actions               map[string]string  // Map of "actions" to take during the test, some are just flags and some have values
	Environment           map[string]string  // Map of environment variables to simulate for the test
	Counts                map[string]int     // Map of arbitrary counts recorded in the test
	Wait                  string             // Duration to wait before simulating the request
}

const (
	jwksCalls          = "jwksCalls"
	useFixedSecret     = "useFixedSecret"
	noAddIsser         = "noAddIsser"
	rotateKey          = "rotateKey"
	excludeIss         = "excludeIss"
	configBadBody      = "configBadBody"
	keysBadURL         = "keysBadURL"
	keysBadBody        = "keysBadBody"
	configServerStatus = "configServerStatus"
	keysServerStatus   = "keysServerStatus"
	invalidJSON        = "invalidJSON"
	traefikURL         = "traefikURL"
	yes                = "yes"
	invalid            = "invalid/dummy"
)

func TestServeHTTP(tester *testing.T) {
	tests := []Test{
		{
			Name:   "no token",
			Expect: http.StatusUnauthorized,
			Config: `
				require:
					aud: test
				parameterName: token`,
		},
		{
			Name:    "no token grpc",
			Expect:  http.StatusOK,
			Headers: map[string]string{"content-type": "application/grpc"},
			ExpectResponseHeaders: map[string]string{
				"grpc-status":  "16",
				"grpc-message": "UNAUTHENTICATED",
			},
			Config: `
				require:
					aud: test
				parameterName: token`,
		},
		{
			Name:   "optional with no token",
			Expect: http.StatusOK,
			Config: `
				require:
					aud: test
				optional: true
				parameterName: token`,
		},
		{
			Name:   "token in cookie",
			Expect: http.StatusOK,
			Config: `
				secret: fixed secret
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodHS256,
			CookieName: "Authorization",
		},
		{
			Name:   "token in header",
			Expect: http.StatusOK,
			Config: `
				secret: fixed secret
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodHS256,
			HeaderName: "Authorization",
		},
		{
			Name:   "token in header with Bearer prefix",
			Expect: http.StatusOK,
			Config: `
				secret: fixed secret
				require:
					aud: test`,
			Claims:       `{"aud": "test"}`,
			Method:       jwt.SigningMethodHS256,
			HeaderName:   "Authorization",
			BearerPrefix: true,
		},

		{
			Name:   "token in query string",
			Expect: http.StatusOK,
			Config: `
				secret: fixed secret
				require:
					aud: test
				parameterName: "token"
				forwardToken: false`,
			Claims:        `{"aud": "test"}`,
			Method:        jwt.SigningMethodHS256,
			ParameterName: "token",
		},

		{
			Name:   "expired token",
			Expect: http.StatusUnauthorized,
			Config: `
				secret: fixed secret
				require:
					aud: test`,
			Claims:     `{"aud": "test", "exp": 1692043084}`,
			Method:     jwt.SigningMethodHS256,
			HeaderName: "Authorization",
		},
		{
			Name:   "invalid claim",
			Expect: http.StatusForbidden,
			Config: `
				secret: fixed secret
				require:
					aud: test`,
			Claims:     `{"aud": "other"}`,
			Method:     jwt.SigningMethodHS256,
			HeaderName: "Authorization",
		},
		{
			Name:    "valid grpc",
			Expect:  http.StatusOK,
			Headers: map[string]string{"content-type": "application/grpc"},
			Config: `
				secret: fixed secret
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodHS256,
			HeaderName: "Authorization",
		},
		{
			Name:    "invalid claim grpc",
			Expect:  http.StatusOK,
			Headers: map[string]string{"content-type": "application/grpc"},
			ExpectResponseHeaders: map[string]string{
				"grpc-status":  "7",
				"grpc-message": "PERMISSION_DENIED",
			},
			Config: `
				secret: fixed secret
				require:
					aud: test`,
			Claims:     `{"aud": "other"}`,
			Method:     jwt.SigningMethodHS256,
			HeaderName: "Authorization",
		},
		{
			Name:    "invalid claim grpc with proto content-type",
			Expect:  http.StatusOK,
			Headers: map[string]string{"content-type": "application/grpc+proto"},
			ExpectResponseHeaders: map[string]string{
				"grpc-status":  "7",
				"grpc-message": "PERMISSION_DENIED",
			},
			Config: `
				secret: fixed secret
				require:
					aud: test`,
			Claims:     `{"aud": "other"}`,
			Method:     jwt.SigningMethodHS256,
			HeaderName: "Authorization",
		},
		{
			Name:   "value requirement with invalid type of claim",
			Expect: http.StatusForbidden,
			Config: `
				secret: fixed secret
				require:
					aud: 123`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodHS256,
			HeaderName: "Authorization",
		},
		{
			Name:   "missing claim",
			Expect: http.StatusForbidden,
			Config: `
				secret: fixed secret
				require:
					aud: test`,
			Method:     jwt.SigningMethodHS256,
			HeaderName: "Authorization",
		},
		{
			Name:   "StatusUnauthorized when outside window of freshness",
			Expect: http.StatusUnauthorized,
			Config: `
				secret: fixed secret
				require:
					aud: test`,
			Claims:     `{"aud": "other", "iat": 1692451139}`,
			Method:     jwt.SigningMethodHS256,
			HeaderName: "Authorization",
		},
		{
			Name:   "StatusForbidden when no window of freshness",
			Expect: http.StatusForbidden,
			Config: `
				secret: fixed secret
				freshness: 0
				require:
					aud: test`,
			Claims:     `{"aud": "other", "iat": 1692451139}`,
			Method:     jwt.SigningMethodHS256,
			HeaderName: "Authorization",
		},
		{
			Name:   "template requirement",
			Expect: http.StatusOK,
			Config: `
				secret: fixed secret
				require:
					authority: "{{.Host}}"`,
			Claims:     `{"authority": "app.example.com"}`,
			Method:     jwt.SigningMethodHS256,
			HeaderName: "Authorization",
		},
		{
			Name:   "template requirement with functions",
			Expect: http.StatusOK,
			Config: `
				secret: fixed secret
				require:
					authority: '{{Index (Split .Host ".") 0}}'`,
			Claims:     `{"authority": "app"}`,
			Method:     jwt.SigningMethodHS256,
			HeaderName: "Authorization",
		},
		{
			Name:   "template requirement wth wildcard claim",
			Expect: http.StatusOK,
			Config: `
				secret: fixed secret
				require:
					authority: "{{.Host}}"`,
			Claims:     `{"authority": "*.example.com"}`,
			Method:     jwt.SigningMethodHS256,
			HeaderName: "Authorization",
		},
		{
			Name:   "template requirement from environment variable",
			Expect: http.StatusOK,
			Config: `
				secret: fixed secret
				require:
					authority: "{{.Domain}}"`,
			Claims:      `{"authority": "*.example.com"}`,
			Method:      jwt.SigningMethodHS256,
			HeaderName:  "Authorization",
			Environment: map[string]string{"Domain": "app.example.com"},
		},
		{
			Name:   "invalid claim for template requirement from environment variable",
			Expect: http.StatusForbidden,
			Config: `
				secret: fixed secret
				require:
					authority: "{{.Domain}}"`,
			Claims:      `{"authority": "*.example.com"}`,
			Method:      jwt.SigningMethodHS256,
			HeaderName:  "Authorization",
			Environment: map[string]string{"Domain": "app.other.com"},
		},
		{
			Name:   "template requirement from missing environment variable",
			Expect: http.StatusForbidden,
			Config: `
				secret: fixed secret
				require:
					authority: "{{.Domain}}"`,
			Claims:     `{"authority": "*.example.com"}`,
			Method:     jwt.SigningMethodHS256,
			HeaderName: "Authorization",
		},
		{
			Name:   "bad template requirement",
			Expect: http.StatusForbidden, // TODO add check on startup
			Config: `
				secret: fixed secret
				require:
					authority: "{{.XHost}}"`,
			Claims:     `{"authority": "*.example.com"}`,
			Method:     jwt.SigningMethodHS256,
			HeaderName: "Authorization",
		},
		{
			Name:   "wildcard claim",
			Expect: http.StatusOK,
			Config: `
				secret: fixed secret
				require:
					authority: test.example.com`,
			Claims:     `{"authority": "*.example.com"}`,
			Method:     jwt.SigningMethodHS256,
			HeaderName: "Authorization",
		},
		{
			Name:   "wildcard claim no subdomain",
			Expect: http.StatusOK,
			Config: `
				secret: fixed secret
				require:
					authority: example.com`,
			Claims:     `{"authority": "*.example.com"}`,
			Method:     jwt.SigningMethodHS256,
			HeaderName: "Authorization",
		},
		{
			Name:   "wildcard list claim",
			Expect: http.StatusOK,
			Config: `
				secret: fixed secret
				require:
					authority: test.example.com`,
			Claims:     `{"authority": ["*.example.com", "other.example.com"]}`,
			Method:     jwt.SigningMethodHS256,
			HeaderName: "Authorization",
		},
		{
			Name:   "list with wildcard list claim",
			Expect: http.StatusOK,
			Config: `
				secret: fixed secret
				require:
					authority: ["test.example.com", "other.other.com"]`,
			Claims:     `{"authority": ["*.example.com", "other.example.com"]}`,
			Method:     jwt.SigningMethodHS256,
			HeaderName: "Authorization",
		},
		{
			Name:   "wildcard object and single required and nested",
			Expect: http.StatusOK,
			Config: `
				secret: fixed secret
				require:
					authority:
						"test.example.com": "user"`,
			Claims: `{
				"authority": {
					"*.example.com": "user"
				}
			}`,
			Method:     jwt.SigningMethodHS256,
			HeaderName: "Authorization",
		},
		{
			Name:   "wildcard object and single requred and multilpe nested",
			Expect: http.StatusOK,
			Config: `
				secret: fixed secret
				require:
					authority:
						"test.example.com": "user"`,
			Claims: `{
				"authority": {
					"*.example.com": ["user", "admin"]
				}
			}`,
			Method:     jwt.SigningMethodHS256,
			HeaderName: "Authorization",
		},
		{
			Name:   "wildcard object and multiple required and single nested",
			Expect: http.StatusOK,
			Config: `
				secret: fixed secret
				require:
					authority:
						"test.example.com": ["user", "admin"]`,
			Claims: `{
				"authority": {
					"*.example.com": "user"
				}
			}`,
			Method:     jwt.SigningMethodHS256,
			HeaderName: "Authorization",
		},
		{
			Name:   "wildcard object and multiple required and single invalid nested",
			Expect: http.StatusForbidden,
			Config: `
				secret: fixed secret
				require:
					authority:
						"test.example.com": ["user", "admin"]`,
			Claims: `{
				"authority": {
					"*.example.com": "other"
				}
			}`,
			Method:     jwt.SigningMethodHS256,
			HeaderName: "Authorization",
		},
		{
			Name:   "wildcard object and irrelevant nested value claim",
			Expect: http.StatusOK,
			Config: `
				secret: fixed secret
				require:
					authority: "test.example.com"`,
			Claims: `{
				"authority": {
					"*.example.com": ["user", "admin"]
				}
			}`,
			Method:     jwt.SigningMethodHS256,
			HeaderName: "Authorization",
		},
		{
			Name:   "wildcard object bad nested value claim",
			Expect: http.StatusForbidden,
			Config: `
				secret: fixed secret
				require:
					authority:
						"test.example.com": "admin"`,
			Claims: `{
				"authority": {
					"*.example.com": ["user", "guest"]
				}
			}`,
			Method:     jwt.SigningMethodHS256,
			HeaderName: "Authorization",
		},
		{
			Name:   "bad wildcard claim",
			Expect: http.StatusForbidden,
			Config: `
				secret: fixed secret
				logUnauthorized: info
				require:
					authority: "test.company.com"`,
			Claims:     `{"authority": "*.example.com"}`,
			Method:     jwt.SigningMethodHS256,
			HeaderName: "Authorization",
		},
		{
			Name:   "bad wildcard list claim",
			Expect: http.StatusForbidden,
			Config: `
				secret: fixed secret
				require:
					authority: "test.example.com"`,
			Claims:     `{"authority": ["*.company.com", "other.example.com"]}`,
			Method:     jwt.SigningMethodHS256,
			HeaderName: "Authorization",
		},
		{
			Name:   "bad wildcard object claim",
			Expect: http.StatusForbidden,
			Config: `
				secret: fixed secret
				require:
					authority: "test.example.com"`,
			Claims: `{
				"authority": {
					"*.company.com": ["user", "admin"]
				}
			}`,
			Method:     jwt.SigningMethodHS256,
			HeaderName: "Authorization",
		},
		{
			Name:   "SigningMethodHS256",
			Expect: http.StatusOK,
			Config: `
				secret: fixed secret
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodHS256,
			HeaderName: "Authorization",
		},
		{
			Name:   "SigningMethodHS384",
			Expect: http.StatusOK,
			Config: `
				secret: fixed secret
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodHS384,
			HeaderName: "Authorization",
		},
		{
			Name:   "SigningMethodHS512",
			Expect: http.StatusOK,
			Config: `
				secret: fixed secret
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodHS512,
			HeaderName: "Authorization",
		},
		{
			Name:   "SigningMethodRS256",
			Expect: http.StatusOK,
			Config: `
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodRS256,
			HeaderName: "Authorization",
		},
		{
			Name:   "SigningMethodRS384",
			Expect: http.StatusOK,
			Config: `
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodRS384,
			HeaderName: "Authorization",
		},
		{
			Name:   "SigningMethodRS512",
			Expect: http.StatusOK,
			Config: `
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodRS512,
			HeaderName: "Authorization",
		},
		{
			Name:   "SigningMethodES256",
			Expect: http.StatusOK,
			Config: `
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodES256,
			HeaderName: "Authorization",
		},
		{
			Name:   "SigningMethodES384",
			Expect: http.StatusOK,
			Config: `
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodES384,
			HeaderName: "Authorization",
		},
		{
			Name:   "SigningMethodES512",
			Expect: http.StatusOK,
			Config: `
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodES512,
			HeaderName: "Authorization",
		},
		{
			Name:   "SigningMethodRS256 with missing kid",
			Expect: http.StatusOK,
			Config: `
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodRS256,
			HeaderName: "Authorization",
			Actions:    map[string]string{"set:kid": ""},
		},
		{
			Name:   "SigningMethodRS256 with bad n",
			Expect: http.StatusUnauthorized,
			Config: `
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodRS256,
			HeaderName: "Authorization",
			Actions:    map[string]string{"set:n": invalid},
		},
		{
			Name:   "SigningMethodRS256 with bad e",
			Expect: http.StatusUnauthorized,
			Config: `
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodRS256,
			HeaderName: "Authorization",
			Actions:    map[string]string{"set:e": invalid},
		},
		{
			Name:   "SigningMethodES256 with missing kid",
			Expect: http.StatusOK,
			Config: `
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodES256,
			HeaderName: "Authorization",
			Actions:    map[string]string{"set:kid": ""},
		},
		{
			Name:   "SigningMethodES256 with bad x",
			Expect: http.StatusUnauthorized,
			Config: `
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodES256,
			HeaderName: "Authorization",
			Actions:    map[string]string{"set:x": invalid},
		},
		{
			Name:   "SigningMethodES256 with bad y",
			Expect: http.StatusUnauthorized,
			Config: `
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodES256,
			HeaderName: "Authorization",
			Actions:    map[string]string{"set:y": invalid},
		},
		{
			Name:   "SigningMethodES256 with missing crv",
			Expect: http.StatusOK,
			Config: `
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodES256,
			HeaderName: "Authorization",
			Actions:    map[string]string{"set:crv": invalid},
		},
		{
			Name:   "SigningMethodES256 with missing crv and alg",
			Expect: http.StatusOK,
			Config: `
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodES256,
			HeaderName: "Authorization",
			Actions:    map[string]string{"set:crv": invalid, "set:alg": invalid},
		},
		{
			Name:   "SigningMethodES384 with missing crv",
			Expect: http.StatusOK,
			Config: `
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodES384,
			HeaderName: "Authorization",
			Actions:    map[string]string{"set:crv": invalid},
		},
		{
			Name:   "SigningMethodES512 with missing crv",
			Expect: http.StatusOK,
			Config: `
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodES512,
			HeaderName: "Authorization",
			Actions:    map[string]string{"set:crv": invalid},
		},
		{
			Name:   "SigningMethodRS256 in fixed secret",
			Expect: http.StatusOK,
			Config: `
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodRS256,
			HeaderName: "Authorization",
			Actions:    map[string]string{useFixedSecret: yes, noAddIsser: yes},
		},
		{
			Name:   "SigningMethodRS512 in fixed secret",
			Expect: http.StatusOK,
			Config: `
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodRS512,
			HeaderName: "Authorization",
			Actions:    map[string]string{useFixedSecret: yes, noAddIsser: yes},
		},
		{
			Name:   "SigningMethodES256 in fixed secret",
			Expect: http.StatusOK,
			Config: `
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodES256,
			HeaderName: "Authorization",
			Actions:    map[string]string{useFixedSecret: yes, noAddIsser: yes},
		},
		{
			Name:   "SigningMethodES384 in fixed secret",
			Expect: http.StatusOK,
			Config: `
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodES384,
			HeaderName: "Authorization",
			Actions:    map[string]string{useFixedSecret: yes, noAddIsser: yes},
		},
		{
			Name:   "SigningMethodES512 in fixed secret",
			Expect: http.StatusOK,
			Config: `
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodES512,
			HeaderName: "Authorization",
			Actions:    map[string]string{useFixedSecret: yes, noAddIsser: yes},
		},
		{
			Name:              "bad fixed secret",
			ExpectPluginError: "invalid key: Key must be a PEM encoded PKCS1 or PKCS8 key",
			Config: `
				secret: -----BEGIN RSA PUBLIC KEY 
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodRS512,
			CookieName: "Authorization",
		},
		{
			Name:         "EC fixed secrets",
			Expect:       http.StatusOK,
			ExpectCounts: map[string]int{jwksCalls: 0},
			Config: `
				secrets:
					43263adb454e2217b26212b925498a139438912d: |
						-----BEGIN EC PUBLIC KEY-----
						MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEE7gFCo/g2PQmC3i5kIqVgCCzr2D1
						nbCeipqfvK1rkqmKfhb7rlVehfC7ITUAy8NIvQ/AsXClvgHDv55BfOoL6w==
						-----END EC PUBLIC KEY-----
				skipPrefetch: true
				require:
					aud: test`,
			Claims: `{"aud": "test"}`,
			Method: jwt.SigningMethodES256,
			Private: `
				-----BEGIN EC PRIVATE KEY-----
				MHcCAQEEIOGYoXIkNQh/7WBgOwZ+epQFMdkgGcdHwLQFL69oYEodoAoGCCqGSM49
				AwEHoUQDQgAEE7gFCo/g2PQmC3i5kIqVgCCzr2D1nbCeipqfvK1rkqmKfhb7rlVe
				hfC7ITUAy8NIvQ/AsXClvgHDv55BfOoL6w==
				-----END EC PRIVATE KEY-----`,
			Kid:        "43263adb454e2217b26212b925498a139438912d",
			CookieName: "Authorization",
			Actions:    map[string]string{noAddIsser: yes},
		},
		{
			Name:         "RSA fixed secrets",
			Expect:       http.StatusOK,
			ExpectCounts: map[string]int{jwksCalls: 0},
			Config: `
				secrets:
					43263adb454e2217b26212b925498a139438912d: |
						-----BEGIN RSA PUBLIC KEY-----
						MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDXmKeNKX/IRWeNcD6LQjAWWOAZ
						SqnLCbjo0kQxXS7hZb8SLe03vogapSv9Ld6Cocs0aFjfkzbrQPdTskooAWfWr8Yq
						x2y2JQTLhjxHpjp/napf5SLG9jbu02jpgWSY/Zks/21ARQ4mXS3T5OlXMJc94BA/
						nT57PUdl55RWyQJxmwIDAQAB
						-----END RSA PUBLIC KEY-----
				skipPrefetch: true
				require:
					aud: test`,
			Claims: `{"aud": "test"}`,
			Method: jwt.SigningMethodRS256,
			Private: `
				-----BEGIN RSA PRIVATE KEY-----
				MIICXAIBAAKBgQDXmKeNKX/IRWeNcD6LQjAWWOAZSqnLCbjo0kQxXS7hZb8SLe03
				vogapSv9Ld6Cocs0aFjfkzbrQPdTskooAWfWr8Yqx2y2JQTLhjxHpjp/napf5SLG
				9jbu02jpgWSY/Zks/21ARQ4mXS3T5OlXMJc94BA/nT57PUdl55RWyQJxmwIDAQAB
				AoGATvc2x1lf2DazivaFsfP4MPc0fY7/ScKx23TITVxYA26E4V+49yXuK/Q7fGwE
				h8xC5Vsi0iDViK0u6ZTv3F9HbIqhmuVoSBWL5PlAZWvEWMwTldHnmQDCQBraQndV
				ZAtJi1CTdVH4LbtCgRfu74yjUktUZqQKHzGi94lkRz5/i4ECQQDx1f47EsBU4v14
				cgXMFVkWAEH23dNGarOc9j6mldiVGQwbqsnO94aY3ki7tEd2n59ByEFpYeXiX/Ei
				kSIXEKGxAkEA5Dk7yco5aK7PffhX/Z534JAd9R9We4FP2SBSBUFibAY47VQVDeXT
				IosMxwExY63UeBJ6FMwgAFCZc/YaQlwvCwJAfWRkrsKZQSp1HMeaY+hJydOWYGdC
				TgezW9Z+Q6f8pcpX8dyLSSok+wx+j/z49PPtApHQANFG/iqbAD5ae7Ue8QJAXuQR
				IOCtKAJvEVBdvXzTGRKy8gU6nxVwDrYqhDbgZkvcBYmNS38AX39zK5cqYuiWy+na
				yqTotVjNxPJRjr/nawJBAOwxui0TfED16oSMbFD6kxfcjnxtHSTu/2AlO/+0ydpE
				9CbIg52IdIg+zM55iKwjllF59cVayR2AeAywT3VyNd8=
				-----END RSA PRIVATE KEY-----`,
			Kid:        "43263adb454e2217b26212b925498a139438912d",
			CookieName: "Authorization",
			Actions:    map[string]string{noAddIsser: yes},
		},
		{
			Name:         "EC fixed secrets no type",
			Expect:       http.StatusOK,
			ExpectCounts: map[string]int{jwksCalls: 0},
			Config: `
				secrets:
					43263adb454e2217b26212b925498a139438912d: |
						-----BEGIN PUBLIC KEY-----
						MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEE7gFCo/g2PQmC3i5kIqVgCCzr2D1
						nbCeipqfvK1rkqmKfhb7rlVehfC7ITUAy8NIvQ/AsXClvgHDv55BfOoL6w==
						-----END PUBLIC KEY-----
				skipPrefetch: true
				require:
					aud: test`,
			Claims: `{"aud": "test"}`,
			Method: jwt.SigningMethodES256,
			Private: `
				-----BEGIN EC PRIVATE KEY-----
				MHcCAQEEIOGYoXIkNQh/7WBgOwZ+epQFMdkgGcdHwLQFL69oYEodoAoGCCqGSM49
				AwEHoUQDQgAEE7gFCo/g2PQmC3i5kIqVgCCzr2D1nbCeipqfvK1rkqmKfhb7rlVe
				hfC7ITUAy8NIvQ/AsXClvgHDv55BfOoL6w==
				-----END EC PRIVATE KEY-----`,
			Kid:        "43263adb454e2217b26212b925498a139438912d",
			CookieName: "Authorization",
			Actions:    map[string]string{noAddIsser: yes},
		},
		{
			Name:         "RSA fixed secrets no type",
			Expect:       http.StatusOK,
			ExpectCounts: map[string]int{jwksCalls: 0},
			Config: `
				secrets:
					43263adb454e2217b26212b925498a139438912d: |
						-----BEGIN PUBLIC KEY-----
						MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDXmKeNKX/IRWeNcD6LQjAWWOAZ
						SqnLCbjo0kQxXS7hZb8SLe03vogapSv9Ld6Cocs0aFjfkzbrQPdTskooAWfWr8Yq
						x2y2JQTLhjxHpjp/napf5SLG9jbu02jpgWSY/Zks/21ARQ4mXS3T5OlXMJc94BA/
						nT57PUdl55RWyQJxmwIDAQAB
						-----END PUBLIC KEY-----
				skipPrefetch: true
				require:
					aud: test`,
			Claims: `{"aud": "test"}`,
			Method: jwt.SigningMethodRS256,
			Private: `
				-----BEGIN RSA PRIVATE KEY-----
				MIICXAIBAAKBgQDXmKeNKX/IRWeNcD6LQjAWWOAZSqnLCbjo0kQxXS7hZb8SLe03
				vogapSv9Ld6Cocs0aFjfkzbrQPdTskooAWfWr8Yqx2y2JQTLhjxHpjp/napf5SLG
				9jbu02jpgWSY/Zks/21ARQ4mXS3T5OlXMJc94BA/nT57PUdl55RWyQJxmwIDAQAB
				AoGATvc2x1lf2DazivaFsfP4MPc0fY7/ScKx23TITVxYA26E4V+49yXuK/Q7fGwE
				h8xC5Vsi0iDViK0u6ZTv3F9HbIqhmuVoSBWL5PlAZWvEWMwTldHnmQDCQBraQndV
				ZAtJi1CTdVH4LbtCgRfu74yjUktUZqQKHzGi94lkRz5/i4ECQQDx1f47EsBU4v14
				cgXMFVkWAEH23dNGarOc9j6mldiVGQwbqsnO94aY3ki7tEd2n59ByEFpYeXiX/Ei
				kSIXEKGxAkEA5Dk7yco5aK7PffhX/Z534JAd9R9We4FP2SBSBUFibAY47VQVDeXT
				IosMxwExY63UeBJ6FMwgAFCZc/YaQlwvCwJAfWRkrsKZQSp1HMeaY+hJydOWYGdC
				TgezW9Z+Q6f8pcpX8dyLSSok+wx+j/z49PPtApHQANFG/iqbAD5ae7Ue8QJAXuQR
				IOCtKAJvEVBdvXzTGRKy8gU6nxVwDrYqhDbgZkvcBYmNS38AX39zK5cqYuiWy+na
				yqTotVjNxPJRjr/nawJBAOwxui0TfED16oSMbFD6kxfcjnxtHSTu/2AlO/+0ydpE
				9CbIg52IdIg+zM55iKwjllF59cVayR2AeAywT3VyNd8=
				-----END RSA PRIVATE KEY-----`,
			Kid:        "43263adb454e2217b26212b925498a139438912d",
			CookieName: "Authorization",
			Actions:    map[string]string{noAddIsser: yes},
		},
		{
			Name:              "bad fixed secrets",
			ExpectPluginError: "kid b6a5717df9dc13c9b15aab32dc811fd38144d43c: invalid key: Key must be a PEM encoded PKCS1 or PKCS8 key",
			Config: `
				secrets:
				  b6a5717df9dc13c9b15aab32dc811fd38144d43c: |
				    -----BEGIN RSA PUBLIC KEY 
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodRS512,
			CookieName: "Authorization",
			Actions:    map[string]string{noAddIsser: yes},
		},
		{
			Name:              "empty fixed secrets",
			ExpectPluginError: "kid b6a5717df9dc13c9b15aab32dc811fd38144d43c: invalid key: Key is empty",
			Config: `
				secrets:
				  b6a5717df9dc13c9b15aab32dc811fd38144d43c: ""
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodRS512,
			CookieName: "Authorization",
			Actions:    map[string]string{noAddIsser: yes},
		},
		{
			Name:   "skipPrefetch",
			Expect: http.StatusOK,
			Config: `
			    skipPrefetch: true
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodRS256,
			HeaderName: "Authorization",
		},
		{
			Name:   "delayPrefetch",
			Expect: http.StatusOK,
			Config: `
			    delayPrefetch: "1s"
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodRS256,
			HeaderName: "Authorization",
		},
		{
			Name:              "bad delayPrefetch",
			ExpectPluginError: `invalid delayPrefetch: time: invalid duration "s"`,
			Config: `
			    delayPrefetch: "s"
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodRS256,
			HeaderName: "Authorization",
		},
		{
			Name:   "refreshKeysInterval",
			Expect: http.StatusOK,
			Config: `
			    refreshKeysInterval: "3s"
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodRS256,
			HeaderName: "Authorization",
		},
		{
			Name:              "bad refreshKeysInterval",
			ExpectPluginError: `invalid refreshKeysInterval: time: invalid duration "s"`,
			Config: `
			    refreshKeysInterval: "s"
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodRS256,
			HeaderName: "Authorization",
		},
		{
			Name:   "unknown issuer",
			Expect: http.StatusUnauthorized,
			Config: `
			    skipPrefetch: true
				require:
					aud: test`,
			Claims:     `{"aud": "test", "iss": "unknown.com"}`,
			Method:     jwt.SigningMethodRS256,
			HeaderName: "Authorization",
		},
		{
			Name:   "no issuer",
			Expect: http.StatusUnauthorized,
			Config: `
			    skipPrefetch: true
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodRS256,
			HeaderName: "Authorization",
			Actions:    map[string]string{excludeIss: yes},
		},
		{
			Name:   "wildcard isser",
			Expect: http.StatusOK,
			Config: `
				issuers:
				    - "http://127.0.0.1:*/"
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodES256,
			HeaderName: "Authorization",
			Actions:    map[string]string{noAddIsser: yes},
		},
		{
			Name:   "bad wildcard isser",
			Expect: http.StatusUnauthorized,
			Config: `
				issuers:
				    - "http://example.com:*/"
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodES256,
			HeaderName: "Authorization",
			Actions:    map[string]string{noAddIsser: yes},
		},
		{
			Name:         "key rotation",
			Expect:       http.StatusOK,
			ExpectCounts: map[string]int{jwksCalls: 2},
			Config: `
			    skipPrefetch: true
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodRS256,
			HeaderName: "Authorization",
			Actions:    map[string]string{rotateKey: yes},
		},
		{
			Name:   "config bad body",
			Expect: http.StatusOK,
			Config: `
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodES256,
			HeaderName: "Authorization",
			Actions:    map[string]string{configBadBody: yes},
		},
		{
			Name:   "keys bad url",
			Expect: http.StatusUnauthorized,
			Config: `
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodES256,
			HeaderName: "Authorization",
			Actions:    map[string]string{keysBadURL: yes},
		},
		{
			Name:   "keys bad body",
			Expect: http.StatusUnauthorized,
			Config: `
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodES256,
			HeaderName: "Authorization",
			Actions:    map[string]string{keysBadBody: yes},
		},
		{
			Name:   "config server internal error",
			Expect: http.StatusOK,
			Config: `
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodES256,
			HeaderName: "Authorization",
			Actions:    map[string]string{configServerStatus: "500"},
		},
		{
			Name:   "keys server internal error",
			Expect: http.StatusUnauthorized,
			Config: `
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodES256,
			HeaderName: "Authorization",
			Actions:    map[string]string{keysServerStatus: "500"},
		},
		{
			Name:   "invalid json",
			Expect: http.StatusUnauthorized,
			Config: `
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodES256,
			HeaderName: "Authorization",
			Actions:    map[string]string{invalidJSON: invalid},
		},
		{
			Name:           "redirect with expired token",
			Expect:         http.StatusFound,
			ExpectRedirect: "https://example.com/login?return_to=https%3A%2F%2Fapp.example.com%2Fhome%3Fid%3D1%26other%3D2",
			Config: `
				secret: fixed secret
				require:
					aud: test
				redirectUnauthorized: https://example.com/login?return_to={{URLQueryEscape .URL}}
				redirectForbidden: https://example.com/unauthorized?return_to={{URLQueryEscape .URL}}`,
			Claims:     `{"aud": "test", "exp": 1692043084}`,
			Method:     jwt.SigningMethodHS256,
			HeaderName: "Authorization",
		},
		{
			Name:           "redirect with expired token and traefik-style URL",
			Expect:         http.StatusFound,
			ExpectRedirect: "https://example.com/login?return_to=https%3A%2F%2Fapp.example.com%2Fhome%3Fid%3D1%26other%3D2",
			Config: `
				secret: fixed secret
				require:
					aud: test
				redirectUnauthorized: https://example.com/login?return_to={{URLQueryEscape .URL}}
				redirectForbidden: https://example.com/unauthorized?return_to={{URLQueryEscape .URL}}`,
			Claims:     `{"aud": "test", "exp": 1692043084}`,
			Method:     jwt.SigningMethodHS256,
			HeaderName: "Authorization",
			Actions:    map[string]string{traefikURL: invalid},
		},
		{
			Name:           "redirect with missing claim",
			Expect:         http.StatusFound,
			ExpectRedirect: "https://example.com/unauthorized?return_to=https%3A%2F%2Fapp.example.com%2Fhome%3Fid%3D1%26other%3D2",
			Config: `
				secret: fixed secret
				require:
					aud: test
				redirectUnauthorized: https://example.com/login?return_to={{URLQueryEscape .URL}}
				redirectForbidden: https://example.com/unauthorized?return_to={{URLQueryEscape .URL}}`,
			Method:     jwt.SigningMethodHS256,
			HeaderName: "Authorization",
		},
		{
			Name:   "redirect with bad interpolation",
			Expect: http.StatusInternalServerError,
			Config: `
				secret: fixed secret
				require:
					aud: test
				redirectUnauthorized: https://example.com/login?return_to={{URLQueryEscape .URL}}
				redirectForbidden: https://example.com/unauthorized?return_to={{URLQueryEscape .Unknown}}`,
			Method:     jwt.SigningMethodHS256,
			HeaderName: "Authorization",
		},
		{
			Name:          "map headers",
			Expect:        http.StatusOK,
			ExpectHeaders: map[string]string{"X-Number": "1234", "X-Array": `["test",1,null]`, "X-Map": `{"a":1,"b":2}`, "X-Boolean": "true", "X-Null": "null", "X-Text": "Hello, world!"},
			Config: `
				secret: fixed secret
				require:
					aud: test
				headerMap:
					X-Number: number
					X-Array: array
					X-Map: map
					X-Boolean: boolean
					X-Null: nulled
					X-Text: text
				forwardToken: false`,
			Claims:     `{"aud": "test", "number": "1234", "array": ["test", 1, null], "map": {"a": 1, "b": 2}, "boolean": true, "nulled": null, "text": "Hello, world!"}`,
			Method:     jwt.SigningMethodHS256,
			HeaderName: "Authorization",
		},
		{
			Name:          "remove missing headers",
			Expect:        http.StatusOK,
			Headers:       map[string]string{"X-Other": "other", "X-Id": "impersonated"},
			ExpectHeaders: map[string]string{"X-Other": "other", "X-Audience": "test"},
			Config: `
				secret: fixed secret
				require:
					aud: test
				headerMap:
					X-Audience: aud
					X-Id: user
				removeMissingHeaders: true`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodHS256,
			HeaderName: "Authorization",
		},
		{
			Name:          "remove headers when optional and no token",
			Expect:        http.StatusOK,
			Headers:       map[string]string{"X-Other": "other", "X-Id": "impersonated"},
			ExpectHeaders: map[string]string{"X-Other": "other"},
			Config: `
				secret: fixed secret
				require:
					aud: test
				optional: true
				headerMap:
					X-Audience: aud
					X-Id: user
				removeMissingHeaders: true`,
		},
		{
			Name:          "cookies",
			Expect:        http.StatusOK,
			ExpectCookies: map[string]string{"Test": "test", "Other": "other"},
			Cookies:       map[string]string{"Test": "test", "Other": "other"},
			Config: `
				secret: fixed secret
				require:
					aud: test
				forwardToken: false`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodHS256,
			CookieName: "Authorization",
		},
		{
			Name:         "Prefetch",
			Expect:       http.StatusOK,
			ExpectCounts: map[string]int{jwksCalls: 1},
			Config: `
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodRS256,
			HeaderName: "Authorization",
			Wait:       "1s",
		},
		{
			Name:   "Non-existant issuers",
			Expect: http.StatusOK,
			Config: `
				issuers:
					- https://dummy.example.com
					- https://example.com
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodRS256,
			HeaderName: "Authorization",
		},
		{
			Name:   "InsecureSkipVerify",
			Expect: http.StatusOK,
			Config: `
				issuers:
					- "https://127.0.0.1/"
				insecureSkipVerify:
					- "127.0.0.1"
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodES256,
			HeaderName: "Authorization",
		},
		{
			Name:   "RootCAs",
			Expect: http.StatusOK,
			Config: `
				rootCAs: |
                    -----BEGIN CERTIFICATE-----
                    MIIDJzCCAg+gAwIBAgIUDDYN8pGCpUC6tsqDW4meIXsmN04wDQYJKoZIhvcNAQEL
                    BQAwIzELMAkGA1UEBhMCVUsxFDASBgNVBAoMC0FnaWxlIFplYnJhMB4XDTI1MDMx
                    MTE0MTU1MloXDTM1MDMwOTE0MTU1MlowIzELMAkGA1UEBhMCVUsxFDASBgNVBAoM
                    C0FnaWxlIFplYnJhMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA70Gs
                    A3QEKB94Eqyt+V07qDNtykhlyOLSiGIRk1/Slr5B1mTY8Mt88gg8MFldyVukjze+
                    /5GT/lZ3plMMiA7wnpJ683iWqMVOzQTtYlgcMknnrRJhHuDIGmcdakudXl484emE
                    9iz+cWgl2cw1rb0rtNC1koQ90MohcTqW+5By0TUaulf80ZcJbGFG8LTqVKVJatET
                    QedgrYR3tIR6VRtj7pnFZ1w9gZhpPL26mrMg3Wk3GHf/j48jebHVYbeuuSoBXJX8
                    rGmfCtwzMWqyZvMU9MRP6KpPu20UIOuzau6JyD22RhlLSrX/1eI9Et0IMqEF/iM/
                    EGpTGDJTeX3bJavzAQIDAQABo1MwUTAdBgNVHQ4EFgQUwR3igK8QvKXQ3JuGlYUc
                    1jHwBqUwHwYDVR0jBBgwFoAUwR3igK8QvKXQ3JuGlYUc1jHwBqUwDwYDVR0TAQH/
                    BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAoEgu6gQTf8Br0Id7Jp6Oht6XSG0o
                    RtYJ4SwWD0U1acJpWKgtTkBA9cfGMYngFzUe9Xmxt1iBSCJtbQ/SQj5x0vcXsoR0
                    zWBnihf3XERnJOyLWR7cUCfVYEu0xFCNrc1m5Wzj4IG2NJBTtiIiAdnTbEcBd7hk
                    f7Vy+al187qn3HQcwdRfMatjFrrM92tHvd79VJsZcgj8Yl3QcgZFIQ2O+PtrXxLR
                    2auMwVTxdRe0QUT6zvtZGf1niNH5s8DBVeDWqBArlC7M/HuLj6QOIMDEI2aC3yS1
                    LT12fZ0MWBjfGc90EEJ9z4/CRUWMdtlOaLnXinyrvOH+SSTJD8xfwKqH6g==
                    -----END CERTIFICATE-----
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodES256,
			HeaderName: "Authorization",
		},
		{
			Name:   "RootCAs from file",
			Expect: http.StatusOK,
			Config: `
				rootCAs: 
					- testing/rootca.pem
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodES256,
			HeaderName: "Authorization",
		},
		{
			Name:              "RootCAs from bad file",
			ExpectPluginError: "failed to load root CA: open notexist/rootca.pem: no such file or directory",
			Config: `
				rootCAs: 
					- notexist/rootca.pem
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodES256,
			HeaderName: "Authorization",
		},
		{
			Name:   "Bad RootCAs",
			Expect: http.StatusOK,
			Config: `
				rootCAs: |
                    -----BEGIN CERTIFICATE-----
                    bad
                    -----END CERTIFICATE-----
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodES256,
			HeaderName: "Authorization",
		},
		{
			Name:   "infoToStdout",
			Expect: http.StatusOK,
			Config: `
				infoToStdout: true
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodES256,
			CookieName: "Authorization",
		},
		{
			Name:   "large integer needing json.Number to keep precision",
			Expect: http.StatusOK,
			Config: `
				infoToStdout: true
				require:
					large: 1147953659032899584`,
			ClaimsMap:  jwt.MapClaims{"large": 1147953659032899584},
			Method:     jwt.SigningMethodES256,
			CookieName: "Authorization",
		},
		{
			Name:   "invalid integer claim",
			Expect: http.StatusForbidden,
			Config: `
				infoToStdout: true
				logUnauthorized: info
				require:
					int: 0`,
			ClaimsMap:  jwt.MapClaims{"int": 1},
			Method:     jwt.SigningMethodES256,
			CookieName: "Authorization",
		},
		{
			Name:   "float claim",
			Expect: http.StatusOK,
			Config: `
				infoToStdout: true
				require:
					float: 0.0`,
			ClaimsMap:  jwt.MapClaims{"float": 0.0},
			Method:     jwt.SigningMethodES256,
			CookieName: "Authorization",
		},
		{
			Name:   "invalid float claim",
			Expect: http.StatusForbidden,
			Config: `
				infoToStdout: true
				logUnauthorized: info
				require:
					float: 0.0`,
			ClaimsMap:  jwt.MapClaims{"float": 1.0},
			Method:     jwt.SigningMethodES256,
			CookieName: "Authorization",
		},
		{
			Name:   "claim with different type",
			Expect: http.StatusForbidden,
			Config: `
				infoToStdout: true
				require:
					large: "1147953659032899584"`,
			ClaimsMap:  jwt.MapClaims{"large": 1147953659032899584},
			Method:     jwt.SigningMethodES256,
			CookieName: "Authorization",
		},
		{
			Name:   "deeply nested valid claims",
			Expect: http.StatusOK,
			Config: `
					secret: fixed secret
					require:
						aud: test
						roles:
							nested:
								roles: ["other", "test"]
				`,
			Claims: `
					{
						"aud": "test",
						"iss": "https://auth.example.com",
						"roles": {
							"nested": {
								"other": "admin",
								"roles": "test"
							}
						}
					}
				`,
			Method:     jwt.SigningMethodHS256,
			HeaderName: "Authorization",
		},
		{
			Name:   "deeply nested invalid claims",
			Expect: http.StatusForbidden,
			Config: `
					secret: fixed secret
					require:
						aud: test
						roles:
							nested:
								roles: ["admin", "test"]
				`,
			Claims: `
					{
						"aud": "test",
						"iss": "https://auth.example.com",
						"roles": {
							"nested": {
								"other": "admin",
								"roles": "other"
							}
						}
					}
				`,
			Method:     jwt.SigningMethodHS256,
			HeaderName: "Authorization",
		},
		{
			Name:   "and requirement with valid claims",
			Expect: http.StatusOK,
			Config: `
							secret: fixed secret
							require:
								aud: test
								roles:
									"$and": ["admin", "other"]
						`,
			Claims: `
						    {
								"aud": "test",
								"iss": "https://auth.example.com",
								"roles": ["admin", "other"]
							}
					    `,
			Method:     jwt.SigningMethodHS256,
			HeaderName: "Authorization",
		},
		{
			Name:   "and requirement with invalid claims",
			Expect: http.StatusForbidden,
			Config: `
							secret: fixed secret
							require:
								aud: test
								roles:
									"$and": ["admin", "other"]
						`,
			Claims: `
						    {
								"aud": "test",
								"iss": "https://auth.example.com",
								"roles": ["admin"]
							}
					    `,
			Method:     jwt.SigningMethodHS256,
			HeaderName: "Authorization",
		},
		{
			Name:   "complex and/or requirement with valid and claims",
			Expect: http.StatusOK,
			Config: `
							secret: fixed secret
							require:
								aud: test
								roles:
									$or:
										- $and: ["hr", "power"]
										- "admin"
						`,
			Claims: `
						    {
								"aud": "test",
								"iss": "https://auth.example.com",
								"roles": ["hr", "power"]
							}
					    `,
			Method:     jwt.SigningMethodHS256,
			HeaderName: "Authorization",
		},
		{
			Name:   "complex and/or requirement with valid or claim",
			Expect: http.StatusOK,
			Config: `
							secret: fixed secret
							require:
								aud: test
								roles:
									$or:
										- $and: ["hr", "power"]
										- "admin"
						`,
			Claims: `
						    {
								"aud": "test",
								"iss": "https://auth.example.com",
								"roles": ["admin"]
							}
					    `,
			Method:     jwt.SigningMethodHS256,
			HeaderName: "Authorization",
		},
		{
			Name:   "complex and/or requirement with invalid claims",
			Expect: http.StatusForbidden,
			Config: `
							secret: fixed secret
							require:
								aud: test
								roles:
									$or:
										- $and: ["hr", "power"]
										- "admin"
						`,
			Claims: `
						    {
								"aud": "test",
								"iss": "https://auth.example.com",
								"roles": ["hr"]
							}
					    `,
			Method:     jwt.SigningMethodHS256,
			HeaderName: "Authorization",
		},
	}

	for _, test := range tests {
		tester.Run(test.Name, func(tester *testing.T) {
			plugin, request, server, err := setup(&test)
			if err != nil {
				tester.Fatal(err)
			}
			if plugin == nil {
				return
			}
			defer server.Close()

			// Set up response
			response := httptest.NewRecorder()

			// Run the request
			if test.Wait != "" {
				duration, err := time.ParseDuration(test.Wait)
				if err != nil {
					panic(err)
				}
				time.Sleep(duration)
			}
			plugin.ServeHTTP(response, request)

			// Check expectations
			if response.Code != test.Expect {
				tester.Fatalf("incorrect result code: got:%d expected:%d body: %s", response.Code, test.Expect, response.Body.String())
			}

			expectAllow := !expectDisallow(&test)
			if test.Allowed != expectAllow {
				tester.Fatalf("incorrect allowed/denied: was allowed:%t should allow:%t", test.Allowed, expectAllow)
			}

			if test.ExpectRedirect != "" {
				location := html.UnescapeString(response.Header().Get("Location"))
				if test.ExpectRedirect != location {
					tester.Fatalf("Expected redirect of %s but got %s", test.ExpectRedirect, location)
				}
			}

			if test.ExpectHeaders != nil {
				for key, value := range test.ExpectHeaders {
					if request.Header.Get(key) != value {
						tester.Fatalf("Expected header %s=%s in %v", key, value, request.Header)
					}
				}
			}

			if test.ExpectResponseHeaders != nil {
				for key, value := range test.ExpectResponseHeaders {
					if response.Result().Header.Get(key) != value {
						tester.Fatalf("Expected response header %s=%s in %v", key, value, request.Header)
					}
				}
			}

			if test.ExpectCookies != nil {
				for key, value := range test.ExpectCookies {
					if cookie, err := request.Cookie(key); err != nil {
						tester.Fatalf("Expected cookie %s=%s in %v", key, value, request.Cookies())
					} else if cookie.Value != value {
						tester.Fatalf("Expected cookie %s=%s in %v", key, value, request.Cookies())
					}
				}
			}

			if test.ExpectCounts != nil {
				for key, value := range test.ExpectCounts {
					if test.Counts[key] != value {
						tester.Fatalf("Expected count of %d for %s but got %d (%v)", value, key, test.Counts[key], test.Counts)
					}
				}
			}
		})
	}
}

// expectDisallow returns true if the test is expected to disallow the request
func expectDisallow(test *Test) bool {
	// If the test is expected to return a non-200 status code, it should not be allowed
	if test.Expect != http.StatusOK {
		return true
	}

	// GRPC status codes 16 and 7 are unauthenticated and forbidden
	if test.ExpectResponseHeaders != nil {
		status := test.ExpectResponseHeaders["grpc-status"]
		if status == "16" || status == "7" {
			return true
		}
	}

	return false
}

// createConfig creates a configuration from a YAML string using the same method traefik uses
func createConfig(text string) (*Config, error) {
	var config map[string]any
	err := yaml.Unmarshal([]byte(strings.ReplaceAll(text, "\t", "    ")), &config)
	if err != nil {
		return nil, err
	}

	result := CreateConfig()
	if len(config) == 0 {
		return result, nil
	}

	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		DecodeHook:       mapstructure.StringToSliceHookFunc(","),
		WeaklyTypedInput: true,
		Result:           result,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create configuration decoder: %w", err)
	}

	err = decoder.Decode(config)
	if err != nil {
		return nil, fmt.Errorf("failed to decode configuration: %w", err)
	}
	return result, nil
}

func setup(test *Test) (http.Handler, *http.Request, *httptest.Server, error) {
	// Set up test record
	if test.ClaimsMap == nil {
		if test.Claims == "" {
			test.Claims = "{}"
		}
		err := json.Unmarshal([]byte(test.Claims), &test.ClaimsMap)
		if err != nil {
			return nil, nil, nil, err
		}
	}

	// Set up the config
	config, err := createConfig(test.Config)
	if err != nil {
		return nil, nil, nil, err
	}

	context := context.Background()

	// Create the request
	request, err := http.NewRequestWithContext(context, http.MethodGet, "https://app.example.com/home?id=1&other=2", nil)
	if err != nil {
		return nil, nil, nil, err
	}

	// Set cookie in the request
	for key, value := range test.Cookies {
		request.AddCookie(&http.Cookie{Name: key, Value: value})
	}

	// Set headers in the request
	for key, value := range test.Headers {
		request.Header.Add(key, value)
	}

	if test.Actions[useFixedSecret] == yes {
		addTokenToRequest(test, config, request)
	}

	// Set up the environment
	if test.Environment != nil {
		for key, value := range test.Environment {
			os.Setenv(key, value) //nolint:errcheck
		}
		defer func() {
			for key := range test.Environment {
				os.Unsetenv(key) //nolint:errcheck
			}
		}()
	}

	test.Counts = make(map[string]int)

	// Run a test server to provide the key(s)
	var lock sync.Mutex // to synchronize access to the keys
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", func(response http.ResponseWriter, request *http.Request) {
		lock.Lock()
		defer lock.Unlock()
		test.Counts[jwksCalls]++

		if _, ok := test.Actions[keysBadBody]; ok {
			response.Header().Add("Content-Length", "1")
			return
		}
		if status, ok := test.Actions[keysServerStatus]; ok {
			status, err := strconv.Atoi(status)
			if err != nil {
				panic(err)
			}
			response.WriteHeader(status)
			return
		} else {
			response.WriteHeader(http.StatusOK)
		}
		payload, err := json.Marshal(test.Keys)
		if err != nil {
			panic(err)
		}
		if test.Actions != nil {
			payload, err = jsonActions(test.Actions, payload)
			if err != nil {
				panic(err)
			}
		}
		fmt.Fprintln(response, string(payload)) //nolint:errcheck
	})
	mux.HandleFunc("/.well-known/openid-configuration", func(response http.ResponseWriter, request *http.Request) {
		if _, ok := test.Actions[configBadBody]; ok {
			response.Header().Add("Content-Length", "1")
			return
		}
		if status, ok := test.Actions[configServerStatus]; ok {
			status, err := strconv.Atoi(status)
			if err != nil {
				panic(err)
			}
			response.WriteHeader(status)
			return
		} else {
			response.WriteHeader(http.StatusOK)
		}
		var url string
		if _, ok := test.Actions[keysBadURL]; ok {
			url = "https://dummy.example.com"
		} else {
			url = test.URL
		}
		config := OpenIDConfiguration{
			JWKSURI: url + "/.well-known/jwks.json",
		}
		payload, err := json.Marshal(config)
		if err != nil {
			panic(err)
		}
		fmt.Fprintln(response, string(payload)) //nolint:errcheck
	})
	server := httptest.NewServer(mux)
	test.URL = server.URL

	if _, present := test.Actions[noAddIsser]; !present {
		config.Issuers = append(config.Issuers, server.URL)
	}

	if test.ClaimsMap["iss"] == nil && test.Actions[excludeIss] == "" {
		test.ClaimsMap["iss"] = server.URL
	}

	if test.Actions[useFixedSecret] != yes {
		addTokenToRequest(test, config, request)
	}

	// Create the plugin
	next := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) { test.Allowed = true })
	plugin, err := New(context, next, config, "test-jwt-middleware")
	if err != nil {
		if err.Error() == test.ExpectPluginError {
			return nil, nil, nil, nil
		}
		return nil, nil, nil, err
	}

	if _, ok := test.Actions[rotateKey]; ok {
		// Similate a key rotation by ...
		plugin.ServeHTTP(httptest.NewRecorder(), request) // causing the plugin to fetch the existing key
		lock.Lock()
		test.Keys.Keys = nil                     // removing it from the server
		addTokenToRequest(test, config, request) // adding a new key to the server and updating the token
		lock.Unlock()
	}

	return plugin, request, server, nil
}

func addTokenToRequest(test *Test, config *Config, request *http.Request) {
	// Set up request
	if _, ok := test.Actions[traefikURL]; ok {
		request.URL.Host = ""
	}

	// Set the token in the request
	token := createTokenAndSaveKey(test, config)
	if token != "" {
		if test.CookieName != "" {
			request.AddCookie(&http.Cookie{Name: test.CookieName, Value: token})
		} else if test.HeaderName != "" {
			if test.BearerPrefix {
				token = "Bearer " + token
			}
			request.Header[test.HeaderName] = []string{token}
		} else if test.ParameterName != "" {
			query := request.URL.Query()
			query.Set(test.ParameterName, token)
			request.URL.RawQuery = query.Encode()
		}
	}
}

// jsonActions manipulates the JSON keys to test the middleware.
func jsonActions(actions map[string]string, keys []byte) ([]byte, error) {
	var data map[string]any
	err := json.Unmarshal(keys, &data)
	if err != nil {
		return nil, err
	}
	if data["keys"] != nil {
		for _, key := range data["keys"].([]any) {
			key := key.(map[string]any)
			for action, value := range actions {
				if strings.HasPrefix(action, "set:") {
					key[action[4:]] = value
				}
			}
		}
	}
	keys, err = json.Marshal(data)
	if err != nil {
		return nil, err
	}
	if value, ok := actions[invalidJSON]; ok {
		keys = []byte(value)
	}
	return keys, nil
}

// createTokenAndSaveKey creates a token, a key pair as needed, signs the token and saves the key in the test.
func createTokenAndSaveKey(test *Test, config *Config) string {
	method := test.Method
	if method == nil {
		return ""
	}

	// Create a token from the claims
	token := jwt.NewWithClaims(method, test.ClaimsMap)

	// Generate or use a key pair based on the method and test mode
	var private any
	var public any
	var publicPEM string
	switch method {
	case jwt.SigningMethodHS256, jwt.SigningMethodHS384, jwt.SigningMethodHS512:
		// HMAC - use the provided key from the config Secret.
		if config.Secret == "" {
			panic(fmt.Errorf("Secret is required for %s", method.Alg()))
		}
		private = []byte(config.Secret)
	case jwt.SigningMethodRS256, jwt.SigningMethodRS384, jwt.SigningMethodRS512:
		// RSA
		if test.Private == "" {
			// Generate a test RSA key pair
			secret, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				panic(err)
			}
			private = secret
			public = &secret.PublicKey
			publicPEM = string(pem.EncodeToMemory(&pem.Block{
				Type:  "RSA PUBLIC KEY",
				Bytes: x509.MarshalPKCS1PublicKey(&secret.PublicKey),
			}))
		} else {
			// Use the provided private key
			secret, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(trimLines(test.Private)))
			if err != nil {
				panic(err)
			}
			private = secret
		}
	case jwt.SigningMethodES256, jwt.SigningMethodES384, jwt.SigningMethodES512:
		// ECDSA
		if test.Private == "" {
			// Generate a test EC key pair
			var curve elliptic.Curve
			switch method {
			case jwt.SigningMethodES256:
				curve = elliptic.P256()
			case jwt.SigningMethodES384:
				curve = elliptic.P384()
			case jwt.SigningMethodES512:
				curve = elliptic.P521()
			}
			secret, err := ecdsa.GenerateKey(curve, rand.Reader)
			if err != nil {
				panic(err)
			}
			private = secret
			public = &secret.PublicKey
			der, err := x509.MarshalPKIXPublicKey(&secret.PublicKey)
			if err != nil {
				panic(err)
			}
			publicPEM = string(pem.EncodeToMemory(&pem.Block{
				Type:  "PUBLIC KEY",
				Bytes: der,
			}))
		} else {
			// Use the provided private key
			var err error
			switch method {
			case jwt.SigningMethodES256:
				private, err = jwt.ParseECPrivateKeyFromPEM([]byte(trimLines(test.Private)))
			case jwt.SigningMethodRS256:
				private, err = jwt.ParseRSAPrivateKeyFromPEM([]byte(trimLines(test.Private)))
			default:
				panic("Unsupported signing method for test")
			}

			if err != nil {
				panic(err)
			}
		}
	default:
		panic("Unsupported signing method")
	}

	// Choose how to use the public key and/or kid based on the test type
	if test.Actions[useFixedSecret] == yes {
		// Take the generated public key to the fixed Secret
		config.Secret = publicPEM
	} else if public != nil {
		// Add the public key to the key set and set the kid in the token
		jwk, kid := convertKeyToJWKWithKID(public, method.Alg())
		test.Keys.Keys = append(test.Keys.Keys, jwk)
		token.Header["kid"] = kid
	} else if test.Private != "" {
		// Using a provided private key (and coresponding public key in the test config) so just set the kid
		if test.Kid == "" {
			panic("Kid is required for test with Private set")
		}
		token.Header["kid"] = test.Kid
	}

	// Sign with the private key and return the token
	signed, err := token.SignedString(private)
	if err != nil {
		panic(err)
	}
	return signed
}

// convertKeyToJWKWithKID converts a RSA key to a JWK JSON string
func convertKeyToJWKWithKID(key any, algorithm string) (jose.JSONWebKey, string) {
	jwk := jose.JSONWebKey{
		Key:       key,
		Algorithm: algorithm,
		Use:       "sig",
	}
	bytes, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		panic(err)
	}
	jwk.KeyID = base64.RawURLEncoding.EncodeToString(bytes)
	return jwk, jwk.KeyID
}

func TestCanonicalizeDomains(tester *testing.T) {
	tests := []struct {
		Name     string
		domains  []string
		expected []string
	}{
		{
			Name:     "Default",
			domains:  []string{"https://example.com", "example.org/"},
			expected: []string{"https://example.com/", "example.org/"},
		},
	}
	for _, test := range tests {
		tester.Run(test.Name, func(tester *testing.T) {
			result := canonicalizeDomains(test.domains)
			if !reflect.DeepEqual(result, test.expected) {
				tester.Errorf("got: %s expected: %s", result, test.expected)
			}
		})
	}
}

func TestHostname(tester *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"https://example.com", "example.com"},
		{"https://example.com/", "example.com"},
		{"https://test.example.com/", "test.example.com"},
		{"https://example.com:8080", "example.com"},
		{"https://example.com:8080/", "example.com"},
		{"https://example.com:8080/path", "example.com"},
		{"https://example.com:8080/path/", "example.com"},
		{"https://example.com:8080/path?query", "example.com"},
		{"https://example.\x00com", ""},
	}
	for _, test := range tests {
		tester.Run(test.input, func(tester *testing.T) {
			result := hostname(test.input)
			if result != test.expected {
				tester.Errorf("got: %s expected: %s", result, test.expected)
			}
		})
	}
}

func TestCreateDefaultClient(tester *testing.T) {
	pems := []string{
		`\
-----BEGIN CERTIFICATE-----
MIIDJzCCAg+gAwIBAgIUDDYN8pGCpUC6tsqDW4meIXsmN04wDQYJKoZIhvcNAQEL
BQAwIzELMAkGA1UEBhMCVUsxFDASBgNVBAoMC0FnaWxlIFplYnJhMB4XDTI1MDMx
MTE0MTU1MloXDTM1MDMwOTE0MTU1MlowIzELMAkGA1UEBhMCVUsxFDASBgNVBAoM
C0FnaWxlIFplYnJhMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA70Gs
A3QEKB94Eqyt+V07qDNtykhlyOLSiGIRk1/Slr5B1mTY8Mt88gg8MFldyVukjze+
/5GT/lZ3plMMiA7wnpJ683iWqMVOzQTtYlgcMknnrRJhHuDIGmcdakudXl484emE
9iz+cWgl2cw1rb0rtNC1koQ90MohcTqW+5By0TUaulf80ZcJbGFG8LTqVKVJatET
QedgrYR3tIR6VRtj7pnFZ1w9gZhpPL26mrMg3Wk3GHf/j48jebHVYbeuuSoBXJX8
rGmfCtwzMWqyZvMU9MRP6KpPu20UIOuzau6JyD22RhlLSrX/1eI9Et0IMqEF/iM/
EGpTGDJTeX3bJavzAQIDAQABo1MwUTAdBgNVHQ4EFgQUwR3igK8QvKXQ3JuGlYUc
1jHwBqUwHwYDVR0jBBgwFoAUwR3igK8QvKXQ3JuGlYUc1jHwBqUwDwYDVR0TAQH/
BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAoEgu6gQTf8Br0Id7Jp6Oht6XSG0o
RtYJ4SwWD0U1acJpWKgtTkBA9cfGMYngFzUe9Xmxt1iBSCJtbQ/SQj5x0vcXsoR0
zWBnihf3XERnJOyLWR7cUCfVYEu0xFCNrc1m5Wzj4IG2NJBTtiIiAdnTbEcBd7hk
f7Vy+al187qn3HQcwdRfMatjFrrM92tHvd79VJsZcgj8Yl3QcgZFIQ2O+PtrXxLR
2auMwVTxdRe0QUT6zvtZGf1niNH5s8DBVeDWqBArlC7M/HuLj6QOIMDEI2aC3yS1
LT12fZ0MWBjfGc90EEJ9z4/CRUWMdtlOaLnXinyrvOH+SSTJD8xfwKqH6g==
-----END CERTIFICATE-----`,
	}
	tester.Run("Default", func(tester *testing.T) {
		client := NewDefaultClient(nil, true)
		if client == nil {
			tester.Error("client is nil")
		}
		client = NewDefaultClient(pems, true)
		if client == nil {
			tester.Error("client is nil")
		}
		client = NewDefaultClient(pems, false)
		if client == nil {
			tester.Error("client is nil")
		}
	})
}

func BenchmarkServeHTTP(benchmark *testing.B) {
	test := Test{
		Name:   "SigningMethodRS256 passes",
		Expect: http.StatusOK,
		Method: jwt.SigningMethodRS256,
		Config: `
			require:
				aud: test`,
		Claims:     `{"aud": "test"}`,
		HeaderName: "Authorization",
	}

	plugin, request, server, err := setup(&test)
	if err != nil {
		benchmark.Fatal(err)
	}
	if plugin == nil {
		return
	}
	defer server.Close()

	// Set up response
	response := httptest.NewRecorder()

	// Run one the request first to ensure the key is cached (as our test setup deliberately doens't)
	plugin.ServeHTTP(response, request)
	benchmark.ResetTimer()

	for count := 0; count < benchmark.N; count++ {
		// Run the request
		plugin.ServeHTTP(response, request)
	}
}

// trimLines trims leading and trailing spaces from all lines in a string
func trimLines(text string) string {
	lines := strings.Split(text, "\n")
	for index, line := range lines {
		lines[index] = strings.TrimSpace(line)
	}
	return strings.Join(lines, "\n")
}

// The following tests are taken from net/http/header_test.go
// We've added the + character to the token boundaries.
func TestHasToken(tester *testing.T) {
	tests := []struct {
		header string
		token  string
		expect bool
	}{
		{"", "", false},
		{"", "foo", false},
		{"foo", "foo", true},
		{"foo ", "foo", true},
		{" foo", "foo", true},
		{" foo ", "foo", true},
		{"foo,bar", "foo", true},
		{"bar,foo", "foo", true},
		{"bar, foo", "foo", true},
		{"bar,foo, baz", "foo", true},
		{"bar, foo,baz", "foo", true},
		{"bar,foo, baz", "foo", true},
		{"bar, foo, baz", "foo", true},
		{"FOO", "foo", true},
		{"FOO ", "foo", true},
		{" FOO", "foo", true},
		{" FOO ", "foo", true},
		{"FOO,BAR", "foo", true},
		{"BAR,FOO", "foo", true},
		{"BAR, FOO", "foo", true},
		{"BAR,FOO, baz", "foo", true},
		{"BAR, FOO,BAZ", "foo", true},
		{"BAR,FOO, BAZ", "foo", true},
		{"BAR, FOO, BAZ", "foo", true},
		{"foobar", "foo", false},
		{"barfoo ", "foo", false},
		{"foo+bar", "foo", true},
	}

	for _, test := range tests {
		result := hasToken(test.header, test.token)
		if result != test.expect {
			tester.Errorf("hasToken(%q, %q) = %v; expect %v", test.header, test.token, result, test.expect)
		}
	}
}
