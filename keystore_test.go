package jwt_middleware

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/golang-jwt/jwt/v5"
)

// countingServer runs a test server that serves the given JWKS and counts the fetches made to its jwks endpoint.
func countingServer(keys jose.JSONWebKeySet, fetches *atomic.Int64) *httptest.Server {
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	mux.HandleFunc("/.well-known/openid-configuration", func(response http.ResponseWriter, request *http.Request) {
		payload, err := json.Marshal(OpenIDConfiguration{JWKSURI: server.URL + "/.well-known/jwks.json"})
		if err != nil {
			panic(err)
		}
		fmt.Fprintln(response, string(payload)) //nolint:errcheck
	})
	mux.HandleFunc("/.well-known/jwks.json", func(response http.ResponseWriter, request *http.Request) {
		fetches.Add(1)
		payload, err := json.Marshal(keys)
		if err != nil {
			panic(err)
		}
		fmt.Fprintln(response, string(payload)) //nolint:errcheck
	})
	return server
}

// signingKey generates an RSA key pair, returning the private key, a JWKS holding the public key, and its kid.
func signingKey(tester *testing.T) (*rsa.PrivateKey, jose.JSONWebKeySet, string) {
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		tester.Fatal(err)
	}
	jwk, kid := convertKeyToJWKWithKID(&private.PublicKey, "RS256")
	return private, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}}, kid
}

// signToken signs a token with the given private key and kid, bearing the given issuer.
func signToken(tester *testing.T, private *rsa.PrivateKey, kid string, issuer string) string {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"iss": issuer})
	token.Header["kid"] = kid
	signed, err := token.SignedString(private)
	if err != nil {
		tester.Fatal(err)
	}
	return signed
}

// buildPlugin creates a plugin instance the way traefik does on every dynamic configuration change.
func buildPlugin(tester *testing.T, configText string) http.Handler {
	config, err := createConfig(configText)
	if err != nil {
		tester.Fatal(err)
	}
	next := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {})
	plugin, err := New(context.Background(), next, config, "test-jwt-middleware")
	if err != nil {
		tester.Fatal(err)
	}
	return plugin
}

// sendRequest sends a request with the given token through the plugin and returns the response status code.
func sendRequest(tester *testing.T, plugin http.Handler, token string) int {
	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://app.example.com/home", nil)
	if err != nil {
		tester.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	plugin.ServeHTTP(response, request)
	return response.Code
}

// TestKeyCacheSurvivesRebuild verifies that keys fetched on demand by one plugin instance are
// still cached when the instance is replaced: traefik re-instantiates middleware plugins on
// every dynamic configuration change and the replacement must not re-fetch from the issuer.
func TestKeyCacheSurvivesRebuild(tester *testing.T) {
	private, keys, kid := signingKey(tester)
	var fetches atomic.Int64
	server := countingServer(keys, &fetches)
	defer server.Close()
	token := signToken(tester, private, kid, server.URL)

	configText := fmt.Sprintf(`
		issuers:
			- %s
		skipPrefetch: true`, server.URL)

	plugin := buildPlugin(tester, configText)
	if code := sendRequest(tester, plugin, token); code != http.StatusOK {
		tester.Fatalf("first instance: expected %d, got %d", http.StatusOK, code)
	}
	if count := fetches.Load(); count != 1 {
		tester.Fatalf("expected 1 fetch after the first instance, got %d", count)
	}

	rebuilt := buildPlugin(tester, configText)
	if code := sendRequest(tester, rebuilt, token); code != http.StatusOK {
		tester.Fatalf("rebuilt instance: expected %d, got %d", http.StatusOK, code)
	}
	if count := fetches.Load(); count != 1 {
		tester.Fatalf("keys were re-fetched on middleware rebuild: %d fetches", count)
	}
}

// TestPrefetchSkipsWarmStores verifies that the prefetch performed on plugin creation is
// skipped when an earlier instance has already fetched the issuer's keys, so that constant
// middleware rebuilds do not translate into constant fetches from the issuer.
func TestPrefetchSkipsWarmStores(tester *testing.T) {
	_, keys, _ := signingKey(tester)
	var fetches atomic.Int64
	server := countingServer(keys, &fetches)
	defer server.Close()

	configText := fmt.Sprintf(`
		issuers:
			- %s`, server.URL)

	buildPlugin(tester, configText)
	deadline := time.Now().Add(5 * time.Second)
	for fetches.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if count := fetches.Load(); count != 1 {
		tester.Fatalf("expected 1 prefetch from the first instance, got %d", count)
	}
	time.Sleep(200 * time.Millisecond) // allow the fetched keys to reach the store before rebuilding

	for range 4 {
		buildPlugin(tester, configText)
	}
	time.Sleep(300 * time.Millisecond) // allow any (erroneous) prefetches from the rebuilds to happen
	if count := fetches.Load(); count != 1 {
		tester.Fatalf("prefetch re-fetched keys on middleware rebuild: %d fetches", count)
	}
}
