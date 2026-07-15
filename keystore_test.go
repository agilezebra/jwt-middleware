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

// TestRefreshSurvivesRebuilds verifies that background key refresh runs once per issuer store
// no matter how many times traefik rebuilds the middleware: without this, every rebuild
// leaks an immortal refresh goroutine and the fetch rate against the issuer grows without bound.
func TestRefreshSurvivesRebuilds(tester *testing.T) {
	_, keys, _ := signingKey(tester)
	var fetches atomic.Int64
	server := countingServer(keys, &fetches)
	defer server.Close()

	configText := fmt.Sprintf(`
		issuers:
			- %s
		skipPrefetch: true
		refreshKeysInterval: 50ms`, server.URL)

	for range 5 {
		buildPlugin(tester, configText)
	}
	time.Sleep(500 * time.Millisecond)
	if count := fetches.Load(); count > 15 {
		tester.Fatalf("fetch rate implies duplicated refresh loops: %d fetches in 500ms at a 50ms interval", count)
	}
}

// storeFor returns the existing shared store for the given issuer without registering with it.
func storeFor(tester *testing.T, issuer string) *Store {
	keystore.lock.RLock()
	defer keystore.lock.RUnlock()
	store, ok := keystore.stores[canonicalizeDomain(issuer)]
	if !ok {
		tester.Fatalf("no store for issuer %s", issuer)
	}
	return store
}

// refreshing returns whether the store is being arbitrarily refreshed
// (refreshing is scheduled while the store's interval is nonzero).
func refreshing(store *Store) bool {
	store.lock.RLock()
	defer store.lock.RUnlock()
	return store.interval > 0
}

// due returns when the store's next arbitrary refresh is due.
func due(store *Store) time.Time {
	store.lock.RLock()
	defer store.lock.RUnlock()
	return store.deadline
}

// TestShortestRefreshIntervalWins verifies that a store shared by middlewares with different
// refreshKeysInterval values adopts the shortest, including when the shorter interval arrives
// while a refresh is already scheduled at a longer cadence.
func TestShortestRefreshIntervalWins(tester *testing.T) {
	_, keys, _ := signingKey(tester)
	var fetches atomic.Int64
	server := countingServer(keys, &fetches)
	defer server.Close()

	// The long cadence is 1s: it must never fire within the observation window below,
	// but be short enough for this test to outlive its superseded sleeper (see below)
	buildPlugin(tester, fmt.Sprintf(`
		issuers:
			- %s
		skipPrefetch: true
		refreshKeysInterval: 1s`, server.URL))
	buildPlugin(tester, fmt.Sprintf(`
		issuers:
			- %s
		skipPrefetch: true
		refreshKeysInterval: 50ms`, server.URL))

	time.Sleep(500 * time.Millisecond)
	if count := fetches.Load(); count < 3 {
		tester.Fatalf("later registrant's shorter interval did not take effect: %d fetches in 500ms at a 50ms interval", count)
	}

	// Outlive the long cadence's superseded sleeper, which wakes at its original deadline (~1s)
	// and must exit without fetching or re-arming; doing so here (rather than relying on later
	// tests to keep the process alive) guarantees it however the suite is composed or filtered
	time.Sleep(700 * time.Millisecond)

	// Had the superseded sleeper wrongly re-armed, it would have spawned a second chain alongside
	// the original, and the fetch rate would now be roughly double the 50ms cadence
	count := fetches.Load()
	time.Sleep(500 * time.Millisecond)
	if delta := fetches.Load() - count; delta > 15 {
		tester.Fatalf("fetch rate implies the superseded sleeper spawned a second chain: %d fetches in 500ms at a 50ms interval", delta)
	}
}

// TestRefreshRetiresAndResurrects verifies that a store's scheduled refresh retires once the
// middleware set has been rebuilt without it (its issuer has left the dynamic configuration) and
// resumes when a later configuration references the issuer again.
func TestRefreshRetiresAndResurrects(tester *testing.T) {
	_, keys, _ := signingKey(tester)
	var fetches atomic.Int64
	server := countingServer(keys, &fetches)
	defer server.Close()

	_, otherKeys, _ := signingKey(tester)
	var otherFetches atomic.Int64
	other := countingServer(otherKeys, &otherFetches)
	defer other.Close()

	configText := fmt.Sprintf(`
		issuers:
			- %s
		skipPrefetch: true
		refreshKeysInterval: 50ms`, server.URL)
	buildPlugin(tester, configText)

	// Simulate "the middleware set was rebuilt without me": age the store's own registration
	// beyond the grace, then register a different issuer to advance the keystore's registration
	store := storeFor(tester, server.URL)
	store.lock.Lock()
	store.registered = time.Now().Add(-2 * retirementGrace)
	store.lock.Unlock()
	buildPlugin(tester, fmt.Sprintf(`
		issuers:
			- %s
		skipPrefetch: true`, other.URL))

	deadline := time.Now().Add(5 * time.Second)
	for refreshing(store) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if refreshing(store) {
		tester.Fatal("refresh did not retire after the middleware set was rebuilt without its store")
	}
	count := fetches.Load()
	time.Sleep(300 * time.Millisecond)
	if grown := fetches.Load(); grown != count {
		tester.Fatalf("fetches continued after retirement: %d -> %d", count, grown)
	}

	// A rebuild that references the issuer again resurrects the loop
	buildPlugin(tester, configText)
	deadline = time.Now().Add(5 * time.Second)
	for fetches.Load() == count && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if fetches.Load() == count {
		tester.Fatal("refresh did not resume after the issuer was registered again")
	}
}

// TestQuietClusterNeverRetires verifies that retirement is driven by rebuilds, not by time:
// with no registrations happening anywhere, a store keeps refreshing indefinitely,
// however long ago the store was last registered.
func TestQuietClusterNeverRetires(tester *testing.T) {
	_, keys, _ := signingKey(tester)
	var fetches atomic.Int64
	server := countingServer(keys, &fetches)
	defer server.Close()

	buildPlugin(tester, fmt.Sprintf(`
		issuers:
			- %s
		skipPrefetch: true
		refreshKeysInterval: 50ms`, server.URL))

	// Move both registration timestamps equally far into the past: on a quiet cluster the two
	// stay equal however much time passes, and equal timestamps must never trigger retirement
	store := storeFor(tester, server.URL)
	past := time.Now().Add(-10 * retirementGrace)
	store.lock.Lock()
	store.registered = past
	store.lock.Unlock()
	keystore.lock.Lock()
	keystore.registered = past
	keystore.lock.Unlock()

	count := fetches.Load()
	time.Sleep(500 * time.Millisecond)
	if !refreshing(store) {
		tester.Fatal("refresh retired on a quiet cluster")
	}
	if fetches.Load() <= count {
		tester.Fatal("refresh stopped fetching on a quiet cluster")
	}
}

// TestFetchPostponesScheduledRefresh verifies that any fetch restarts the full refresh interval:
// refreshing means "fetch if not fetched within the interval", not a fixed metronome, so when the
// scheduled refresh comes due after an intervening fetch it re-arms for the remainder rather than
// fetching again.
func TestFetchPostponesScheduledRefresh(tester *testing.T) {
	_, keys, _ := signingKey(tester)
	var fetches atomic.Int64
	server := countingServer(keys, &fetches)
	defer server.Close()

	buildPlugin(tester, fmt.Sprintf(`
		issuers:
			- %s
		skipPrefetch: true
		refreshKeysInterval: 500ms`, server.URL))

	store := storeFor(tester, server.URL)
	before := due(store)
	time.Sleep(400 * time.Millisecond)
	if err := store.fetch(); err != nil {
		tester.Fatal(err)
	}

	// When the original deadline expires, the scheduled refresh re-arms rather than fetches
	deadline := time.Now().Add(5 * time.Second)
	for !due(store).After(before) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !due(store).After(before) {
		tester.Fatal("the scheduled refresh was not postponed by the fetch")
	}
	if count := fetches.Load(); count != 1 {
		tester.Fatalf("the scheduled refresh fetched despite the intervening fetch: %d fetches", count)
	}

	// And refreshing continues from the postponed deadline
	for fetches.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if count := fetches.Load(); count < 2 {
		tester.Fatalf("scheduled refreshing did not continue after being postponed: %d fetches", count)
	}
}

// TestRefreshWaitsForPrefetchDelay verifies that a configured prefetch delay is honored even when
// refreshKeysInterval is shorter: the delay exists to give an issuer behind the same traefik time
// to come up, so no background fetch of any kind may hit it earlier, and the prefetch (not a
// refresh tick) must be the first fetch.
func TestRefreshWaitsForPrefetchDelay(tester *testing.T) {
	_, keys, _ := signingKey(tester)
	var fetches atomic.Int64
	server := countingServer(keys, &fetches)
	defer server.Close()

	buildPlugin(tester, fmt.Sprintf(`
		issuers:
			- %s
		delayPrefetch: 300ms
		refreshKeysInterval: 50ms`, server.URL))

	time.Sleep(150 * time.Millisecond)
	if count := fetches.Load(); count != 0 {
		tester.Fatalf("issuer was fetched %d times before the prefetch delay", count)
	}
	deadline := time.Now().Add(5 * time.Second)
	for fetches.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if fetches.Load() == 0 {
		tester.Fatal("prefetch never happened after the delay")
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
