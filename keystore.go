package jwt_middleware

import (
	"net/http"
	"sync"

	"github.com/agilezebra/jwt-middleware/logger"
)

// Store is a process-wide cache of the keys fetched for a single issuer, along with the
// configuration needed to fetch them.
type Store struct {
	issuer        string                  // The issuer whose keys the store holds
	endpoint      string                  // A hard-coded JWKS endpoint, or empty for OpenID Connect discovery
	clients       map[string]*http.Client // A map of clients for specific hosts that skip certificate verification
	defaultClient *http.Client            // A default client for fetching keys with certificate verification
	lock          sync.RWMutex            // Read-write lock for keys and populated
	keys          map[string]any          // A map of key IDs to public keys
	populated     bool                    // Whether the store has completed at least one successful fetch
}

// KeyStore resolves issuers to their shared key Stores.
type KeyStore struct {
	lock   sync.RWMutex
	stores map[string]*Store
}

// keystore is the process-wide singleton through which all key fetching and caching happens.
// traefik re-instantiates middleware plugins on every dynamic configuration change and offers
// them no way to carry state across rebuilds other than the package scope, so this is the
// an unavoidable global that lets keys survive the rebuilds.
var keystore = &KeyStore{stores: make(map[string]*Store)}

// store returns the Store for the given issuer, creating it if absent.
// The first caller to reference an issuer defines how its keys are fetched (endpoint and clients);
// later callers share the store as-is.
func (keystore *KeyStore) store(issuer string, endpoint string, clients map[string]*http.Client, defaultClient *http.Client) *Store {
	keystore.lock.RLock()
	store, ok := keystore.stores[issuer]
	keystore.lock.RUnlock()
	if ok {
		return store
	}

	keystore.lock.Lock()
	defer keystore.lock.Unlock()
	store, ok = keystore.stores[issuer]
	if !ok {
		store = &Store{
			issuer:        issuer,
			endpoint:      endpoint,
			clients:       clients,
			defaultClient: defaultClient,
			keys:          make(map[string]any),
		}
		keystore.stores[issuer] = store
	}
	return store
}

// key returns the cached key for the given key ID from any store whose issuer the caller trusts, or nil.
// Tokens are not required to carry an iss claim: a key already fetched from any trusted issuer matches by kid alone.
func (keystore *KeyStore) key(kid string, trusted func(issuer string) bool) any {
	keystore.lock.RLock()
	defer keystore.lock.RUnlock()
	for issuer, store := range keystore.stores {
		if trusted(issuer) {
			if key := store.key(kid); key != nil {
				return key
			}
		}
	}
	return nil
}

// key returns the cached key for the given key ID, or nil if not present.
func (store *Store) key(kid string) any {
	store.lock.RLock()
	defer store.lock.RUnlock()
	return store.keys[kid]
}

// warm returns true if the store already holds the result of a successful fetch.
func (store *Store) warm() bool {
	store.lock.RLock()
	defer store.lock.RUnlock()
	return store.populated
}

// clientFor returns the http.Client for the given URL, or the store's default client if no specific client is configured.
func (store *Store) clientFor(address string) *http.Client {
	client, ok := store.clients[hostname(address)]
	if ok {
		return client
	}
	return store.defaultClient
}

// fetch fetches the issuer's keys from its hard-coded or discovered JWKS endpoint and replaces the store's cached keys.
// There is a design choice here: we fetch from the issuer before acquiring the write lock, as we don't want to block
// readers that can immediately use the available keys, given the store is shared by all middlewares in the process.
// The cost is that concurrent misses for the same issuer may fetch more than once; this is a tradeoff between the
// extra requests (more so to the issuer's server) and the cost to other requests of holding the lock across a fetch.
func (store *Store) fetch() error {
	url := store.endpoint
	if url == "" {
		configURL := store.issuer + ".well-known/openid-configuration" // issuer has trailing slash
		config, err := FetchOpenIDConfiguration(configURL, store.clientFor(configURL))

		if err != nil {
			// Fall back to direct JWKS URL if OpenID configuration fetch fails
			url = store.issuer + ".well-known/jwks.json"
			logger.Log("WARN", "failed to fetch openid-configuration from url:%s; falling back to direct JWKS URL:%s", configURL, url)
		} else {
			logger.Log("INFO", "fetched openid-configuration from url:%s", configURL)
			url = config.JWKSURI
		}
	}

	keys, err := FetchJWKS(url, store.clientFor(url))
	if err != nil {
		return err
	}

	store.lock.Lock()
	defer store.lock.Unlock()

	for kid := range store.keys {
		if _, ok := keys[kid]; !ok {
			logger.Log("INFO", "key:%s dropped", kid)
		}
	}
	for kid := range keys {
		logger.Log("INFO", "fetched key:%s from url:%s", kid, url)
	}
	store.keys = keys
	store.populated = true

	return nil
}
