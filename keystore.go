package jwt_middleware

import (
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/agilezebra/jwt-middleware/logger"
)

// retirementGrace is how much more recent the keystore's last registration may be than a store's own
// before the store's scheduled refresh concludes the middleware set was rebuilt without it and retires.
// It need only comfortably exceed the duration of a single dynamic configuration apply.
const retirementGrace = time.Minute

// Store is a process-wide cache of the keys fetched for a single issuer, along with the
// configuration needed to fetch them.
type Store struct {
	issuer        string                  // The issuer whose keys the store holds
	endpoint      string                  // A hard-coded JWKS endpoint, or empty for OpenID Connect discovery
	clients       map[string]*http.Client // A map of clients for specific hosts that skip certificate verification
	defaultClient *http.Client            // A default client for fetching keys with certificate verification
	lock          sync.RWMutex            // Read-write lock for keys, populated, interval, registered, attempted, and deadline
	keys          map[string]any          // A map of key IDs to public keys
	populated     bool                    // Whether the store has completed at least one successful fetch
	interval      time.Duration           // The shortest refresh interval any registrant has requested, or zero when refreshing is retired or unwanted
	registered    time.Time               // When a plugin last registered this store
	attempted     time.Time               // When the issuer was last fetched (successfully or not); initially the store's creation
	deadline      time.Time               // When the next arbitrary refresh is due, or zero when none is scheduled
}

// KeyStore resolves issuers to their shared key Stores.
type KeyStore struct {
	lock       sync.RWMutex
	stores     map[string]*Store
	registered time.Time // When any store was last registered
}

// keystore is the process-wide singleton through which all key fetching and caching happens.
// traefik re-instantiates middleware plugins on every dynamic configuration change and offers
// them no way to carry state across rebuilds other than the package scope, so this is the
// an unavoidable global that lets keys survive the rebuilds.
var keystore = &KeyStore{stores: make(map[string]*Store)}

// store returns the Store for the given issuer, creating it if absent, and registers the caller with it.
// The first caller to reference an issuer defines how its keys are fetched (endpoint and clients);
// later callers share the store as-is.
// Every call counts as a registration: the timestamps recorded here are what keep a store's
// scheduled refresh alive across traefik's middleware rebuilds (see expire); refreshing itself is
// arranged separately (see schedule).
func (keystore *KeyStore) store(issuer string, endpoint string, clients map[string]*http.Client, defaultClient *http.Client) *Store {
	keystore.lock.Lock()
	store, ok := keystore.stores[issuer]
	if !ok {
		store = &Store{
			issuer:        issuer,
			endpoint:      endpoint,
			clients:       clients,
			defaultClient: defaultClient,
			keys:          make(map[string]any),
			attempted:     time.Now(),
		}
		keystore.stores[issuer] = store
	}
	keystore.registered = time.Now()
	keystore.lock.Unlock()

	store.lock.Lock()
	store.registered = time.Now()
	store.lock.Unlock()

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
// The attempt is recorded whether it succeeds or not, so that the scheduled arbitrary refresh can wait a full
// interval from the most recent contact with the issuer, whatever triggered it (see schedule and expire).
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
		store.lock.Lock()
		store.attempted = time.Now()
		store.lock.Unlock()
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
		if _, ok := store.keys[kid]; !ok {
			logger.Log("INFO", "fetched key:%s from url:%s", kid, url)
		}
	}
	store.keys = keys
	store.populated = true
	store.attempted = time.Now()

	return nil
}

// adopt takes on the given interval as the store's refresh cadence if it is nonzero and shorter
// than the current cadence: most-demanding-wins, because the keys are identical for all sharers,
// so refreshing at the fastest requested cadence is safe and benefits everyone.
// The caller must hold store.lock.
func (store *Store) adopt(interval time.Duration) {
	if interval > 0 && (store.interval == 0 || interval < store.interval) {
		store.interval = interval
	}
}

// schedule registers the caller's refresh cadence and ensures that, if any registrant wants
// refreshing at all, an arbitrary refresh is scheduled for one interval after the last fetch
// attempt (a fresh store's creation counts): a sooner-scheduled refresh stands, a later one is
// pulled in (and its sleeper superseded). A refresh is pending exactly while the store's deadline
// is nonzero, so scheduling a first cadence starts refreshing and a call after retirement restarts it.
func (store *Store) schedule(interval time.Duration) {
	store.lock.Lock()
	defer store.lock.Unlock()
	store.adopt(interval)
	if store.interval == 0 {
		return
	}
	deadline := store.attempted.Add(store.interval)
	if store.deadline.IsZero() || deadline.Before(store.deadline) {
		store.deadline = deadline
		go store.expire(deadline)
	}
}

// expire performs the arbitrary refresh scheduled for the given deadline and schedules its own
// successor: each goroutine sleeps once and exits, so no refresh machinery can outlive its own
// deadline. A refresh superseded by a shorter cadence exits in favor of the sooner sleeper, and
// one that finds a fetch happened while it slept re-arms for the remainder instead of fetching:
// refreshing means "fetch if not fetched, for any reason, within the interval" (not a metronome).
// The refresh retires (zeroing the store's cadence and scheduling nothing) when the middleware set
// has been rebuilt without the store: every dynamic configuration apply re-registers every live
// store, so a store whose own registration is significantly older than the keystore's latest is
// no longer part of the configuration. A retired store keeps serving its cached keys and resumes
// refreshing if it is registered again (by a later configuration, or by a request for a
// wildcard-matched issuer). On a quiet cluster nothing registers again, the two timestamps stay
// equal, and refreshing continues forever (as it is a warm-cache guarantee and does not depend on traffic).
func (store *Store) expire(deadline time.Time) {
	time.Sleep(time.Until(deadline))

	// keystore.key takes the keystore's lock and then each store's, so we must not hold the
	// store's lock while taking the keystore's: read the keystore's timestamp separately first
	keystore.lock.RLock()
	latest := keystore.registered
	keystore.lock.RUnlock()

	store.lock.Lock()
	if !store.deadline.Equal(deadline) {
		store.lock.Unlock()
		return // superseded while we slept
	}
	if due := store.attempted.Add(store.interval); due.After(deadline) {
		// A fetch while we slept restarted the interval: re-arm for the remainder
		store.deadline = due
		go store.expire(due)
		store.lock.Unlock()
		return
	}
	if latest.Sub(store.registered) > retirementGrace {
		store.interval = 0
		store.deadline = time.Time{}
		store.lock.Unlock()
		return
	}
	store.lock.Unlock()

	err := store.fetch()
	if err != nil {
		log.Printf("failed to fetch keys for %s: %v", store.issuer, err)
	}

	store.lock.Lock()
	deadline = store.attempted.Add(store.interval) // the fetch we just made, successful or not
	store.deadline = deadline
	go store.expire(deadline)
	store.lock.Unlock()
}
