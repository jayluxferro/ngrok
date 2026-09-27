package server

import (
	"encoding/gob"
	"errors"
	"fmt"
	"net"
	"ngrok/cache"
	"ngrok/log"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	cacheSaveInterval time.Duration = 10 * time.Minute

	// The binding values ReqTunnel.Binding may carry live in package msg with
	// the rest of the wire vocabulary: msg.BindingPublic is the zero value, so
	// a client which predates the field keeps behaving exactly as before.

	// defaultOwner is the single namespace every client shares when the server
	// runs without -authToken (SPEC 3.1, documented limitation).
	defaultOwner = "default"

	// maxForwardDepth caps how many forward_to hops a single public connection
	// may take before we refuse it (SPEC 3.3).
	maxForwardDepth = 8
)

// Forward chain resolution failures. Each one is turned into an explicit 502
// at the public edge (SPEC 3.3); the wrapped detail is what the client reads
// in the response body and what we log.
var (
	errForwardTargetMissing = errors.New("forward target offline")
	errForwardCycle         = errors.New("forward loop detected")
	errForwardDepth         = errors.New("forward chain too deep")
)

type cacheUrl string

func (url cacheUrl) Size() int {
	return len(url)
}

// bucket holds every tunnel registered at one url. A non-pooling url has
// exactly one member; a pooling url has as many as there are agents that
// registered it, and Get() hands connections out round-robin (SPEC 3.2).
type bucket struct {
	tunnels []*Tunnel
	next    uint32

	// owner is the account of the bucket's first member, and the account every
	// later member must share to join it. It is a security boundary, not
	// bookkeeping: the members of a bucket serve each other's public traffic --
	// Get() round-robins over all of them without consulting the owner of the
	// connection's Host -- so a bucket that accepted a member from another
	// account would hand that account's agent, and the requests that carry its
	// customers' credentials, another account's traffic.
	owner string
}

// pooling reports whether this bucket accepts more members: only a bucket
// whose members registered with Pooling may be shared.
func (b *bucket) pooling() bool {
	return len(b.tunnels) > 0 && b.tunnels[0].req.Pooling
}

// get returns the next member of the bucket in round-robin order.
//
// The caller must hold at least the registry read lock: atomic.AddUint32
// keeps the cursor consistent between concurrent readers, but the slice
// itself is only stable while the lock is held.
func (b *bucket) get() *Tunnel {
	n := uint32(len(b.tunnels))
	if n == 0 {
		return nil
	}
	return b.tunnels[(atomic.AddUint32(&b.next, 1)-1)%n]
}

// internalKey namespaces an internal endpoint by its owner (SPEC 3.2). Public
// lookups use the bare url, so they can never see an entry stored under this
// key: that is what makes .internal hosts unreachable from the public
// listener, 404 exactly as an unknown host would be.
func internalKey(url, owner string) string {
	return url + "\x00" + owner
}

// registryKey is the key a tunnel is stored under.
func registryKey(url string, t *Tunnel) string {
	if t.internal() {
		return internalKey(url, t.owner)
	}
	return url
}

// canonicalForwardURL normalizes a forward_to target so that chain
// bookkeeping and internal key lookup agree on spelling differences that
// would otherwise let a loop escape detection: case, surrounding whitespace,
// and one trailing slash.
func canonicalForwardURL(url string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(url)), "/")
}

// TunnelRegistry maps a tunnel URL to Tunnel structures
type TunnelRegistry struct {
	tunnels  map[string]*bucket
	affinity *cache.LRUCache
	log.Logger
	sync.RWMutex
}

func NewTunnelRegistry(cacheSize uint64, cacheFile string) *TunnelRegistry {
	registry := &TunnelRegistry{
		tunnels:  make(map[string]*bucket),
		affinity: cache.NewLRUCache(cacheSize),
		Logger:   log.NewPrefixLogger("registry", "tun"),
	}

	// LRUCache uses Gob encoding. Unfortunately, Gob is fickle and will fail
	// to encode or decode any non-primitive types that haven't been "registered"
	// with it. Since we store cacheUrl objects, we need to register them here first
	// for the encoding/decoding to work
	var urlobj cacheUrl
	gob.Register(urlobj)

	// try to load and then periodically save the affinity cache to file, if specified
	if cacheFile != "" {
		err := registry.affinity.LoadItemsFromFile(cacheFile)
		if err != nil {
			registry.Error("Failed to load affinity cache %s: %v", cacheFile, err)
		}

		registry.SaveCacheThread(cacheFile, cacheSaveInterval)
	} else {
		registry.Info("No affinity cache specified")
	}

	return registry
}

// Spawns a goroutine the periodically saves the cache to a file.
func (r *TunnelRegistry) SaveCacheThread(path string, interval time.Duration) {
	go func() {
		r.Info("Saving affinity cache to %s every %s", path, interval.String())
		for {
			time.Sleep(interval)

			r.Debug("Saving affinity cache")
			err := r.affinity.SaveItemsToFile(path)
			if err != nil {
				r.Error("Failed to save affinity cache: %v", err)
			} else {
				r.Info("Saved affinity cache")
			}
		}
	}()
}

// Register a tunnel with a specific url, returns an error
// if a tunnel is already registered at that url
//
// v2 (SPEC 3.2): the owner and the pooling flag are read from the tunnel
// itself (t.owner, t.req.Pooling) rather than passed as extra parameters, so
// the signature stays compatible with every existing caller. That is the
// equivalent of the spec's Register(url, owner, t, pooling) with a smaller
// surface: there is exactly one way to say who owns a tunnel and whether it
// pools.
//
// Conflict rules: a registration conflicts with an existing bucket unless both
// the existing members and the newcomer are pooling, and unless the newcomer
// belongs to the same account as the bucket. Every pooling path -- the vhost
// one and the TCP one -- arrives here, so this is the single place where a
// cross-account join can be refused.
func (r *TunnelRegistry) Register(url string, t *Tunnel) error {
	r.Lock()
	defer r.Unlock()

	key := registryKey(url, t)

	if b := r.tunnels[key]; b != nil {
		if !b.pooling() {
			return fmt.Errorf("The tunnel %s is already registered.", url)
		}
		// Pooling shares the url, and with it every connection the bucket is
		// handed: whoever joins serves traffic that was addressed to somebody
		// else's endpoint. Only the account that owns the bucket may join it,
		// and a refusal says so without saying anything about the other
		// account beyond the fact that this url is taken.
		if b.owner != t.owner {
			return fmt.Errorf("The tunnel %s is already registered by a different account; pooling only joins a pool owned by the same account.", url)
		}
		if !t.req.Pooling {
			return fmt.Errorf("The tunnel %s is already shared by pooling tunnels; enable pooling to join it.", url)
		}
		b.tunnels = append(b.tunnels, t)
		return nil
	}

	r.tunnels[key] = &bucket{
		tunnels: []*Tunnel{t},
		owner:   t.owner,
	}

	return nil
}

func (r *TunnelRegistry) cacheKeys(t *Tunnel) (ip string, id string) {
	clientIp := t.ctl.conn.RemoteAddr().(*net.TCPAddr).IP.String()
	clientId := t.ctl.id

	ipKey := fmt.Sprintf("client-ip-%s:%s", t.req.Protocol, clientIp)
	idKey := fmt.Sprintf("client-id-%s:%s", t.req.Protocol, clientId)
	return ipKey, idKey
}

func (r *TunnelRegistry) GetCachedRegistration(t *Tunnel) (url string) {
	ipCacheKey, idCacheKey := r.cacheKeys(t)

	// check cache for ID first, because we prefer that over IP which might
	// not be specific to a user because of NATs
	if v, ok := r.affinity.Get(idCacheKey); ok {
		url = string(v.(cacheUrl))
		t.Debug("Found registry affinity %s for %s", url, idCacheKey)
	} else if v, ok := r.affinity.Get(ipCacheKey); ok {
		url = string(v.(cacheUrl))
		t.Debug("Found registry affinity %s for %s", url, ipCacheKey)
	}
	return
}

func (r *TunnelRegistry) RegisterAndCache(url string, t *Tunnel) (err error) {
	if err = r.Register(url, t); err == nil {
		// we successfully assigned a url, cache it
		ipCacheKey, idCacheKey := r.cacheKeys(t)
		r.affinity.Set(ipCacheKey, cacheUrl(url))
		r.affinity.Set(idCacheKey, cacheUrl(url))
	}
	return

}

// Register a tunnel with the following process:
// Consult the affinity cache to try to assign a previously used tunnel url if possible
// Generate new urls repeatedly with the urlFn and register until one is available.
func (r *TunnelRegistry) RegisterRepeat(urlFn func() string, t *Tunnel) (string, error) {
	url := r.GetCachedRegistration(t)
	if url == "" {
		url = urlFn()
	}

	maxAttempts := 5
	for i := 0; i < maxAttempts; i++ {
		if err := r.RegisterAndCache(url, t); err != nil {
			// pick a new url and try again
			url = urlFn()
		} else {
			// we successfully assigned a url, we're done
			return url, nil
		}
	}

	return "", fmt.Errorf("Failed to assign a URL after %d attempts!", maxAttempts)
}

// Del removes every tunnel registered at a public url, pooling members
// included. Tunnel shutdown removes only itself through Remove; this is the
// blunt instrument used for teardown and tests.
func (r *TunnelRegistry) Del(url string) {
	r.Lock()
	defer r.Unlock()
	delete(r.tunnels, url)
}

// DelBucket removes the whole bucket at url and returns the tunnels it held,
// in registration order. It is what a listener-owning tunnel's shutdown needs:
// the members of a TCP pool share a listener they did not bind, so when the
// creator goes the shared endpoint is gone for all of them, and a bucket key
// left behind would keep pointing at a url nothing listens on -- and would even
// report itself as pooling, inviting new members into a pool with no listener.
func (r *TunnelRegistry) DelBucket(url string) []*Tunnel {
	r.Lock()
	defer r.Unlock()

	b := r.tunnels[url]
	if b == nil {
		return nil
	}
	delete(r.tunnels, url)

	// the caller shuts the members down, so it gets its own slice: it must not
	// be holding a view into the bucket while doing so.
	return append([]*Tunnel(nil), b.tunnels...)
}

// Remove drops a single tunnel from the bucket it was registered in and
// deletes the bucket once the last member is gone (SPEC 3.2). Removing a
// tunnel that is no longer registered is a no-op.
func (r *TunnelRegistry) Remove(url string, t *Tunnel) {
	r.Lock()
	defer r.Unlock()

	key := registryKey(url, t)
	b := r.tunnels[key]
	if b == nil {
		return
	}

	for i, member := range b.tunnels {
		if member == t {
			b.tunnels = append(b.tunnels[:i], b.tunnels[i+1:]...)
			break
		}
	}

	if len(b.tunnels) == 0 {
		delete(r.tunnels, key)
	}
}

// Get returns the tunnel registered for a public url, round-robining across
// the members of a pooling bucket. The lookup is the bare url, exactly as
// before pooling existed, and the owner is deliberately not part of the
// public key: that is what keeps internal endpoints unreachable from here
// (SPEC 3.2).
func (r *TunnelRegistry) Get(url string) *Tunnel {
	r.RLock()
	defer r.RUnlock()

	b := r.tunnels[url]
	if b == nil {
		return nil
	}
	return b.get()
}

// GetInternal returns the internal endpoint registered at url by owner, or
// nil. Internal endpoints are keyed by owner, so a different account asking
// for the same url gets the same answer as for a url that was never
// registered (SPEC 3.1/3.2).
func (r *TunnelRegistry) GetInternal(url, owner string) *Tunnel {
	r.RLock()
	defer r.RUnlock()

	b := r.tunnels[internalKey(canonicalForwardURL(url), owner)]
	if b == nil {
		return nil
	}
	return b.get()
}

// IsPooling reports whether url is currently a pooling bucket, i.e. whether
// another tunnel may join it instead of binding a second listener (SPEC 3.2).
func (r *TunnelRegistry) IsPooling(url string) bool {
	r.RLock()
	defer r.RUnlock()

	b := r.tunnels[url]
	return b != nil && b.pooling()
}

// ResolveForward walks the forward_to chain that starts at t and returns the
// tunnel that should actually serve the connection (SPEC 3.3).
//
// Every hop is resolved with t's owner, so same-account forwarding only: an
// internal endpoint owned by somebody else is indistinguishable from one that
// does not exist. A chain that loops or runs longer than maxForwardDepth hops
// is refused rather than followed. t itself comes back when it does not
// forward, which is the common case and allocates nothing.
func (r *TunnelRegistry) ResolveForward(t *Tunnel) (*Tunnel, error) {
	owner := t.owner
	target := canonicalForwardURL(t.forwardTo())
	if target == "" {
		return t, nil
	}

	visited := make(map[string]bool)
	for hop := 0; ; hop++ {
		if hop >= maxForwardDepth {
			return nil, fmt.Errorf("%w: more than %d hops from %s", errForwardDepth, maxForwardDepth, t.url)
		}
		if visited[target] {
			return nil, fmt.Errorf("%w: %s", errForwardCycle, target)
		}
		visited[target] = true

		next := r.GetInternal(target, owner)
		if next == nil {
			return nil, fmt.Errorf("%w: %s", errForwardTargetMissing, target)
		}

		target = canonicalForwardURL(next.forwardTo())
		if target == "" {
			return next, nil
		}
	}
}

// ControlRegistry maps a client ID to Control structures
type ControlRegistry struct {
	controls map[string]*Control
	log.Logger
	sync.RWMutex
}

func NewControlRegistry() *ControlRegistry {
	return &ControlRegistry{
		controls: make(map[string]*Control),
		Logger:   log.NewPrefixLogger("registry", "ctl"),
	}
}

func (r *ControlRegistry) Get(clientId string) *Control {
	r.RLock()
	defer r.RUnlock()
	return r.controls[clientId]
}

func (r *ControlRegistry) Add(clientId string, ctl *Control) (oldCtl *Control) {
	r.Lock()
	defer r.Unlock()

	oldCtl = r.controls[clientId]
	if oldCtl != nil {
		oldCtl.Replaced(ctl)
	}

	r.controls[clientId] = ctl
	r.Info("Registered control with id %s", clientId)
	return
}

// Del removes the control registered under clientId, but only if it is still
// ctl. A control that was replaced (the client reconnected before the old
// connection noticed) must not evict its replacement on its way out, and
// comparing pointers is how that is decided now: the check is under the same
// lock as the delete, so no window exists in which the replacement can slip in
// between the two.
//
// This replaces the old "clear c.id in Replaced so that Del(”) finds
// nothing" trick, which worked by mutating a field that the registry, the
// metrics and the logs all read concurrently (see Control.Replaced).
func (r *ControlRegistry) Del(clientId string, ctl *Control) error {
	r.Lock()
	defer r.Unlock()

	current := r.controls[clientId]
	if current == nil {
		return fmt.Errorf("No control found for client id: %s", clientId)
	}
	if current != ctl {
		// Not an error worth shouting about: the normal outcome of a reconnect
		// race, where the old control's stopper runs after the new control was
		// registered.
		r.Debug("Control %s was replaced; not removing the replacement", clientId)
		return nil
	}

	r.Info("Removed control registry id %s", clientId)
	delete(r.controls, clientId)
	return nil
}
