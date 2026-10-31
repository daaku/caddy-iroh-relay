// Package irohrelay is a Caddy HTTP handler that serves an iroh relay, with
// optional access control by shared tokens.
package irohrelay

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/daaku/caddydecl"
	"github.com/tmc/go-iroh/relayserver"
)

func init() {
	caddy.RegisterModule(&Handler{})
	httpcaddyfile.RegisterHandlerDirective("iroh_relay", parseCaddyfile)
	httpcaddyfile.RegisterDirectiveOrder("iroh_relay", httpcaddyfile.Before, "respond")
}

const (
	relayPath = "/relay"
	probePath = "/ping"
)

// Handler serves the iroh relay protocol at /relay and latency probes at
// /ping. Anything else is passed to the next handler.
//
// A relay is not shared between configs: reloading Caddy disconnects its
// clients, which reconnect to the new config's relay.
type Handler struct {
	// SharedToken lists the tokens that allow connecting to the relay. A
	// client sends one in an "Authorization: Bearer" header or a "token" URL
	// query parameter, like with access.shared_token in iroh-relay. Latency
	// probes are always allowed, since clients send no token with them.
	//
	// Global placeholders such as {env.RELAY_TOKEN} are expanded. Without
	// tokens the relay is open to everyone.
	SharedToken []string `json:"shared_token,omitempty"`

	tokens [][sha256.Size]byte
	relay  *relayserver.Server
	ctx    context.Context
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m Handler
	err := caddydecl.Unmarshal(&m, h.Dispenser)
	return &m, err
}

// CaddyModule returns the Caddy module information.
func (*Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.iroh_relay",
		New: func() caddy.Module { return new(Handler) },
	}
}

// Provision implements [caddy.Provisioner].
func (h *Handler) Provision(ctx caddy.Context) error {
	repl := caddy.NewReplacer()
	for _, token := range h.SharedToken {
		token = repl.ReplaceAll(token, "")
		if token == "" {
			return errors.New("iroh_relay: shared_token must not be empty")
		}
		h.tokens = append(h.tokens, sha256.Sum256([]byte(token)))
	}
	h.relay = relayserver.NewWithOptions(relayserver.WithClientRate(0))
	h.ctx = ctx
	return nil
}

// ServeHTTP implements [caddyhttp.MiddlewareHandler].
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	switch r.URL.Path {
	case relayPath:
		if !h.allowed(r) {
			w.WriteHeader(http.StatusUnauthorized)
			return nil
		}
		// A session is a hijacked connection, which outlives the old config
		// on a reload. End it with the config: it would otherwise stay on a
		// relay that clients of the new config can't reach, and keep access
		// that the new config may have revoked.
		ctx, cancel := context.WithCancel(r.Context())
		defer cancel()
		defer context.AfterFunc(h.ctx, cancel)()
		h.relay.ServeHTTP(w, r.WithContext(ctx))
		return nil
	case probePath:
		h.relay.ServeHTTP(w, r)
		return nil
	}
	return next.ServeHTTP(w, r)
}

// allowed reports whether r may connect, comparing the token it presents
// against every configured token in constant time.
func (h *Handler) allowed(r *http.Request) bool {
	if len(h.tokens) == 0 {
		return true
	}
	token, ok := requestToken(r)
	if !ok {
		return false
	}
	sum := sha256.Sum256([]byte(token))
	allowed := 0
	for _, t := range h.tokens {
		allowed |= subtle.ConstantTimeCompare(sum[:], t[:])
	}
	return allowed == 1
}

// requestToken returns the value of the first Authorization header with the
// Bearer scheme, or else the token query parameter.
func requestToken(r *http.Request) (string, bool) {
	for _, value := range r.Header.Values("Authorization") {
		if scheme, token, ok := strings.Cut(value, " "); ok && strings.EqualFold(scheme, "Bearer") {
			return token, true
		}
	}
	values, ok := r.URL.Query()["token"]
	if !ok {
		return "", false
	}
	return values[0], true
}

var (
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
)
