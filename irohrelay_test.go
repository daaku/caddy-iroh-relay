package irohrelay

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/coder/websocket"
	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/netaddr"
	"github.com/tmc/go-iroh/relay"
)

const (
	testALPN = "caddy-iroh-relay/test"

	// relayProtocol is a WebSocket subprotocol of the relay protocol.
	relayProtocol = "iroh-relay-v2"
)

func TestCaddyfile(t *testing.T) {
	adapter := caddyconfig.GetAdapter("caddyfile")
	out, _, err := adapter.Adapt([]byte(`iroh-relay.example.com {
	respond 404
	iroh_relay {
		shared_token a b
		shared_token {env.C}
	}
}
`), nil)
	if err != nil {
		t.Fatalf("adapt: %v", err)
	}
	if strings.Index(string(out), `"handler":"iroh_relay"`) > strings.Index(string(out), `"handler":"static_response"`) {
		t.Errorf("iroh_relay is ordered after respond in %s", out)
	}
	if want := `"shared_token":["a","b","{env.C}"]`; !strings.Contains(string(out), want) {
		t.Errorf("adapted config %s does not contain %s", out, want)
	}
}

func TestProvision(t *testing.T) {
	t.Setenv("TOKEN", "from-env")
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	h := Handler{SharedToken: []string{"{env.TOKEN}"}}
	if err := h.Provision(ctx); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, relayPath, nil)
	r.Header.Set("Authorization", "Bearer from-env")
	if !h.allowed(r) {
		t.Error("token from the environment is not allowed")
	}

	for _, tokens := range [][]string{{""}, {"a", ""}, {"{env.IROH_RELAY_TEST_UNSET}"}} {
		h := Handler{SharedToken: tokens}
		if err := h.Provision(ctx); err == nil {
			t.Errorf("provisioned with tokens %q", tokens)
		}
	}
}

func TestAllowed(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()
	open := Handler{}
	if err := open.Provision(ctx); err != nil {
		t.Fatal(err)
	}
	if !open.allowed(httptest.NewRequest(http.MethodGet, relayPath, nil)) {
		t.Error("a relay without tokens must allow everyone")
	}

	h := Handler{SharedToken: []string{"token-a", "token-b"}}
	if err := h.Provision(ctx); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		target  string
		headers []string
		want    bool
	}{
		{name: "no token", target: relayPath},
		{name: "first token", target: relayPath, headers: []string{"Bearer token-a"}, want: true},
		{name: "second token", target: relayPath, headers: []string{"Bearer token-b"}, want: true},
		{name: "scheme is case insensitive", target: relayPath, headers: []string{"bEaReR token-a"}, want: true},
		{name: "unknown token", target: relayPath, headers: []string{"Bearer token-c"}},
		{name: "prefix of a token", target: relayPath, headers: []string{"Bearer token"}},
		{name: "empty bearer", target: relayPath, headers: []string{"Bearer "}},
		{name: "wrong scheme", target: relayPath, headers: []string{"Basic token-a"}},
		{name: "query", target: relayPath + "?token=token-b", want: true},
		{name: "unknown query", target: relayPath + "?token=token-c"},
		{name: "empty query", target: relayPath + "?token="},
		{name: "other scheme falls back to query", target: relayPath + "?token=token-a", headers: []string{"Basic x"}, want: true},
		{name: "second header", target: relayPath, headers: []string{"Basic x", "Bearer token-a"}, want: true},
		{name: "bearer wins over query", target: relayPath + "?token=token-a", headers: []string{"Bearer nope"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, tt.target, nil)
			for _, v := range tt.headers {
				r.Header.Add("Authorization", v)
			}
			if got := h.allowed(r); got != tt.want {
				t.Errorf("allowed = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestCaddy runs the relay in Caddy over TLS, with clients that have no way to
// reach each other but the relay.
func TestCaddy(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	certPEM, keyPEM := testCert()
	certFile := filepath.Join(t.TempDir(), "cert.pem")
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	// Relay clients verify the server against the system roots.
	t.Setenv("SSL_CERT_FILE", certFile)

	addr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	load := func(tokens ...string) {
		t.Helper()
		cfg, err := json.Marshal(caddyConfig(addr, certPEM, keyPEM, tokens))
		if err != nil {
			t.Fatal(err)
		}
		if err := caddy.Load(cfg, true); err != nil {
			t.Fatal(err)
		}
	}
	load("kept", "revoked")
	t.Cleanup(func() { caddy.Stop() })

	url := "https://" + addr
	relayURL, err := netaddr.ParseRelayURL(url)
	if err != nil {
		t.Fatal(err)
	}
	httpClient := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{NextProtos: []string{"http/1.1"}, RootCAs: certPool(t, certPEM)},
	}}
	t.Cleanup(httpClient.CloseIdleConnections)

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	for _, tt := range []struct {
		path string
		want int
	}{
		{probePath, http.StatusOK},
		{relayPath, http.StatusUnauthorized},
		{"/", http.StatusNoContent},
	} {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url+tt.path, nil)
		resp, err := httpClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != tt.want {
			t.Errorf("GET %s = %d, want %d", tt.path, resp.StatusCode, tt.want)
		}
	}

	bind := func(token string, alpns ...string) *iroh.Endpoint {
		t.Helper()
		m := relay.NewMap(relay.NewConfig(relayURL, nil).WithAuthToken(token))
		ep, err := iroh.Bind(ctx, iroh.WithRelayMode(relay.ModeCustom(m)), iroh.WithALPNs(alpns...),
			iroh.WithoutIPTransports(), iroh.WithoutNetReport())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ep.Shutdown(context.Background()) })
		return ep
	}
	online := func(ep *iroh.Endpoint, d time.Duration) error {
		ctx, cancel := context.WithTimeout(ctx, d)
		defer cancel()
		return ep.Online(ctx)
	}

	server := bind("kept", testALPN)
	if err := online(server, 15*time.Second); err != nil {
		t.Fatalf("server online: %v", err)
	}
	go echo(ctx, server)
	check := func(client *iroh.Endpoint) error {
		ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		conn, err := client.Connect(ctx, netaddr.NewEndpointAddr(server.ID()).WithRelayURL(relayURL), testALPN)
		if err != nil {
			return fmt.Errorf("connect: %w", err)
		}
		defer conn.CloseWithError(0, "")
		s, err := conn.OpenStreamSync(ctx)
		if err != nil {
			return fmt.Errorf("open: %w", err)
		}
		const msg = "over the relay"
		if _, err := s.Write([]byte(msg)); err != nil {
			return fmt.Errorf("write: %w", err)
		}
		s.Close()
		got, err := io.ReadAll(s)
		if err != nil {
			return fmt.Errorf("read: %w", err)
		}
		if string(got) != msg {
			return fmt.Errorf("echo = %q, want %q", got, msg)
		}
		return nil
	}

	client := bind("revoked")
	if err := online(client, 15*time.Second); err != nil {
		t.Fatalf("client online: %v", err)
	}
	if err := check(client); err != nil {
		t.Fatalf("relay between clients: %v", err)
	}

	if err := online(bind("wrong"), 2*time.Second); err == nil {
		t.Error("client with an unknown token got online")
	}

	// A session of the old config is ended by a reload.
	dialCtx, dialCancel := context.WithTimeout(ctx, 10*time.Second)
	defer dialCancel()
	session, _, err := websocket.Dial(dialCtx, url+relayPath+"?token=revoked", &websocket.DialOptions{
		HTTPClient:   httpClient,
		Subprotocols: []string{relayProtocol},
	})
	if err != nil {
		t.Fatalf("websocket: %v", err)
	}
	defer session.CloseNow()
	if _, _, err := session.Read(dialCtx); err != nil {
		t.Fatalf("read challenge: %v", err)
	}

	load("kept")

	if _, _, err := session.Read(dialCtx); err == nil || dialCtx.Err() != nil {
		t.Errorf("session survived the reload: %v (context: %v)", err, dialCtx.Err())
	}

	// Clients of the old config move to the new one on their own, or a client
	// that is new to the relay couldn't reach them.
	deadline := time.Now().Add(30 * time.Second)
	late := bind("kept")
	if err := online(late, 15*time.Second); err != nil {
		t.Fatalf("client online after reload: %v", err)
	}
	for {
		err := check(late)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("relay after reload: %v", err)
		}
	}

	if err := online(bind("revoked"), 2*time.Second); err == nil {
		t.Error("client with a revoked token got online")
	}
}

func echo(ctx context.Context, ep *iroh.Endpoint) {
	for {
		conn, err := ep.Accept(ctx)
		if err != nil {
			return
		}
		go func() {
			s, err := conn.AcceptStream(ctx)
			if err != nil {
				return
			}
			b, _ := io.ReadAll(s)
			s.Write(b)
			s.Close()
			<-conn.Context().Done()
		}()
	}
}

func caddyConfig(addr string, certPEM, keyPEM []byte, tokens []string) map[string]any {
	return map[string]any{
		"admin": map[string]any{"disabled": true, "config": map[string]any{"persist": false}},
		"apps": map[string]any{
			"tls": map[string]any{"certificates": map[string]any{"load_pem": []any{map[string]any{
				"certificate": string(certPEM),
				"key":         string(keyPEM),
			}}}},
			"http": map[string]any{"servers": map[string]any{"relay": map[string]any{
				"listen":                  []string{addr},
				"protocols":               []string{"h1", "h2"},
				"automatic_https":         map[string]any{"disable": true},
				"tls_connection_policies": []any{map[string]any{}},
				"routes": []any{map[string]any{"handle": []any{
					map[string]any{"handler": "iroh_relay", "shared_token": tokens},
					map[string]any{"handler": "static_response", "status_code": 204},
				}}},
			}}},
		},
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func certPool(t *testing.T, certPEM []byte) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certPEM) {
		t.Fatal("bad certificate")
	}
	return pool
}

// testCert returns a self-signed certificate for 127.0.0.1 and its key. It is
// the same one for the whole process, which reads SSL_CERT_FILE only once.
var testCert = sync.OnceValues(func() (certPEM, keyPEM []byte) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		panic(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		panic(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
})
