# caddy-iroh-relay

A Caddy HTTP handler (`http.handlers.iroh_relay`) that serves an iroh relay with
go-iroh's `relayserver`, plus shared token auth.

## Layout

- `irohrelay.go`: the whole module. Directive parsing goes through
  `github.com/daaku/caddydecl` over the exported fields of `Handler`.
- `irohrelay_test.go`: unit tests, and `TestCaddy`, which runs the handler in
  Caddy over TLS with go-iroh endpoints that have no IP transports, so traffic
  can only take the relay.
- `cmd/caddy`: Caddy with the standard modules and this one.
- `contrib`: a patch that gives iroh-ssh a relay token. See the readme.

## Invariants

- Only `/relay` needs a token. Rust clients send none with `/ping`, and don't
  select a relay as home without a 200 from it.
- Sessions end with the config, through `h.ctx`. They are hijacked connections,
  which `http.Server.Shutdown` leaves alone, and a relay is per config. Without
  this, a reload strands old clients on a relay new clients can't reach, and
  revoked tokens keep working. `TestCaddy` covers both.
- Refusing a token writes the status directly instead of returning
  `caddyhttp.Error`, which would log the URI, and with it a `?token=`.
- Token parsing follows `ClientRequest::auth_token` in iroh-relay: the first
  Bearer header, and the query only if there is none.

## Checklist

- `go vet ./...`, `go test -race ./...`
- Standard library first; be very wary of new dependencies.
- One source file and one test file.
