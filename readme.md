# caddy-iroh-relay

A [Caddy](https://caddyserver.com/) HTTP handler that serves an
[iroh](https://github.com/n0-computer/iroh) relay, built on
[go-iroh's relayserver](https://github.com/tmc/go-iroh/tree/main/relayserver).
Caddy provides the listener and certificates. Clients are not rate limited.

## Build

```sh
xcaddy build --with github.com/daaku/caddy-iroh-relay
```

or `go build ./cmd/caddy` in this repository.

## Configuration

```
iroh-relay.example.com {
	iroh_relay {
		shared_token {env.IROH_RELAY_TOKEN_ALICE} {env.IROH_RELAY_TOKEN_BOB}
	}
}
```

- `shared_token` lists the tokens that may connect. It takes several tokens and
  may be repeated. An expanded token must not be empty, so an unset variable
  fails at startup rather than opening the relay. Without `shared_token`, the
  relay is open to everyone.

The relay is served at `/relay` and `/ping`. Other paths go to the next handler,
so a site can serve something else next to the relay.

Reloading Caddy with a changed config disconnects all clients, which reconnect
on their own. That is also how a revoked token takes effect on live sessions.

## Tokens

As with `access.shared_token` in
[iroh-relay](https://github.com/n0-computer/iroh/tree/main/iroh-relay), a client
sends its token in an `Authorization: Bearer` header, which is what
`RelayConfig::with_auth_token` does, or in a `?token=` query parameter. `/ping`
needs no token, because clients don't send one with their latency probes.

Prefer the header. A token in the query shows up in Caddy's access logs, and a
token in a relay URL is public, as below.

## iroh-ssh

[iroh-ssh](https://github.com/rustonbsd/iroh-ssh) has no option for a relay
token, so there are two ways to use it:

**With a token**, using the patch in `contrib`, against iroh-ssh `82e9971`. It
reads the token from `IROH_RELAY_TOKEN` and sends it to the relays named with
`--relay-url` or `--extra-relay-url`:

```sh
git apply contrib/iroh-ssh-relay-token.patch   # in a checkout of iroh-ssh

IROH_RELAY_TOKEN=... iroh-ssh server --relay-url https://iroh-relay.example.com/
IROH_RELAY_TOKEN=... iroh-ssh user@ENDPOINT_ID --relay-url https://iroh-relay.example.com/
```

**Without a token**, unmodified, on a relay with no `shared_token`.

Don't put the token in the URL (`--relay-url 'https://…/?token=…'`). With
iroh 1.3 that looks like it works when peers connect directly, but:

- iroh publishes the home relay URL, so the token ends up in public DNS
  (`dns.iroh.link`) and the mainline DHT;
- the published record is cut at the second `=`, so peers look for
  `…/?token`, are refused, and can't connect through the relay;
- iroh-ssh pastes the URL unquoted into `ProxyCommand`, and zsh fails on the
  `?` with `no matches found`;
- iroh 1.4 and later drop the query when building the `/relay` URL.

## Limits

- There is no QUIC address discovery, which go-iroh's relayserver doesn't
  provide. Clients that only know this relay can't learn their public address
  from it, so expect fewer direct connections and more traffic through the
  relay. Adding it with `--extra-relay-url` keeps n0's relays available.
- Tokens are the only access control; there is no allowlist of endpoint ids.
