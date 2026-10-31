// Command caddy is Caddy with its standard modules and the iroh_relay handler.
package main

import (
	caddycmd "github.com/caddyserver/caddy/v2/cmd"
	_ "github.com/caddyserver/caddy/v2/modules/standard"
	_ "github.com/daaku/caddy-iroh-relay"
)

func main() {
	caddycmd.Main()
}
