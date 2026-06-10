// Ligolo-ng
// Copyright (C) 2025 Nicolas Chatelain (nicocha30)

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

// Command ng-mcp is a Model Context Protocol (MCP) server that exposes
// ligolo-ng pivoting operations as tools, so an AI agent (Claude Desktop,
// Claude Code, or any MCP client) can discover agents and drive tunnels,
// routes, and reverse listeners on its own.
//
// It is a thin stdio bridge to the proxy's web API (pkg/webui): start the proxy
// with -web-listen and -web-token, then run ng-mcp pointed at that address. The
// API token can be passed with -token or the LIGOLO_WEB_TOKEN environment
// variable (preferred, to keep it out of the process list).
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
)

func main() {
	apiURL := flag.String("url", "http://127.0.0.1:8080", "ng-proxy web API base URL (matches the proxy's -web-listen)")
	token := flag.String("token", "", "ng-proxy web API token (-web-token); falls back to $LIGOLO_WEB_TOKEN")
	flag.Parse()

	tok := *token
	if tok == "" {
		tok = os.Getenv("LIGOLO_WEB_TOKEN")
	}
	if tok == "" {
		fmt.Fprintln(os.Stderr, "ng-mcp: API token required (-token or $LIGOLO_WEB_TOKEN)")
		os.Exit(2)
	}

	srv := newServer(newRESTClient(*apiURL, tok))
	if err := srv.run(context.Background(), os.Stdin, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "ng-mcp: %v\n", err)
		os.Exit(1)
	}
}
