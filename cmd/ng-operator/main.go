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

// Command ng-operator is the multi-operator client for the refactored Ligolo
// server. It connects to the operator hub over mutual TLS using a config bundle
// produced by ng-proxy (-operator-config) and issues commands.
//
// Usage:
//
//	ng-operator -connect host:port -config DIR <command> [args]
//
// Commands:
//
//	list                                  list connected agents
//	watch                                 stream agent lifecycle events
//	listener <agentID> <net> <bind> <to>  open a reverse listener
//	stop-listener <agentID> <id>          close a reverse listener
//	kill <agentID>                        terminate an agent
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"text/tabwriter"

	"github.com/nicocha30/ligolo-ng/pkg/operator"
)

func main() {
	connect := flag.String("connect", "127.0.0.1:11602", "operator hub address (host:port)")
	configDir := flag.String("config", "ligolo-operator", "operator config bundle directory")
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: ng-operator [flags] <list|watch|listener|stop-listener|kill> ...")
		os.Exit(2)
	}

	tlsConfig, err := operator.LoadClientTLS(*configDir)
	if err != nil {
		fatal("load operator config from %s: %v", *configDir, err)
	}

	switch args[0] {
	case "watch":
		runWatch(*connect, tlsConfig)
		return
	}

	cli, err := operator.Dial(*connect, tlsConfig)
	if err != nil {
		fatal("connect to hub: %v", err)
	}
	defer cli.Close()

	switch args[0] {
	case "list":
		runList(cli)
	case "listener":
		if len(args) != 5 {
			fatal("usage: listener <agentID> <tcp|udp> <bindAddr> <toAddr>")
		}
		id, err := cli.AddListener(args[1], args[2], args[3], args[4])
		if err != nil {
			fatal("add listener: %v", err)
		}
		fmt.Printf("listener #%d created\n", id)
	case "stop-listener":
		if len(args) != 3 {
			fatal("usage: stop-listener <agentID> <listenerID>")
		}
		id, err := strconv.Atoi(args[2])
		if err != nil {
			fatal("invalid listener id: %v", err)
		}
		if err := cli.StopListener(args[1], int32(id)); err != nil {
			fatal("stop listener: %v", err)
		}
		fmt.Println("listener stopped")
	case "kill":
		if len(args) != 2 {
			fatal("usage: kill <agentID>")
		}
		if err := cli.KillAgent(args[1]); err != nil {
			fatal("kill agent: %v", err)
		}
		fmt.Println("kill request sent")
	default:
		fatal("unknown command %q", args[0])
	}
}

func runList(cli *operator.Client) {
	agents, err := cli.ListAgents()
	if err != nil {
		fatal("list agents: %v", err)
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tNAME\tONLINE\tCAPS\tLISTENERS")
	for _, a := range agents {
		fmt.Fprintf(w, "%s\t%s\t%t\t%#x\t%d\n", a.ID, a.Name, a.Online, a.Caps, len(a.Listeners))
	}
	w.Flush()
}

func runWatch(addr string, tlsConfig *tls.Config) {
	events, stop, err := operator.Subscribe(addr, tlsConfig)
	if err != nil {
		fatal("subscribe: %v", err)
	}
	defer stop()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	fmt.Println("watching agent events (Ctrl-C to stop)...")
	for {
		select {
		case <-sig:
			return
		case ev, ok := <-events:
			if !ok {
				return
			}
			fmt.Printf("[%s] %s (%s) online=%t\n", ev.Kind, ev.Agent.Name, ev.Agent.ID, ev.Agent.Online)
		}
	}
}

func fatal(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
