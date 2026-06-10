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

package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/nicocha30/ligolo-ng/pkg/ngconfig"
	"github.com/nicocha30/ligolo-ng/pkg/node"
	"github.com/nicocha30/ligolo-ng/pkg/session"
)

// runConsole is a minimal interactive operator console for the v2 stack. It
// drives node.Server and the gVisor tunnel directly, giving the same core UX as
// the legacy CLI (select an agent, route it through the TUN, manage reverse
// listeners) without the v1 yamux-bound code.
func runConsole(srv *node.Server, tun *tunnelManager, cfg *ngconfig.Config) {
	c := &console{srv: srv, tun: tun, cfg: cfg, listeners: map[int32]*node.ReverseListener{}}
	fmt.Println("ligolo-ng v2 console. type 'help' for commands.")
	sc := bufio.NewScanner(os.Stdin)
	c.prompt()
	for sc.Scan() {
		c.dispatch(strings.Fields(strings.TrimSpace(sc.Text())))
		c.prompt()
	}
}

type console struct {
	srv       *node.Server
	tun       *tunnelManager
	cfg       *ngconfig.Config
	selected  *session.Session
	listeners map[int32]*node.ReverseListener
}

func (c *console) prompt() {
	name := "*"
	if c.selected != nil {
		name = c.selected.Name
	}
	fmt.Printf("ligolo[%s] » ", name)
}

func (c *console) dispatch(args []string) {
	if len(args) == 0 {
		return
	}
	switch args[0] {
	case "help", "?":
		c.help()
	case "agents", "list":
		c.list()
	case "use":
		c.use(args)
	case "start":
		c.start(args)
	case "stop":
		c.stop()
	case "tunnels":
		c.showTunnels()
	case "listener":
		c.addListener(args)
	case "listeners":
		c.showListeners()
	case "stop-listener":
		c.stopListener(args)
	case "kill":
		c.kill(args)
	case "autobind":
		c.autobind()
	case "exit", "quit":
		os.Exit(0)
	default:
		fmt.Printf("unknown command %q (try 'help')\n", args[0])
	}
}

func (c *console) help() {
	fmt.Println(`commands:
  agents                          list connected agents
  use <id-prefix>                 select an agent
  start [ifname]                  route the selected agent through its own TUN
  stop                            stop routing the selected agent
  tunnels                         list active tunnels
  listener <tcp|udp> <bind> <to>  open a reverse listener on the selected agent
  listeners                       list reverse listeners
  stop-listener <id>              close a reverse listener
  kill <id-prefix>                terminate an agent
  autobind                        persist the selected agent's tunnel + listeners to config
  exit                            quit`)
}

// autobind saves the selected agent's current tunnel and reverse listeners to
// the config keyed by the agent's static key, so a daemon restores them when
// the agent reconnects.
func (c *console) autobind() {
	if c.cfg == nil {
		fmt.Println("no -config in use; start ng-proxy with -config to enable autobind")
		return
	}
	if c.selected == nil {
		fmt.Println("select an agent first (use <id>)")
		return
	}
	ifName := c.tun.ifNameFor(c.selected.ID)
	rule := ngconfig.Autobind{Interface: ifName, Route: ifName != ""}
	for _, l := range c.selected.Listeners() {
		rule.Listeners = append(rule.Listeners, ngconfig.ListenerRule{Network: l.Network, Bind: l.Address, To: l.To})
	}
	if err := c.cfg.SetAutobind(c.selected.PeerKeyHex, rule); err != nil {
		fmt.Printf("save autobind failed: %v\n", err)
		return
	}
	fmt.Printf("autobind saved for %s (key %s…)\n", c.selected.Name, c.selected.PeerKeyHex[:16])
}

func (c *console) list() {
	agents := c.srv.Registry.List()
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tNAME\tONLINE\tTUN")
	for _, a := range agents {
		ifName := c.tun.ifNameFor(a.ID)
		if ifName == "" {
			ifName = "-"
		}
		fmt.Fprintf(w, "%s\t%s\t%t\t%s\n", a.ID, a.Name, a.Online(), ifName)
	}
	w.Flush()
}

func (c *console) resolve(prefix string) *session.Session {
	for _, a := range c.srv.Registry.List() {
		if strings.HasPrefix(a.ID, prefix) {
			return a
		}
	}
	return nil
}

func (c *console) use(args []string) {
	if len(args) != 2 {
		fmt.Println("usage: use <id-prefix>")
		return
	}
	s := c.resolve(args[1])
	if s == nil {
		fmt.Println("no such agent")
		return
	}
	c.selected = s
	fmt.Printf("selected %s (%s)\n", s.Name, s.ID)
}

func (c *console) start(args []string) {
	if c.selected == nil {
		fmt.Println("select an agent first (use <id>)")
		return
	}
	ifName := ""
	if len(args) >= 2 {
		ifName = args[1]
	}
	name, err := c.tun.start(c.selected, ifName)
	if err != nil {
		fmt.Printf("start tunnel failed: %v\n", err)
		return
	}
	fmt.Printf("routing %s through %s\n", c.selected.Name, name)
	fmt.Printf("assign it: sudo ip addr add 240.0.0.1/4 dev %s && sudo ip link set %s up\n", name, name)
}

func (c *console) stop() {
	if c.selected == nil {
		fmt.Println("select an agent first (use <id>)")
		return
	}
	if c.tun.stop(c.selected.ID) {
		fmt.Println("tunnel stopped")
	} else {
		fmt.Println("no tunnel for the selected agent")
	}
}

func (c *console) showTunnels() {
	tunnels := c.tun.list()
	if len(tunnels) == 0 {
		fmt.Println("no active tunnels")
		return
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "IFACE\tAGENT\tID")
	for _, at := range tunnels {
		fmt.Fprintf(w, "%s\t%s\t%s\n", at.ifName, at.sess.Name, at.sess.ID)
	}
	w.Flush()
}

func (c *console) addListener(args []string) {
	if c.selected == nil {
		fmt.Println("select an agent first (use <id>)")
		return
	}
	if len(args) != 4 {
		fmt.Println("usage: listener <tcp|udp> <bindAddr> <toAddr>")
		return
	}
	rl, err := c.srv.AddListener(context.Background(), c.selected, args[1], args[2], args[3])
	if err != nil {
		fmt.Printf("add listener failed: %v\n", err)
		return
	}
	c.listeners[rl.ID] = rl
	fmt.Printf("listener #%d created\n", rl.ID)
}

func (c *console) showListeners() {
	if c.selected == nil {
		fmt.Println("select an agent first (use <id>)")
		return
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tNET\tBIND\tTO")
	for _, l := range c.selected.Listeners() {
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\n", l.ID, l.Network, l.Address, l.To)
	}
	w.Flush()
}

func (c *console) stopListener(args []string) {
	if len(args) != 2 {
		fmt.Println("usage: stop-listener <id>")
		return
	}
	id, err := strconv.Atoi(args[1])
	if err != nil {
		fmt.Println("invalid id")
		return
	}
	rl := c.listeners[int32(id)]
	if rl == nil {
		fmt.Println("unknown listener")
		return
	}
	if err := rl.Stop(context.Background()); err != nil {
		fmt.Printf("stop failed: %v\n", err)
		return
	}
	delete(c.listeners, int32(id))
	fmt.Println("listener stopped")
}

func (c *console) kill(args []string) {
	if len(args) != 2 {
		fmt.Println("usage: kill <id-prefix>")
		return
	}
	s := c.resolve(args[1])
	if s == nil {
		fmt.Println("no such agent")
		return
	}
	if err := c.srv.KillAgent(context.Background(), s); err != nil {
		fmt.Printf("kill failed: %v\n", err)
		return
	}
	fmt.Println("kill request sent")
}
