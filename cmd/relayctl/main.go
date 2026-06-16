// Ligolo-ng
// Copyright (C) 2025 Nicolas Chatelain (nicocha30)

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type client struct {
	baseURL    string
	username   string
	password   string
	token      string
	httpClient *http.Client
}

func main() {
	apiURL := envDefault("LIGOLO_API", "http://127.0.0.1:8080")
	username := envDefault("LIGOLO_USER", "")
	password := envDefault("LIGOLO_PASSWORD", "")
	token := envDefault("LIGOLO_TOKEN", "")

	global := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	global.StringVar(&apiURL, "api", apiURL, "Ligolo API base URL")
	global.StringVar(&username, "user", username, "API username")
	global.StringVar(&password, "password", password, "API password")
	global.StringVar(&token, "token", token, "API bearer token")
	global.Usage = usage
	if err := global.Parse(os.Args[1:]); err != nil {
		fatal(err)
	}
	if global.NArg() == 0 {
		usage()
		os.Exit(2)
	}

	c := &client{
		baseURL:  strings.TrimRight(apiURL, "/"),
		username: username,
		password: password,
		token:    token,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}

	cmd := global.Arg(0)
	args := global.Args()[1:]
	var err error
	switch cmd {
	case "agents":
		err = c.print("GET", "/api/v1/agents", nil)
	case "chains":
		err = c.print("GET", "/api/v1/chains", nil)
	case "doctor":
		err = runDoctor(c, args)
	case "ops":
		err = runOps(c, args)
	case "chain-routes":
		err = runChainRoutes(c, args)
	case "chain-plan":
		err = runChainPlan(c, args)
	case "chain-repair":
		err = runChainRepair(c, args)
	case "chain-autoroute":
		err = runChainAutoroute(c, args)
	case "relay-start":
		err = runRelayStart(c, args)
	case "relay-stop":
		err = runRelayStop(c, args)
	case "relay-token-rotate":
		err = runRelayTokenRotate(c, args)
	case "relay-token-revoke":
		err = runRelayTokenRevoke(c, args)
	default:
		err = fmt.Errorf("unknown command %q", cmd)
	}
	if err != nil {
		fatal(err)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `Usage:
  relayctl [global flags] agents
  relayctl [global flags] chains
  relayctl [global flags] doctor [--with-ipv6] [--interface-prefix ligolo]
  relayctl [global flags] ops [--with-ipv6] [--interface-prefix ligolo] [--fail-on-warning]
  relayctl [global flags] chain-routes [--with-ipv6] [--interface-prefix ligolo]
  relayctl [global flags] chain-plan [--with-ipv6] [--interface-prefix ligolo] [--start]
  relayctl [global flags] chain-repair [--with-ipv6] [--interface-prefix ligolo] [--start] [--prune-conflicts] [--apply]
  relayctl [global flags] chain-autoroute [--with-ipv6] [--interface-prefix ligolo] [--start]
  relayctl [global flags] relay-start --agent id --listen 127.0.0.1:11602 [--relay-token token] [--token-ttl 8h] [--one-time-token]
  relayctl [global flags] relay-stop --agent id
  relayctl [global flags] relay-token-rotate --agent id [--relay-token token] [--token-ttl 8h] [--one-time-token]
  relayctl [global flags] relay-token-revoke --agent id

Global flags:
`)
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	fmt.Fprintln(os.Stderr, "  -api string")
	fmt.Fprintln(os.Stderr, "        Ligolo API base URL (or LIGOLO_API)")
	fmt.Fprintln(os.Stderr, "  -user string")
	fmt.Fprintln(os.Stderr, "        API username (or LIGOLO_USER)")
	fmt.Fprintln(os.Stderr, "  -password string")
	fmt.Fprintln(os.Stderr, "        API password (or LIGOLO_PASSWORD)")
	fmt.Fprintln(os.Stderr, "  -token string")
	fmt.Fprintln(os.Stderr, "        API bearer token (or LIGOLO_TOKEN)")
}

func runDoctor(c *client, args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	withIPv6 := fs.Bool("with-ipv6", false, "include IPv6 route candidates")
	interfacePrefix := fs.String("interface-prefix", "ligolo", "interface prefix")
	if err := fs.Parse(args); err != nil {
		return err
	}
	q := url.Values{}
	q.Set("with_ipv6", fmt.Sprintf("%t", *withIPv6))
	q.Set("interface_prefix", *interfacePrefix)
	return c.print("GET", "/api/v1/relay/doctor?"+q.Encode(), nil)
}

func runOps(c *client, args []string) error {
	fs := flag.NewFlagSet("ops", flag.ExitOnError)
	withIPv6 := fs.Bool("with-ipv6", false, "include IPv6 route candidates")
	interfacePrefix := fs.String("interface-prefix", "ligolo", "interface prefix")
	failOnWarning := fs.Bool("fail-on-warning", false, "exit non-zero when relay ops status is not ok")
	if err := fs.Parse(args); err != nil {
		return err
	}
	q := url.Values{}
	q.Set("with_ipv6", fmt.Sprintf("%t", *withIPv6))
	q.Set("interface_prefix", *interfacePrefix)
	payload, err := c.do("GET", "/api/v1/relay/ops?"+q.Encode(), nil)
	if err != nil {
		return err
	}
	printPayload(payload)
	if !*failOnWarning {
		return nil
	}
	var status struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(payload, &status); err != nil {
		return err
	}
	if status.Status != "ok" {
		return fmt.Errorf("relay ops status is %q", status.Status)
	}
	return nil
}

func runChainRoutes(c *client, args []string) error {
	fs := flag.NewFlagSet("chain-routes", flag.ExitOnError)
	withIPv6 := fs.Bool("with-ipv6", false, "include IPv6 route candidates")
	interfacePrefix := fs.String("interface-prefix", "ligolo", "interface prefix")
	if err := fs.Parse(args); err != nil {
		return err
	}
	q := url.Values{}
	q.Set("with_ipv6", fmt.Sprintf("%t", *withIPv6))
	q.Set("interface_prefix", *interfacePrefix)
	return c.print("GET", "/api/v1/chain_routes?"+q.Encode(), nil)
}

func runChainPlan(c *client, args []string) error {
	fs := flag.NewFlagSet("chain-plan", flag.ExitOnError)
	withIPv6 := fs.Bool("with-ipv6", false, "include IPv6 route candidates")
	interfacePrefix := fs.String("interface-prefix", "ligolo", "interface prefix")
	start := fs.Bool("start", false, "include tunnel start actions in the dry-run plan")
	if err := fs.Parse(args); err != nil {
		return err
	}
	q := url.Values{}
	q.Set("with_ipv6", fmt.Sprintf("%t", *withIPv6))
	q.Set("interface_prefix", *interfacePrefix)
	q.Set("start", fmt.Sprintf("%t", *start))
	return c.print("GET", "/api/v1/chain_route_plan?"+q.Encode(), nil)
}

func runChainRepair(c *client, args []string) error {
	fs := flag.NewFlagSet("chain-repair", flag.ExitOnError)
	withIPv6 := fs.Bool("with-ipv6", false, "include IPv6 route candidates")
	interfacePrefix := fs.String("interface-prefix", "ligolo", "interface prefix")
	start := fs.Bool("start", false, "include or apply tunnel start actions")
	pruneConflicts := fs.Bool("prune-conflicts", false, "remove configured lower-ranked duplicate routes")
	apply := fs.Bool("apply", false, "apply supported repair actions")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *apply {
		return c.print("POST", "/api/v1/chain_repair", map[string]any{
			"WithIPv6":        *withIPv6,
			"InterfacePrefix": *interfacePrefix,
			"Start":           *start,
			"PruneConflicts":  *pruneConflicts,
		})
	}
	q := url.Values{}
	q.Set("with_ipv6", fmt.Sprintf("%t", *withIPv6))
	q.Set("interface_prefix", *interfacePrefix)
	q.Set("start", fmt.Sprintf("%t", *start))
	q.Set("prune_conflicts", fmt.Sprintf("%t", *pruneConflicts))
	return c.print("GET", "/api/v1/chain_repair_plan?"+q.Encode(), nil)
}

func runChainAutoroute(c *client, args []string) error {
	fs := flag.NewFlagSet("chain-autoroute", flag.ExitOnError)
	withIPv6 := fs.Bool("with-ipv6", false, "include IPv6 route candidates")
	interfacePrefix := fs.String("interface-prefix", "ligolo", "interface prefix")
	start := fs.Bool("start", false, "start tunnels after configuring routes")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return c.print("POST", "/api/v1/chain_autoroute", map[string]any{
		"WithIPv6":        *withIPv6,
		"InterfacePrefix": *interfacePrefix,
		"Start":           *start,
	})
}

func runRelayStart(c *client, args []string) error {
	fs := flag.NewFlagSet("relay-start", flag.ExitOnError)
	agentID := fs.Int("agent", 0, "agent ID")
	listenAddr := fs.String("listen", "127.0.0.1:11602", "relay listen address")
	relayToken := fs.String("relay-token", os.Getenv("LIGOLO_RELAY_TOKEN"), "relay auth token (or LIGOLO_RELAY_TOKEN); generated when empty")
	tokenTTL := fs.String("token-ttl", "8h", "relay auth token lifetime")
	oneTimeToken := fs.Bool("one-time-token", false, "allow the token to authenticate one downstream agent only")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *agentID <= 0 {
		return errors.New("relay-start requires --agent")
	}
	tokenTTLSeconds, err := parseTokenTTLSeconds(*tokenTTL)
	if err != nil {
		return err
	}
	return c.print("POST", fmt.Sprintf("/api/v1/relay/%d", *agentID), map[string]any{
		"ListenAddr":      *listenAddr,
		"AuthToken":       *relayToken,
		"TokenTTLSeconds": tokenTTLSeconds,
		"OneTimeToken":    *oneTimeToken,
	})
}

func runRelayStop(c *client, args []string) error {
	fs := flag.NewFlagSet("relay-stop", flag.ExitOnError)
	agentID := fs.Int("agent", 0, "agent ID")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *agentID <= 0 {
		return errors.New("relay-stop requires --agent")
	}
	return c.print("DELETE", fmt.Sprintf("/api/v1/relay/%d", *agentID), nil)
}

func runRelayTokenRotate(c *client, args []string) error {
	fs := flag.NewFlagSet("relay-token-rotate", flag.ExitOnError)
	agentID := fs.Int("agent", 0, "agent ID")
	relayToken := fs.String("relay-token", os.Getenv("LIGOLO_RELAY_TOKEN"), "new relay auth token (or LIGOLO_RELAY_TOKEN); generated when empty")
	tokenTTL := fs.String("token-ttl", "8h", "relay auth token lifetime")
	oneTimeToken := fs.Bool("one-time-token", false, "allow the token to authenticate one downstream agent only")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *agentID <= 0 {
		return errors.New("relay-token-rotate requires --agent")
	}
	tokenTTLSeconds, err := parseTokenTTLSeconds(*tokenTTL)
	if err != nil {
		return err
	}
	return c.print("POST", fmt.Sprintf("/api/v1/relay/%d/token", *agentID), map[string]any{
		"AuthToken":       *relayToken,
		"TokenTTLSeconds": tokenTTLSeconds,
		"OneTimeToken":    *oneTimeToken,
	})
}

func runRelayTokenRevoke(c *client, args []string) error {
	fs := flag.NewFlagSet("relay-token-revoke", flag.ExitOnError)
	agentID := fs.Int("agent", 0, "agent ID")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *agentID <= 0 {
		return errors.New("relay-token-revoke requires --agent")
	}
	return c.print("DELETE", fmt.Sprintf("/api/v1/relay/%d/token", *agentID), nil)
}

func parseTokenTTLSeconds(value string) (int64, error) {
	duration, err := time.ParseDuration(value)
	if err != nil || duration <= 0 {
		return 0, fmt.Errorf("invalid token TTL %q", value)
	}
	return int64(duration.Seconds()), nil
}

func (c *client) print(method, path string, body any) error {
	payload, err := c.do(method, path, body)
	if err != nil {
		return err
	}
	printPayload(payload)
	return nil
}

func printPayload(payload []byte) {
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, payload, "", "  "); err != nil {
		fmt.Println(string(payload))
		return
	}
	fmt.Println(pretty.String())
}

func (c *client) do(method, path string, body any) ([]byte, error) {
	if c.token == "" {
		if err := c.auth(); err != nil {
			return nil, err
		}
	}

	var reader io.Reader
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(payload)
	}
	req, err := http.NewRequest(method, c.baseURL+path, reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%s %s failed: HTTP %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(payload)))
	}
	return payload, nil
}

func (c *client) auth() error {
	if c.username == "" || c.password == "" {
		return errors.New("set -token, or set -user and -password")
	}
	payload, err := json.Marshal(map[string]string{
		"Username": c.username,
		"Password": c.password,
	})
	if err != nil {
		return err
	}
	resp, err := c.httpClient.Post(c.baseURL+"/api/auth", "application/json", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("auth failed: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	var authResp struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(data, &authResp); err != nil {
		return err
	}
	if authResp.Token == "" {
		return errors.New("auth response did not include token")
	}
	c.token = authResp.Token
	return nil
}

func envDefault(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "relayctl:", err)
	os.Exit(1)
}
