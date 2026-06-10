package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nicocha30/ligolo-ng/pkg/webui"
)

// fakeController implements webui.Controller so the MCP bridge can be tested
// end to end against the real REST handlers.
type fakeController struct {
	agents       []webui.AgentView
	startedIface string
	killed       string
	lastListener [3]string // network, bind, to
}

func (f *fakeController) Agents() []webui.AgentView { return f.agents }
func (f *fakeController) StartTunnel(agentID, ifname string) (string, error) {
	if agentID != "agent-1" {
		return "", errors.New("unknown agent")
	}
	if ifname == "" {
		ifname = "ligolo0"
	}
	f.startedIface = ifname
	return ifname, nil
}
func (f *fakeController) StopTunnel(string) error           { return nil }
func (f *fakeController) Autoroute(string) ([]string, error) { return []string{"10.0.0.0/8"}, nil }
func (f *fakeController) AddListener(_, network, bind, to string) (int32, error) {
	f.lastListener = [3]string{network, bind, to}
	return 7, nil
}
func (f *fakeController) StopListener(string, int32) error { return nil }
func (f *fakeController) Kill(agentID string) error {
	if agentID != "agent-1" {
		return errors.New("unknown agent")
	}
	f.killed = agentID
	return nil
}

func newTestServer(t *testing.T) (*server, *fakeController) {
	t.Helper()
	ctrl := &fakeController{agents: []webui.AgentView{{ID: "agent-1", Name: "alpha", Online: true, Networks: []string{"10.0.0.0/8"}}}}
	ts := httptest.NewServer(webui.New(ctrl, "secret").Handler())
	t.Cleanup(ts.Close)
	return newServer(newRESTClient(ts.URL, "secret")), ctrl
}

// callTool drives a tools/call through handle() and returns the text content
// plus the isError flag.
func callTool(t *testing.T, s *server, name string, args map[string]any) (string, bool) {
	t.Helper()
	params, _ := json.Marshal(map[string]any{"name": name, "arguments": args})
	resp, notif := s.handle(context.Background(), &rpcRequest{Method: "tools/call", ID: json.RawMessage("1"), Params: params})
	if notif {
		t.Fatal("tools/call must not be treated as a notification")
	}
	res, ok := resp.Result.(map[string]any)
	if !ok {
		t.Fatalf("result is not an object: %#v", resp.Result)
	}
	content := res["content"].([]map[string]any)
	return content[0]["text"].(string), res["isError"].(bool)
}

func TestInitializeEchoesProtocolVersion(t *testing.T) {
	s, _ := newTestServer(t)
	resp, _ := s.handle(context.Background(), &rpcRequest{
		Method: "initialize", ID: json.RawMessage("1"),
		Params: json.RawMessage(`{"protocolVersion":"2025-06-18"}`),
	})
	res := resp.Result.(map[string]any)
	if res["protocolVersion"] != "2025-06-18" {
		t.Errorf("protocolVersion = %v, want echo of client value", res["protocolVersion"])
	}
	if _, ok := res["capabilities"].(map[string]any)["tools"]; !ok {
		t.Error("server must advertise the tools capability")
	}
}

func TestToolsListExposesAllOperations(t *testing.T) {
	s, _ := newTestServer(t)
	resp, _ := s.handle(context.Background(), &rpcRequest{Method: "tools/list", ID: json.RawMessage("1")})
	tools := resp.Result.(map[string]any)["tools"].([]tool)
	want := map[string]bool{
		"list_agents": false, "start_tunnel": false, "stop_tunnel": false,
		"autoroute": false, "add_listener": false, "stop_listener": false, "kill_agent": false,
	}
	for _, tl := range tools {
		want[tl.Name] = true
		if !json.Valid(tl.InputSchema) {
			t.Errorf("tool %q has invalid inputSchema JSON", tl.Name)
		}
	}
	for name, seen := range want {
		if !seen {
			t.Errorf("tool %q missing from tools/list", name)
		}
	}
}

func TestListAgentsBridgesREST(t *testing.T) {
	s, _ := newTestServer(t)
	text, isErr := callTool(t, s, "list_agents", nil)
	if isErr {
		t.Fatalf("list_agents errored: %s", text)
	}
	if !strings.Contains(text, "agent-1") || !strings.Contains(text, "10.0.0.0/8") {
		t.Errorf("list_agents text missing expected data: %s", text)
	}
}

func TestStartTunnelAndAddListener(t *testing.T) {
	s, ctrl := newTestServer(t)

	text, isErr := callTool(t, s, "start_tunnel", map[string]any{"agent_id": "agent-1", "interface": "lig9"})
	if isErr {
		t.Fatalf("start_tunnel errored: %s", text)
	}
	if ctrl.startedIface != "lig9" || !strings.Contains(text, "lig9") {
		t.Errorf("start_tunnel did not pass the interface through: iface=%q text=%s", ctrl.startedIface, text)
	}

	text, isErr = callTool(t, s, "add_listener", map[string]any{
		"agent_id": "agent-1", "network": "tcp", "bind": "0.0.0.0:1234", "to": "127.0.0.1:80",
	})
	if isErr {
		t.Fatalf("add_listener errored: %s", text)
	}
	if ctrl.lastListener != [3]string{"tcp", "0.0.0.0:1234", "127.0.0.1:80"} {
		t.Errorf("add_listener args not forwarded: %#v", ctrl.lastListener)
	}
	if !strings.Contains(text, "7") {
		t.Errorf("add_listener should return listener id 7: %s", text)
	}
}

func TestToolErrorsSurfaceAsIsError(t *testing.T) {
	s, _ := newTestServer(t)

	// Missing required argument is caught before the REST call.
	if text, isErr := callTool(t, s, "start_tunnel", map[string]any{}); !isErr {
		t.Errorf("missing agent_id should be an error, got %s", text)
	}

	// REST-level failure (unknown agent) must surface as isError, not a panic.
	text, isErr := callTool(t, s, "kill_agent", map[string]any{"agent_id": "nope"})
	if !isErr || !strings.Contains(text, "unknown agent") {
		t.Errorf("expected unknown-agent error, got isErr=%v text=%s", isErr, text)
	}
}

func TestUnknownMethodReturnsRPCError(t *testing.T) {
	s, _ := newTestServer(t)
	resp, _ := s.handle(context.Background(), &rpcRequest{Method: "bogus", ID: json.RawMessage("1")})
	if resp.Error == nil || resp.Error.Code != -32601 {
		t.Errorf("unknown method should return -32601, got %#v", resp.Error)
	}
}
