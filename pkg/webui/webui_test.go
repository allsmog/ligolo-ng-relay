package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type fakeCtrl struct {
	started  string
	killed   string
	listener struct{ agent, net, bind, to string }
}

func (f *fakeCtrl) Agents() []AgentView {
	return []AgentView{{ID: "abc", Name: "root@host", Online: true, Caps: 0x7f, Networks: []string{"10.0.0.0/24"}}}
}
func (f *fakeCtrl) StartTunnel(id, ifname string) (string, error) {
	f.started = id
	return "ligolo", nil
}
func (f *fakeCtrl) StopTunnel(id string) error            { return nil }
func (f *fakeCtrl) Autoroute(id string) ([]string, error) { return []string{"10.0.0.0/24"}, nil }
func (f *fakeCtrl) AddListener(id, n, b, to string) (int32, error) {
	f.listener.agent, f.listener.net, f.listener.bind, f.listener.to = id, n, b, to
	return 7, nil
}
func (f *fakeCtrl) StopListener(id string, lid int32) error { return nil }
func (f *fakeCtrl) Kill(id string) error                    { f.killed = id; return nil }

func newTestServer(t *testing.T) (*httptest.Server, *fakeCtrl) {
	t.Helper()
	f := &fakeCtrl{}
	s := New(f, "secrettoken")
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return ts, f
}

func do(t *testing.T, ts *httptest.Server, method, path, token, body string) *http.Response {
	t.Helper()
	var r *http.Request
	var err error
	if body != "" {
		r, err = http.NewRequest(method, ts.URL+path, strings.NewReader(body))
	} else {
		r, err = http.NewRequest(method, ts.URL+path, nil)
	}
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestRequiresToken(t *testing.T) {
	ts, _ := newTestServer(t)
	if r := do(t, ts, "GET", "/api/agents", "", ""); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no token: status %d, want 401", r.StatusCode)
	}
	if r := do(t, ts, "GET", "/api/agents", "wrong", ""); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong token: status %d, want 401", r.StatusCode)
	}
}

func TestAgentsAndActions(t *testing.T) {
	ts, f := newTestServer(t)

	r := do(t, ts, "GET", "/api/agents", "secrettoken", "")
	if r.StatusCode != http.StatusOK {
		t.Fatalf("agents: status %d", r.StatusCode)
	}
	var agents []AgentView
	json.NewDecoder(r.Body).Decode(&agents)
	if len(agents) != 1 || agents[0].ID != "abc" || !agents[0].Online {
		t.Fatalf("unexpected agents: %+v", agents)
	}

	do(t, ts, "POST", "/api/agents/abc/tunnel", "secrettoken", "{}")
	if f.started != "abc" {
		t.Errorf("StartTunnel not called for abc, got %q", f.started)
	}

	do(t, ts, "POST", "/api/agents/abc/listeners", "secrettoken", `{"network":"tcp","bind":"0.0.0.0:8080","to":"127.0.0.1:80"}`)
	if f.listener.agent != "abc" || f.listener.bind != "0.0.0.0:8080" || f.listener.to != "127.0.0.1:80" {
		t.Errorf("AddListener wrong args: %+v", f.listener)
	}

	do(t, ts, "POST", "/api/agents/abc/kill", "secrettoken", "{}")
	if f.killed != "abc" {
		t.Errorf("Kill not called for abc")
	}
}

func TestServesIndex(t *testing.T) {
	ts, _ := newTestServer(t)
	r := do(t, ts, "GET", "/", "", "")
	if r.StatusCode != http.StatusOK {
		t.Fatalf("index: status %d", r.StatusCode)
	}
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("index content-type %q", ct)
	}
}
