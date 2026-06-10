package ngconfig

import (
	"path/filepath"
	"testing"
)

func TestSaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ligolo.json")
	c := New(path)
	c.Listen = "quic://0.0.0.0:11601"
	c.ServerKeyHex = "deadbeef"
	c.PSK = "secret"
	if err := c.SetAutobind("agentkey", Autobind{
		Interface: "ligolo",
		Route:     true,
		Listeners: []ListenerRule{{Network: "tcp", Bind: "0.0.0.0:8080", To: "127.0.0.1:80"}},
	}); err != nil {
		t.Fatal(err)
	}

	if !Exists(path) {
		t.Fatal("config file not written")
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Listen != c.Listen || loaded.ServerKeyHex != c.ServerKeyHex || loaded.PSK != c.PSK {
		t.Errorf("scalar fields mismatch: %+v", loaded)
	}
	rule, ok := loaded.AutobindFor("agentkey")
	if !ok {
		t.Fatal("autobind rule not persisted")
	}
	if !rule.Route || rule.Interface != "ligolo" || len(rule.Listeners) != 1 {
		t.Errorf("autobind rule mismatch: %+v", rule)
	}
	if rule.Listeners[0].Bind != "0.0.0.0:8080" {
		t.Errorf("listener rule mismatch: %+v", rule.Listeners[0])
	}

	if err := loaded.RemoveAutobind("agentkey"); err != nil {
		t.Fatal(err)
	}
	if _, ok := loaded.AutobindFor("agentkey"); ok {
		t.Error("autobind rule not removed")
	}
}
