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

// Package ngconfig persists the v2 proxy/daemon configuration: a stable server
// identity, listen settings, and per-agent autobind rules so a daemon restores
// tunnels and reverse listeners automatically when known agents reconnect.
//
// This is the v2 replacement for the legacy viper-based config; it is a small
// self-contained JSON file with no external config framework.
package ngconfig

import (
	"encoding/json"
	"os"
	"sync"
)

// ListenerRule recreates a reverse listener on autobind.
type ListenerRule struct {
	Network string `json:"network"`
	Bind    string `json:"bind"`
	To      string `json:"to"`
}

// Autobind is applied when an agent with the given static public key connects.
type Autobind struct {
	Interface string         `json:"interface"`
	Route     bool           `json:"route"`
	AutoRoute bool           `json:"autoroute,omitempty"` // install routes for the agent's networks
	Listeners []ListenerRule `json:"listeners,omitempty"`
}

// Config is the persisted daemon configuration.
type Config struct {
	Listen            string              `json:"listen"`
	ServerKeyHex      string              `json:"server_key"`
	PSK               string              `json:"psk,omitempty"`
	OperatorListen    string              `json:"operator_listen,omitempty"`
	OperatorConfigDir string              `json:"operator_config_dir,omitempty"`
	Autobind          map[string]Autobind `json:"autobind,omitempty"`

	mu   sync.Mutex
	path string
}

// Load reads a config from path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	if c.Autobind == nil {
		c.Autobind = make(map[string]Autobind)
	}
	c.path = path
	return &c, nil
}

// New returns an empty config bound to path.
func New(path string) *Config {
	return &Config{path: path, Autobind: make(map[string]Autobind)}
}

// Exists reports whether a config file is present at path.
func Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// Path returns the file path backing the config.
func (c *Config) Path() string { return c.path }

// Save writes the config to its path atomically (0600).
func (c *Config) Save() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, c.path)
}

// SetAutobind stores (or replaces) an autobind rule for an agent key and saves.
func (c *Config) SetAutobind(agentKeyHex string, rule Autobind) error {
	c.mu.Lock()
	if c.Autobind == nil {
		c.Autobind = make(map[string]Autobind)
	}
	c.Autobind[agentKeyHex] = rule
	c.mu.Unlock()
	return c.Save()
}

// RemoveAutobind deletes an autobind rule and saves.
func (c *Config) RemoveAutobind(agentKeyHex string) error {
	c.mu.Lock()
	delete(c.Autobind, agentKeyHex)
	c.mu.Unlock()
	return c.Save()
}

// AutobindFor returns the rule for an agent key, if any.
func (c *Config) AutobindFor(agentKeyHex string) (Autobind, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	r, ok := c.Autobind[agentKeyHex]
	return r, ok
}
