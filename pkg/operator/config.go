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

package operator

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
)

// Bundle file names within an operator config directory.
const (
	caFile   = "ca.crt"
	certFile = "operator.crt"
	keyFile  = "operator.key"
	hubName  = "ligolo-hub"
)

// WriteOperatorBundle issues a client certificate for cn and writes a self-
// contained operator config bundle (CA + operator cert/key) into dir. This is
// the `new-operator` flow: hand the directory to an operator and they can
// connect with no further setup.
func WriteOperatorBundle(ca *CA, dir, cn string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	certPEM, keyPEM, err := ca.IssueOperatorPEM(cn)
	if err != nil {
		return err
	}
	files := map[string][]byte{
		caFile:   ca.CertPEM,
		certFile: certPEM,
		keyFile:  keyPEM,
	}
	for name, data := range files {
		mode := os.FileMode(0o600)
		if err := os.WriteFile(filepath.Join(dir, name), data, mode); err != nil {
			return err
		}
	}
	return nil
}

// LoadClientTLS builds an operator mTLS client config from a bundle directory.
func LoadClientTLS(dir string) (*tls.Config, error) {
	caPEM, err := os.ReadFile(filepath.Join(dir, caFile))
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("operator: no certificates in %s", caFile)
	}
	cert, err := tls.LoadX509KeyPair(filepath.Join(dir, certFile), filepath.Join(dir, keyFile))
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		ServerName:   hubName,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// ServerName is the hub's certificate common name; the proxy issues its server
// cert with this CN and operators verify it.
func ServerName() string { return hubName }
