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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"time"
)

// CA is a minimal certificate authority used to issue the hub's server
// certificate and per-operator client certificates. This is the operator-plane
// PKI; it is independent of the agent-plane Noise keys.
type CA struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	CertPEM []byte
}

// NewCA creates a self-signed CA.
func NewCA() (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: "ligolo-operator-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(5, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{cert: cert, key: key, CertPEM: pemBlock("CERTIFICATE", der)}, nil
}

// issuePEM creates a leaf certificate signed by the CA, returning PEM bytes.
// server selects ServerAuth (with loopback SANs) vs ClientAuth.
func (ca *CA) issuePEM(cn string, server bool) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	if server {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tmpl.DNSNames = []string{"localhost", cn}
		tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	} else {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pemBlock("CERTIFICATE", der), pemBlock("EC PRIVATE KEY", keyDER), nil
}

func (ca *CA) issue(cn string, server bool) (tls.Certificate, error) {
	certPEM, keyPEM, err := ca.issuePEM(cn, server)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(certPEM, keyPEM)
}

// IssueServer issues the hub's server certificate.
func (ca *CA) IssueServer(cn string) (tls.Certificate, error) { return ca.issue(cn, true) }

// IssueOperator issues a client certificate for an operator identified by cn.
func (ca *CA) IssueOperator(cn string) (tls.Certificate, error) { return ca.issue(cn, false) }

// IssueOperatorPEM issues an operator client certificate as PEM bytes, for
// writing an operator config bundle to disk.
func (ca *CA) IssueOperatorPEM(cn string) (certPEM, keyPEM []byte, err error) {
	return ca.issuePEM(cn, false)
}

func (ca *CA) pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(ca.cert)
	return p
}

// HubTLSConfig builds the server-side mTLS config: it presents serverCert and
// requires + verifies operator client certificates against the CA.
func (ca *CA) HubTLSConfig(serverCert tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    ca.pool(),
		MinVersion:   tls.VersionTLS13,
	}
}

// ClientTLSConfig builds the operator-side mTLS config: it presents the operator
// cert and verifies the hub against the CA.
func (ca *CA) ClientTLSConfig(operatorCert tls.Certificate, serverName string) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{operatorCert},
		RootCAs:      ca.pool(),
		ServerName:   serverName,
		MinVersion:   tls.VersionTLS13,
	}
}

func serial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if n == nil {
		return big.NewInt(time.Now().UnixNano())
	}
	return n
}

func pemBlock(typ string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}
