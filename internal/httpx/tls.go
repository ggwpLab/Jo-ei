package httpx

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
)

// RootPool returns the system root pool with every certificate from caFiles
// added, and how many certificates were added. Configured CAs supplement the
// public roots rather than replacing them, so a private mirror signed by a
// corporate CA and a public registry both verify through the same pool.
//
// Every failure is fatal to the caller by design: a CA file that cannot be read
// or parsed is a misconfiguration, and continuing with silently reduced trust
// would surface much later as an opaque x509 error on a fetch.
func RootPool(caFiles []string) (*x509.CertPool, int, error) {
	pool, err := x509.SystemCertPool()
	if err != nil {
		return nil, 0, fmt.Errorf("loading system CA pool: %w", err)
	}
	added := 0
	for _, f := range caFiles {
		raw, err := os.ReadFile(f) // #nosec G304 -- the path comes from the operator's own config
		if err != nil {
			return nil, 0, fmt.Errorf("reading CA file %q: %w", f, err)
		}
		n := 0
		rest := raw
		for {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			if block.Type != "CERTIFICATE" {
				continue
			}
			cert, perr := x509.ParseCertificate(block.Bytes)
			if perr != nil {
				return nil, 0, fmt.Errorf("parsing a certificate in CA file %q: %w", f, perr)
			}
			pool.AddCert(cert)
			n++
		}
		if n == 0 {
			return nil, 0, fmt.Errorf("CA file %q contains no certificates", f)
		}
		added += n
	}
	return pool, added, nil
}

// NewTransport clones the default transport and points its root pool at the
// given one. A nil pool keeps the platform default. Cloning preserves the
// default connection pooling, proxy handling, and HTTP/2 negotiation.
func NewTransport(pool *x509.CertPool) *http.Transport {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if tr.TLSClientConfig == nil {
		tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	tr.TLSClientConfig.RootCAs = pool
	return tr
}
