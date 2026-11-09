// Package coretrust is how logos-vpn trusts core's TLS certificate: by
// default the system's certificate authorities, as any HTTPS client; for a
// core whose certificate they do not sign (a self-signed one), the same
// three settings a module takes (docs: deployment, "How modules reach
// core"), as flags or from the environment:
//
//	-ca-file      LOGOS_CORE_CA_FILE       a PEM file of certificates trusted
//	                                       beside the system's; still
//	                                       verified, host name included.
//	-cert-sha256  LOGOS_CORE_CERT_SHA256   the SHA-256 fingerprint of core's
//	                                       certificate: exactly that one is
//	                                       accepted, whatever signed it and
//	                                       whatever name it carries.
//	-insecure     LOGOS_CORE_TLS_INSECURE  no verification: the link stays
//	                                       encrypted, but to whoever answers.
//
// One of them decides: the first set, in the order insecure, fingerprint,
// CA file.
package coretrust

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// The settings' environment variables: the modules' own.
const (
	EnvCAFile     = "LOGOS_CORE_CA_FILE"
	EnvCertSHA256 = "LOGOS_CORE_CERT_SHA256"
	EnvInsecure   = "LOGOS_CORE_TLS_INSECURE"
)

// Config is how core's certificate is trusted.
type Config struct {
	// CAFile is a PEM file of certificates trusted beside the system's.
	CAFile string
	// CertSHA256 is the one certificate accepted: the SHA-256 of its DER.
	CertSHA256 []byte
	// Insecure skips verification.
	Insecure bool
}

// Read makes a Config of the flags' values, each one unset falling back to
// its environment variable (lookup; os.LookupEnv when nil).
func Read(caFile, certSHA256 string, insecure bool, lookup func(string) (string, bool)) (Config, error) {
	if lookup == nil {
		lookup = os.LookupEnv
	}
	env := func(k string) string {
		v, _ := lookup(k)
		return strings.TrimSpace(v)
	}
	c := Config{Insecure: insecure, CAFile: strings.TrimSpace(caFile)}
	if !insecure {
		if v := env(EnvInsecure); v != "" {
			b, err := strconv.ParseBool(v)
			if err != nil {
				return c, fmt.Errorf("%s: %q is not true or false", EnvInsecure, v)
			}
			c.Insecure = b
		}
	}
	fp, name := strings.TrimSpace(certSHA256), "-cert-sha256"
	if fp == "" {
		fp, name = env(EnvCertSHA256), EnvCertSHA256
	}
	if fp != "" {
		b, err := ParseFingerprint(fp)
		if err != nil {
			return c, fmt.Errorf("%s: %w", name, err)
		}
		c.CertSHA256 = b
	}
	if c.CAFile == "" {
		c.CAFile = env(EnvCAFile)
	}
	return c, nil
}

// ParseFingerprint reads a SHA-256 fingerprint: 64 hex digits, colons or
// spaces between them allowed, either case ("AB:CD:…", as openssl prints it).
func ParseFingerprint(s string) ([]byte, error) {
	h := strings.NewReplacer(":", "", " ", "", "-", "").Replace(strings.TrimSpace(s))
	h = strings.TrimPrefix(strings.TrimPrefix(h, "sha256/"), "SHA256=")
	b, err := hex.DecodeString(h)
	if err != nil || len(b) != sha256.Size {
		return nil, errors.New("a SHA-256 fingerprint is 64 hex digits")
	}
	return b, nil
}

// Fingerprint is a certificate's SHA-256 fingerprint as openssl prints it.
func Fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}

// Mode names what decides: "system", "ca-file", "fingerprint" or "insecure".
func (c Config) Mode() string {
	switch {
	case c.Insecure:
		return "insecure"
	case c.CertSHA256 != nil:
		return "fingerprint"
	case c.CAFile != "":
		return "ca-file"
	}
	return "system"
}

// TLS is the TLS configuration c makes; nil for the system's defaults.
func (c Config) TLS() (*tls.Config, error) {
	switch c.Mode() {
	case "insecure":
		return &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}, nil //nolint:gosec // asked for
	case "fingerprint":
		want := c.CertSHA256
		return &tls.Config{
			MinVersion: tls.VersionTLS12,
			// The leaf is checked byte for byte, below: not its chain or name.
			InsecureSkipVerify: true, //nolint:gosec // verified below
			VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
				if len(raw) == 0 {
					return errors.New("core sent no certificate")
				}
				if got := sha256.Sum256(raw[0]); !bytes.Equal(got[:], want) {
					return fmt.Errorf("core's certificate is %s, not the one -cert-sha256 names", Fingerprint(raw[0]))
				}
				return nil
			},
		}, nil
	case "ca-file":
		pem, err := os.ReadFile(c.CAFile)
		if err != nil {
			return nil, fmt.Errorf("-ca-file: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("-ca-file: %s holds no PEM certificate", c.CAFile)
		}
		return &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}, nil
	}
	return nil, nil
}
