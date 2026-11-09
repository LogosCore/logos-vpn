package coretrust

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
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// selfSigned is a self-signed certificate for 127.0.0.1, in DER: not
// httptest's, which every test server shares.
func selfSigned(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "not core"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func env(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

func TestTrust(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }))
	defer srv.Close()
	fp := Fingerprint(srv.Certificate().Raw)
	dir := t.TempDir()
	caFile := filepath.Join(dir, "core.pem")
	_ = os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600)
	other := selfSigned(t)
	otherFile := filepath.Join(dir, "other.pem")
	_ = os.WriteFile(otherFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: other}), 0o600)

	type flags struct {
		ca, fp   string
		insecure bool
	}
	for name, tc := range map[string]struct {
		flags flags
		env   map[string]string
		mode  string
		ok    bool
	}{
		"the system's":               {flags{}, nil, "system", false},
		"its fingerprint":            {flags{fp: fp}, nil, "fingerprint", true},
		"its fingerprint, plain":     {flags{fp: strings.ToLower(strings.ReplaceAll(fp, ":", ""))}, nil, "fingerprint", true},
		"another fingerprint":        {flags{fp: Fingerprint(other)}, nil, "fingerprint", false},
		"its PEM":                    {flags{ca: caFile}, nil, "ca-file", true},
		"another PEM":                {flags{ca: otherFile}, nil, "ca-file", false},
		"insecure":                   {flags{insecure: true}, nil, "insecure", true},
		"from the environment":       {flags{}, map[string]string{EnvCertSHA256: fp}, "fingerprint", true},
		"insecure, environment":      {flags{}, map[string]string{EnvInsecure: "1"}, "insecure", true},
		"the flag over the variable": {flags{fp: fp}, map[string]string{EnvCertSHA256: Fingerprint(other)}, "fingerprint", true},
		"insecure first":             {flags{fp: Fingerprint(other), insecure: true}, nil, "insecure", true},
	} {
		c, err := Read(tc.flags.ca, tc.flags.fp, tc.flags.insecure, env(tc.env))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if c.Mode() != tc.mode {
			t.Errorf("%s: mode %s, want %s", name, c.Mode(), tc.mode)
		}
		tc2, err := c.TLS()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		tr := &http.Transport{TLSClientConfig: tc2}
		if tc2 == nil {
			tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		}
		resp, err := (&http.Client{Transport: tr}).Get(srv.URL)
		if err == nil {
			_ = resp.Body.Close()
		}
		if (err == nil) != tc.ok {
			t.Errorf("%s: %v", name, err)
		}
		if name == "another fingerprint" && (err == nil || !strings.Contains(err.Error(), fp)) {
			t.Errorf("a wrong fingerprint does not say core's: %v", err)
		}
	}
}

func TestReadRefusals(t *testing.T) {
	if _, err := Read("", "AB:CD", false, env(nil)); err == nil || !strings.Contains(err.Error(), "-cert-sha256") {
		t.Errorf("a short fingerprint: %v", err)
	}
	if _, err := Read("", "", false, env(map[string]string{EnvCertSHA256: "zz"})); err == nil || !strings.Contains(err.Error(), EnvCertSHA256) {
		t.Errorf("a variable's: %v", err)
	}
	if _, err := Read("", "", false, env(map[string]string{EnvInsecure: "yes please"})); err == nil {
		t.Error("not a boolean")
	}
	if _, err := (Config{CAFile: filepath.Join(t.TempDir(), "none.pem")}).TLS(); err == nil {
		t.Error("a missing CA file")
	}
}
