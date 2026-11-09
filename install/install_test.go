// Package install holds logos-vpn's installers, install.sh (Linux, macOS)
// and install.ps1 (Windows), which core serves beside the binaries. The
// tests run each as core's Connect a machine line does, fetched from a
// fake core and piped into the shell, against plain HTTP and against a
// certificate no system trusts, pinned.
package install

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const testKey = "lgv_0123456789ab_secret"

// fakeVPN is a stand-in for logos-vpn: -version prints one, anything else
// writes its arguments where the test reads them.
func fakeVPN(argsFile string) []byte {
	return []byte("#!/bin/sh\nif [ \"$1\" = -version ]; then echo v9.9.9; exit 0; fi\necho \"$@\" > " + argsFile + "\n")
}

// fakeCore serves the installers and, for the key alone, SHA256SUMS and the
// binary for platform (sums lists it with hash, its own unless given).
type fakeCore struct {
	bin, sums []byte
	platform  string
}

func newCore(platform string, bin []byte) *fakeCore {
	sum := sha256.Sum256(bin)
	name := "logos-vpn-" + platform
	if strings.HasPrefix(platform, "windows-") {
		name += ".exe"
	}
	return &fakeCore{bin: bin, platform: platform, sums: fmt.Appendf(nil, "%x  %s\n%x  logos-vpn-other\n", sum, name, sha256.Sum256(nil))}
}

func (f *fakeCore) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/api/v1/vpn/install.sh", "/api/v1/vpn/install.ps1":
		b, err := os.ReadFile(strings.TrimPrefix(r.URL.Path, "/api/v1/vpn/"))
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		_, _ = w.Write(b)
		return
	}
	if r.Header.Get("Authorization") != "Bearer "+testKey {
		http.Error(w, `{"error":"the key is unknown, lapsed or used"}`, http.StatusUnauthorized)
		return
	}
	switch r.URL.Path {
	case "/api/v1/vpn/client/SHA256SUMS":
		_, _ = w.Write(f.sums)
	case "/api/v1/vpn/client/" + f.platform:
		_, _ = w.Write(f.bin)
	default:
		http.NotFound(w, r)
	}
}

// pin is a certificate's public key as curl's --pinnedpubkey takes it.
func pin(c *x509.Certificate) string {
	sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return "sha256//" + base64.StdEncoding.EncodeToString(sum[:])
}

func fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}

func hostPlatform(t *testing.T) string {
	t.Helper()
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("install.sh is for Linux and macOS")
	}
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("no curl")
	}
	return runtime.GOOS + "-" + runtime.GOARCH
}

// runSH runs the line core gives: curl … install.sh | sh -s -- args, into dir.
func runSH(t *testing.T, base, curlFlags, dir string, args ...string) (string, error) {
	t.Helper()
	q := make([]string, len(args))
	for i, a := range args {
		q[i] = "'" + a + "'"
	}
	line := fmt.Sprintf("curl -fsSL %s %s/api/v1/vpn/install.sh | sh -s -- %s", curlFlags, base, strings.Join(q, " "))
	// pipefail where the shell has it (dash has not, and exits on the try).
	cmd := exec.Command("sh", "-c", "if (set -o pipefail) 2>/dev/null; then set -o pipefail; fi; "+line)
	cmd.Env = append(os.Environ(), "LOGOS_VPN_DIR="+dir)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func TestInstallSH(t *testing.T) {
	platform := hostPlatform(t)
	work := t.TempDir()
	argsFile := filepath.Join(work, "args")
	bin := fakeVPN(argsFile)
	srv := httptest.NewServer(newCore(platform, bin))
	defer srv.Close()

	t.Run("installs and connects", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "bin")
		out, err := runSH(t, srv.URL, "", dir, srv.URL+"/", testKey)
		if err != nil {
			t.Fatalf("%v: %s", err, out)
		}
		got, err := os.ReadFile(filepath.Join(dir, "logos-vpn"))
		if err != nil || !bytes.Equal(got, bin) {
			t.Fatalf("installed %q, %v", got, err)
		}
		if st, _ := os.Stat(filepath.Join(dir, "logos-vpn")); st.Mode().Perm() != 0o755 {
			t.Errorf("mode %v", st.Mode())
		}
		if !strings.Contains(out, "v9.9.9") {
			t.Errorf("no version said: %s", out)
		}
		if a, _ := os.ReadFile(argsFile); strings.TrimSpace(string(a)) != srv.URL+" "+testKey {
			t.Errorf("connected with %q", a)
		}
	})

	t.Run("again: replaced", func(t *testing.T) {
		dir := t.TempDir()
		_ = os.WriteFile(filepath.Join(dir, "logos-vpn"), []byte("old"), 0o755)
		if out, err := runSH(t, srv.URL, "", dir, "--no-connect", srv.URL, testKey); err != nil {
			t.Fatalf("%v: %s", err, out)
		}
		if got, _ := os.ReadFile(filepath.Join(dir, "logos-vpn")); !bytes.Equal(got, bin) {
			t.Errorf("not replaced: %q", got)
		}
	})

	for name, tc := range map[string]struct {
		core func() *httptest.Server
		args []string
		says string
	}{
		"an unknown key": {func() *httptest.Server { return srv }, []string{srv.URL, "lgv_other_key"}, `401 {"error":"the key is unknown, lapsed or used"}`},
		"no key":         {func() *httptest.Server { return srv }, []string{srv.URL, "secret"}, "no VPN key"},
		"a wrong hash": {func() *httptest.Server {
			c := newCore(platform, bin)
			c.bin = []byte("tampered")
			return httptest.NewServer(c)
		}, nil, "does not match"},
		"not listed": {func() *httptest.Server {
			c := newCore(platform, bin)
			c.sums = []byte("abc  logos-vpn-other\n")
			return httptest.NewServer(c)
		}, nil, "not listed"},
	} {
		t.Run(name, func(t *testing.T) {
			s := tc.core()
			args := tc.args
			if args == nil {
				args = []string{s.URL, testKey}
			}
			dir := t.TempDir()
			out, err := runSH(t, srv.URL, "", dir, append([]string{"--no-connect"}, args...)...)
			if err == nil || !strings.Contains(out, tc.says) {
				t.Errorf("%v: %s", err, out)
			}
			if _, err := os.Stat(filepath.Join(dir, "logos-vpn")); err == nil {
				t.Error("installed all the same")
			}
		})
	}
}

// A core with a certificate no system trusts: the line pins its public key
// for curl, the script pins it for its own fetches and hands logos-vpn the
// certificate's fingerprint.
func TestInstallSHPinned(t *testing.T) {
	platform := hostPlatform(t)
	work := t.TempDir()
	argsFile := filepath.Join(work, "args")
	srv := httptest.NewTLSServer(newCore(platform, fakeVPN(argsFile)))
	defer srv.Close()
	p, fp := pin(srv.Certificate()), fingerprint(srv.Certificate().Raw)

	dir := t.TempDir()
	out, err := runSH(t, srv.URL, "-k --pinnedpubkey "+p, dir, "--pin", p, "--cert-sha256", fp, srv.URL, testKey)
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if a, _ := os.ReadFile(argsFile); strings.TrimSpace(string(a)) != "-cert-sha256 "+fp+" "+srv.URL+" "+testKey {
		t.Errorf("connected with %q", a)
	}

	// Unpinned, the certificate is refused; pinned to another key, too.
	wrong := "sha256//" + base64.StdEncoding.EncodeToString(make([]byte, 32))
	for name, flags := range map[string][]string{"unpinned": nil, "another key": {"--pin", wrong}} {
		dir := t.TempDir()
		out, err := runSH(t, srv.URL, "-k --pinnedpubkey "+p, dir, append(append([]string{"--no-connect"}, flags...), srv.URL, testKey)...)
		if err == nil {
			t.Errorf("%s: installed: %s", name, out)
		}
		t.Logf("%s: %s", name, out)
	}
}

// pwsh runs PowerShell: LOGOS_VPN_PWSH names the command (a wrapper running
// PowerShell's image, say), else pwsh on PATH; without either the test
// skips, unless LOGOS_VPN_REQUIRE_PWSH is set (CI).
func pwsh(t *testing.T) []string {
	t.Helper()
	if c := os.Getenv("LOGOS_VPN_PWSH"); c != "" {
		return strings.Fields(c)
	}
	for _, name := range []string{"pwsh", "powershell"} {
		if p, err := exec.LookPath(name); err == nil {
			return []string{p}
		}
	}
	if os.Getenv("LOGOS_VPN_REQUIRE_PWSH") != "" {
		t.Fatal("no PowerShell: set LOGOS_VPN_PWSH or put pwsh on PATH")
	}
	t.Skip("no PowerShell (LOGOS_VPN_PWSH, or pwsh on PATH)")
	return nil
}

// pinPrefix is what core's line for Windows runs before fetching the
// script from a core whose certificate it pins (the frontend's vpnInstall,
// tunnel-values.ts): keep the two the same.
func pinPrefix(fp string) string {
	return `if(-not('LogosPin'-as[type])){Add-Type 'public static class LogosPin{public static string Want;public static bool Check(object s,System.Security.Cryptography.X509Certificates.X509Certificate c,System.Security.Cryptography.X509Certificates.X509Chain h,System.Net.Security.SslPolicyErrors e){return System.BitConverter.ToString(System.Security.Cryptography.SHA256.Create().ComputeHash(c.GetRawCertData())).Replace("-","")==Want;}}'};` +
		`[LogosPin]::Want='` + strings.ReplaceAll(fp, ":", "") + `';` +
		`[Net.ServicePointManager]::ServerCertificateValidationCallback=[Delegate]::CreateDelegate([Net.Security.RemoteCertificateValidationCallback],[LogosPin].GetMethod('Check'));`
}

func TestInstallPS1(t *testing.T) {
	ps := pwsh(t)
	// The Windows build, installed where the test says, without connecting
	// (it would not run here): what install.ps1 does on any system.
	bin := []byte("MZ not really a program")
	plain := httptest.NewServer(newCore("windows-amd64", bin))
	defer plain.Close()
	tls := httptest.NewTLSServer(newCore("windows-amd64", bin))
	defer tls.Close()
	fp := fingerprint(tls.Certificate().Raw)

	run := func(t *testing.T, prefix, base string, extra string) (string, string, error) {
		t.Helper()
		dir := filepath.Join(t.TempDir(), "Logos")
		line := prefix + `[Net.ServicePointManager]::SecurityProtocol=[Net.ServicePointManager]::SecurityProtocol -bor 3072;` +
			`& ([scriptblock]::Create((New-Object Net.WebClient).DownloadString('` + base + `/api/v1/vpn/install.ps1'))) '` + base + `' '` + testKey + `'` +
			extra + ` -NoConnect -Platform windows-amd64 -Dir '` + dir + `'`
		cmd := exec.Command(ps[0], append(ps[1:], "-NoProfile", "-NonInteractive", "-Command", line)...)
		out, err := cmd.CombinedOutput()
		return dir, string(out), err
	}

	t.Run("plain", func(t *testing.T) {
		dir, out, err := run(t, "", plain.URL, "")
		if err != nil {
			t.Fatalf("%v: %s", err, out)
		}
		if got, err := os.ReadFile(filepath.Join(dir, "logos-vpn.exe")); err != nil || !bytes.Equal(got, bin) {
			t.Fatalf("installed %q, %v: %s", got, err, out)
		}
	})

	t.Run("pinned", func(t *testing.T) {
		dir, out, err := run(t, pinPrefix(fp), tls.URL, " -CertSha256 '"+fp+"'")
		if err != nil {
			t.Fatalf("%v: %s", err, out)
		}
		if got, _ := os.ReadFile(filepath.Join(dir, "logos-vpn.exe")); !bytes.Equal(got, bin) {
			t.Fatalf("installed %q: %s", got, out)
		}
	})

	t.Run("pinned to another", func(t *testing.T) {
		dir, out, err := run(t, pinPrefix(strings.Repeat("AB:", 31)+"AB"), tls.URL, "")
		if _, serr := os.Stat(filepath.Join(dir, "logos-vpn.exe")); serr == nil {
			t.Fatalf("installed all the same (%v): %s", err, out)
		}
		t.Logf("refused: %s", out)
	})

	t.Run("an unknown key", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "Logos")
		line := `& ([scriptblock]::Create((New-Object Net.WebClient).DownloadString('` + plain.URL + `/api/v1/vpn/install.ps1'))) '` + plain.URL +
			`' 'lgv_other' -NoConnect -Platform windows-amd64 -Dir '` + dir + `'`
		out, _ := exec.Command(ps[0], append(ps[1:], "-NoProfile", "-NonInteractive", "-Command", line)...).CombinedOutput()
		// Windows PowerShell wraps an error's lines at the console's width.
		if !strings.Contains(strings.Join(strings.Fields(string(out)), ""), `401{"error":"thekeyisunknown,lapsedorused"}`) {
			t.Errorf("says %s", out)
		}
		if _, err := os.Stat(filepath.Join(dir, "logos-vpn.exe")); err == nil {
			t.Error("installed all the same")
		}
	})
}
