package upgrader

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func localTLSTestDownloader(t *testing.T, server *httptest.Server) HTTPDownloader {
	t.Helper()
	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	return HTTPDownloader{
		Client: server.Client(),
		LookupIP: func(context.Context, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("1.1.1.1")}, nil
		},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, u.Host)
		},
	}
}

func serverHost(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u.Hostname()
}

func TestHTTPSDownloader(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("artifact")) }))
	defer server.Close()
	destination := filepath.Join(t.TempDir(), "artifact")
	sum, err := localTLSTestDownloader(t, server).Download(context.Background(), server.URL, destination, 64, []string{serverHost(t, server.URL)})
	if err != nil {
		t.Fatal(err)
	}
	if sum != checksumBytes([]byte("artifact")) {
		t.Fatalf("checksum=%s", sum)
	}
}

func TestDownloaderRejectsRedirectToUnapprovedHost(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Redirect(w, &http.Request{}, "https://evil.example/artifact", http.StatusFound)
	}))
	defer server.Close()
	destination := filepath.Join(t.TempDir(), "artifact")
	_, err := localTLSTestDownloader(t, server).Download(context.Background(), server.URL, destination, 64, []string{serverHost(t, server.URL)})
	if err == nil || err.Error() != "artifact download request failed" {
		t.Fatalf("error=%v", err)
	}
	if _, err := os.Stat(destination); !os.IsNotExist(err) {
		t.Fatalf("destination should not exist: %v", err)
	}
}

func TestDownloaderRejectsOversizedResponse(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("0123456789")) }))
	defer server.Close()
	destination := filepath.Join(t.TempDir(), "artifact")
	_, err := localTLSTestDownloader(t, server).Download(context.Background(), server.URL, destination, 5, []string{serverHost(t, server.URL)})
	if err == nil || !strings.Contains(err.Error(), "size limit") {
		t.Fatalf("error=%v", err)
	}
}

func TestDownloaderRejectsPrivateAddress(t *testing.T) {
	d := HTTPDownloader{LookupIP: func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("127.0.0.1")}, nil
	}}
	_, err := d.Download(context.Background(), "https://artifacts.example.test/file", filepath.Join(t.TempDir(), "x"), 10, []string{"artifacts.example.test"})
	if err == nil {
		t.Fatal("expected private address rejection")
	}
}

func TestDownloaderRejectsMixedPublicAndPrivateResolution(t *testing.T) {
	dialed := false
	d := HTTPDownloader{
		LookupIP: func(context.Context, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("93.184.216.34"), net.ParseIP("169.254.169.254")}, nil
		},
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			dialed = true
			return nil, errors.New("unexpected dial")
		},
	}
	_, err := d.Download(context.Background(), "https://artifacts.example.test/file", filepath.Join(t.TempDir(), "x"), 10, []string{"artifacts.example.test"})
	if err == nil || dialed {
		t.Fatalf("error=%v dialed=%t", err, dialed)
	}
}

func TestIsPublicIP(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		want bool
	}{
		{name: "public IPv4", ip: "93.184.216.34", want: true},
		{name: "public IPv6", ip: "2606:4700:4700::1111", want: true},
		{name: "loopback", ip: "127.0.0.1"},
		{name: "private", ip: "10.0.0.1"},
		{name: "carrier grade NAT", ip: "100.64.0.1"},
		{name: "IETF protocol assignments", ip: "192.0.0.1"},
		{name: "TEST-NET-1", ip: "192.0.2.1"},
		{name: "benchmark", ip: "198.18.0.1"},
		{name: "TEST-NET-2", ip: "198.51.100.1"},
		{name: "TEST-NET-3", ip: "203.0.113.1"},
		{name: "reserved", ip: "240.0.0.1"},
		{name: "IPv6 discard-only", ip: "100::1"},
		{name: "IPv6 benchmark", ip: "2001:2::1"},
		{name: "IPv6 documentation", ip: "2001:db8::1"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := isPublicIP(net.ParseIP(test.ip)); got != test.want {
				t.Fatalf("isPublicIP(%s)=%t want=%t", test.ip, got, test.want)
			}
		})
	}
}

func TestDownloaderDoesNotLeakPresignedURL(t *testing.T) {
	secret := "presigned-top-secret"
	d := HTTPDownloader{
		LookupIP: func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP("1.1.1.1")}, nil },
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("dial failure containing " + secret)
		},
	}
	_, err := d.Download(context.Background(), "https://artifacts.example.test/file?X-Signature="+secret, filepath.Join(t.TempDir(), "x"), 10, []string{"artifacts.example.test"})
	if err == nil || strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "X-Signature") {
		t.Fatalf("unsafe error=%v", err)
	}
}

func TestDownloaderRequiresHTTPS(t *testing.T) {
	_, err := (HTTPDownloader{}).Download(context.Background(), "http://github.com/file", filepath.Join(t.TempDir(), "x"), 10, []string{"github.com"})
	if err == nil {
		t.Fatal("expected HTTP URL rejection")
	}
}

func TestPublicIPPolicyRejectsSpecialUseNetworks(t *testing.T) {
	for _, raw := range []string{
		"100.64.0.1", "192.0.0.1", "192.0.2.1", "192.31.196.1", "192.52.193.1",
		"192.88.99.1", "192.175.48.1", "198.18.0.1", "198.51.100.1",
		"203.0.113.1", "240.0.0.1", "::ffff:127.0.0.1", "::ffff:169.254.169.254",
		"64:ff9b::1", "64:ff9b:1::1", "100::1",
		"2001::1", "2001:2::1", "2001:db8::1", "2002::1", "2620:4f:8000::1",
		"3fff::1", "5f00::1", "fec0::1",
	} {
		t.Run(raw, func(t *testing.T) {
			if isPublicIP(net.ParseIP(raw)) {
				t.Fatalf("special-use address %s accepted as public", raw)
			}
		})
	}
	if !isPublicIP(net.ParseIP("1.1.1.1")) || !isPublicIP(net.ParseIP("2606:4700:4700::1111")) {
		t.Fatal("public address rejected")
	}
}

func TestDownloaderRejectsURLFragment(t *testing.T) {
	_, err := (HTTPDownloader{}).Download(context.Background(), "https://github.com/file#secret", filepath.Join(t.TempDir(), "x"), 10, []string{"github.com"})
	if err == nil {
		t.Fatal("expected URL fragment rejection")
	}
}
