package upgrader

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
)

type Downloader interface {
	Download(context.Context, string, string, int64, []string) (string, error)
}

type HTTPDownloader struct {
	Client      *http.Client
	LookupIP    func(context.Context, string) ([]net.IP, error)
	DialContext func(context.Context, string, string) (net.Conn, error)
}

var nonPublicNetworks = mustParseNetworks(
	"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24",
	"192.31.196.0/24", "192.52.193.0/24", "192.88.99.0/24", "192.175.48.0/24",
	"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4",
	"64:ff9b::/96", "64:ff9b:1::/48", "100::/64", "2001::/23", "2001:2::/48",
	"2001:db8::/32", "2002::/16", "2620:4f:8000::/48", "3fff::/20", "5f00::/16", "fec0::/10",
)

func (d HTTPDownloader) Download(ctx context.Context, rawURL, destination string, maxBytes int64, allowedHosts []string) (string, error) {
	if err := validateURL(rawURL, allowedHosts); err != nil {
		return "", err
	}
	base := d.Client
	if base == nil {
		base = &http.Client{}
	}
	client := *base
	transport, err := cloneTransport(base.Transport)
	if err != nil {
		return "", err
	}
	transport.Proxy = nil
	transport.DialTLS = nil
	transport.DialTLSContext = nil
	lookupIP := d.LookupIP
	if lookupIP == nil {
		lookupIP = func(ctx context.Context, host string) ([]net.IP, error) {
			return net.DefaultResolver.LookupIP(ctx, "ip", host)
		}
	}
	dialContext := d.DialContext
	if dialContext == nil {
		dialContext = (&net.Dialer{}).DialContext
	}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, splitErr := net.SplitHostPort(address)
		if splitErr != nil {
			return nil, errors.New("artifact destination is invalid")
		}
		ips, lookupErr := lookupIP(ctx, host)
		if lookupErr != nil || len(ips) == 0 {
			return nil, errors.New("artifact host resolution failed")
		}
		for _, ip := range ips {
			if !isPublicIP(ip) {
				return nil, errors.New("artifact host resolves to a non-public address")
			}
		}
		var lastErr error
		for _, ip := range ips {
			conn, dialErr := dialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if dialErr == nil {
				return conn, nil
			}
			lastErr = dialErr
		}
		_ = lastErr
		return nil, errors.New("artifact connection failed")
	}
	client.Transport = transport
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return errors.New("too many redirects")
		}
		return validateURL(req.URL.String(), allowedHosts)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", errors.New("create artifact request failed")
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", errors.New("artifact download request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("artifact HTTP status %d", resp.StatusCode)
	}
	if resp.ContentLength > maxBytes {
		return "", fmt.Errorf("artifact exceeds size limit")
	}
	f, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return "", err
	}
	ok := false
	defer func() {
		f.Close()
		if !ok {
			os.Remove(destination)
		}
	}()
	hash := sha256.New()
	written, err := io.Copy(io.MultiWriter(f, hash), io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return "", err
	}
	if written > maxBytes {
		return "", fmt.Errorf("artifact exceeds size limit")
	}
	if err := f.Sync(); err != nil {
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	ok = true
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func cloneTransport(roundTripper http.RoundTripper) (*http.Transport, error) {
	if roundTripper == nil {
		return http.DefaultTransport.(*http.Transport).Clone(), nil
	}
	transport, ok := roundTripper.(*http.Transport)
	if !ok {
		return nil, errors.New("artifact downloader requires an HTTP transport")
	}
	return transport.Clone(), nil
}

func isPublicIP(ip net.IP) bool {
	if ip == nil || !ip.IsGlobalUnicast() || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	for _, network := range nonPublicNetworks {
		if network.Contains(ip) {
			return false
		}
	}
	return true
}

func mustParseNetworks(values ...string) []*net.IPNet {
	networks := make([]*net.IPNet, 0, len(values))
	for _, value := range values {
		_, network, err := net.ParseCIDR(value)
		if err != nil {
			panic(err)
		}
		networks = append(networks, network)
	}
	return networks
}

func validateURL(rawURL string, allowedHosts []string) error {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return errors.New("artifact URL must be an HTTPS URL without userinfo or fragment")
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	for _, allowed := range allowedHosts {
		if host == strings.ToLower(strings.TrimSuffix(allowed, ".")) {
			return nil
		}
	}
	return fmt.Errorf("artifact host %q is not allowed", host)
}
