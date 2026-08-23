package alerting

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/frp-admin/frp-admin/server/internal/domain"
	"github.com/frp-admin/frp-admin/server/internal/events"
	"github.com/frp-admin/frp-admin/server/internal/metrics"
	"github.com/frp-admin/frp-admin/server/internal/store"
	"github.com/google/uuid"
)

type Service struct {
	store     store.Store
	bus       *events.Bus
	logger    *slog.Logger
	url       string
	secret    []byte
	client    *http.Client
	now       func() time.Time
	poll      time.Duration
	configErr error
}

type Options struct {
	AllowedHosts          []string
	AllowPrivateAddresses bool
	Client                *http.Client
	LookupIP              func(context.Context, string) ([]net.IP, error)
	DialContext           func(context.Context, string, string) (net.Conn, error)
}

func New(s store.Store, bus *events.Bus, logger *slog.Logger, webhookURL, secret string, options ...Options) *Service {
	var option Options
	if len(options) > 0 {
		option = options[0]
	}
	client, configErr := webhookClient(webhookURL, option)
	return &Service{store: s, bus: bus, logger: logger, url: webhookURL, secret: []byte(secret), client: client, configErr: configErr, now: time.Now, poll: 250 * time.Millisecond}
}

func (s *Service) Trigger(ctx context.Context, kind, severity, resource, message string) {
	now := time.Now().UTC()
	v := domain.Alert{ID: uuid.Must(uuid.NewV7()).String(), Kind: kind, Severity: severity, State: "open", Resource: resource, Fingerprint: kind + ":" + resource, Message: message, CreatedAt: now, UpdatedAt: now}
	if err := s.store.CreateAlert(store.WithWebhookDelivery(ctx, s.url != ""), v); err != nil {
		if !errors.Is(err, store.ErrConflict) {
			s.logger.ErrorContext(ctx, "persist alert failed", "error", err, "kind", kind, "resource", resource)
		}
		return
	}
	if s.bus != nil {
		s.bus.Publish(events.Event{ID: v.ID, Type: "alert.opened", Data: []byte(`{}`)})
	}
}

func (s *Service) Run(ctx context.Context) {
	if s.url == "" {
		<-ctx.Done()
		return
	}
	s.process(ctx)
	ticker := time.NewTicker(s.poll)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.process(ctx)
		}
	}
}
func (s *Service) process(ctx context.Context) {
	now := s.now().UTC()
	items, err := s.store.LeaseWebhookDeliveries(ctx, now, 30*time.Second, 20)
	if err != nil {
		if ctx.Err() == nil {
			s.logger.ErrorContext(ctx, "lease alert webhooks failed", "error", err)
		}
		return
	}
	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	for _, v := range items {
		v := v
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
				s.deliver(ctx, v)
			case <-ctx.Done():
			}
		}()
	}
	wg.Wait()
}
func (s *Service) deliver(ctx context.Context, v domain.WebhookDelivery) {
	err := s.configErr
	var req *http.Request
	if err == nil {
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, s.url, bytes.NewReader([]byte(v.Payload)))
		if err != nil {
			err = errors.New("create webhook request failed")
		}
	}
	if err == nil {
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", v.ID)
		req.Header.Set("X-Frp-Admin-Event", v.EventType)
		mac := hmac.New(sha256.New, s.secret)
		_, _ = mac.Write([]byte(v.Payload))
		req.Header.Set("X-Frp-Admin-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
		var resp *http.Response
		resp, err = s.client.Do(req)
		if err != nil {
			err = errors.New("webhook request failed")
		}
		if err == nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
			_ = resp.Body.Close()
			if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				err = errors.New("webhook HTTP status " + http.StatusText(resp.StatusCode))
			}
		}
	}
	now := s.now().UTC()
	if err == nil {
		if completeErr := s.store.CompleteWebhookDelivery(ctx, v.ID, true, now, "", 5); completeErr != nil {
			s.logger.ErrorContext(ctx, "complete webhook delivery failed", "delivery_id", v.ID, "error", completeErr)
			return
		}
		metrics.Default.WebhookResult("success")
		return
	}
	backoff := time.Second << min(v.Attempts-1, 6)
	if completeErr := s.store.CompleteWebhookDelivery(ctx, v.ID, false, now.Add(backoff), err.Error(), 5); completeErr != nil {
		s.logger.ErrorContext(ctx, "reschedule webhook delivery failed", "delivery_id", v.ID, "error", completeErr)
		return
	}
	if v.Attempts >= 5 {
		metrics.Default.WebhookResult("dead_letter")
	} else {
		metrics.Default.WebhookResult("retry")
	}
}

func webhookClient(rawURL string, option Options) (*http.Client, error) {
	if rawURL == "" {
		return &http.Client{Timeout: 5 * time.Second}, nil
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return nil, errors.New("webhook URL must be an HTTPS URL without userinfo or fragment")
	}
	allowedHosts := option.AllowedHosts
	if len(allowedHosts) == 0 {
		allowedHosts = []string{u.Hostname()}
	}
	if option.AllowPrivateAddresses && len(option.AllowedHosts) == 0 {
		return nil, errors.New("private webhook destinations require an explicit host allowlist")
	}
	if !hostAllowed(u.Hostname(), allowedHosts) {
		return nil, errors.New("webhook host is not allowed")
	}
	base := option.Client
	if base == nil {
		base = &http.Client{Timeout: 5 * time.Second}
	}
	client := *base
	var transport *http.Transport
	if base.Transport == nil {
		transport = http.DefaultTransport.(*http.Transport).Clone()
	} else {
		configured, ok := base.Transport.(*http.Transport)
		if !ok {
			return nil, errors.New("webhook requires an HTTP transport")
		}
		transport = configured.Clone()
	}
	transport.Proxy = nil
	transport.DialTLS = nil
	transport.DialTLSContext = nil
	lookupIP := option.LookupIP
	if lookupIP == nil {
		lookupIP = func(ctx context.Context, host string) ([]net.IP, error) {
			return net.DefaultResolver.LookupIP(ctx, "ip", host)
		}
	}
	dialContext := option.DialContext
	if dialContext == nil {
		dialContext = (&net.Dialer{}).DialContext
	}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, splitErr := net.SplitHostPort(address)
		if splitErr != nil {
			return nil, errors.New("webhook destination is invalid")
		}
		ips, lookupErr := lookupIP(ctx, host)
		if lookupErr != nil || len(ips) == 0 {
			return nil, errors.New("webhook host resolution failed")
		}
		for _, ip := range ips {
			if !option.AllowPrivateAddresses && !isPublicIP(ip) {
				return nil, errors.New("webhook host resolves to a non-public address")
			}
		}
		for _, ip := range ips {
			conn, dialErr := dialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if dialErr == nil {
				return conn, nil
			}
		}
		return nil, errors.New("webhook connection failed")
	}
	client.Transport = transport
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return errors.New("webhook redirects are not allowed")
	}
	return &client, nil
}

func hostAllowed(host string, allowedHosts []string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, allowed := range allowedHosts {
		if host == strings.ToLower(strings.TrimSuffix(strings.TrimSpace(allowed), ".")) {
			return true
		}
	}
	return false
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

var nonPublicNetworks = mustParseNetworks(
	"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24",
	"192.31.196.0/24", "192.52.193.0/24", "192.88.99.0/24", "192.175.48.0/24",
	"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4",
	"64:ff9b::/96", "64:ff9b:1::/48", "100::/64", "2001::/23", "2001:2::/48",
	"2001:db8::/32", "2002::/16", "2620:4f:8000::/48", "3fff::/20", "5f00::/16", "fec0::/10",
)

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
