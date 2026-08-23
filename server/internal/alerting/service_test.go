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
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/frp-admin/frp-admin/server/internal/domain"
	"github.com/frp-admin/frp-admin/server/internal/events"
	"github.com/frp-admin/frp-admin/server/internal/store"
	"github.com/frp-admin/frp-admin/server/internal/store/sqlstore"
	"github.com/google/uuid"
)

func privateTLSServerOptions(t *testing.T, server *httptest.Server) Options {
	t.Helper()
	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	return Options{AllowedHosts: []string{u.Hostname()}, AllowPrivateAddresses: true, Client: server.Client()}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type trackingBody struct {
	*bytes.Reader
	closed bool
}

func (b *trackingBody) Close() error { b.closed = true; return nil }

func TestWebhookIsSignedAndIdempotent(t *testing.T) {
	secret := "webhook-test-secret"
	received := make(chan struct{}, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		mac := hmac.New(sha256.New, []byte(secret))
		_, _ = mac.Write(body)
		want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
		if !hmac.Equal([]byte(r.Header.Get("X-Frp-Admin-Signature")), []byte(want)) {
			t.Error("invalid webhook signature")
		}
		if r.Header.Get("Idempotency-Key") == "" {
			t.Error("missing idempotency key")
		}
		w.WriteHeader(http.StatusNoContent)
		received <- struct{}{}
	}))
	defer server.Close()
	db, err := sqlstore.Open(context.Background(), "sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s := New(db, events.New(), slog.New(slog.NewTextHandler(io.Discard, nil)), server.URL, secret, privateTLSServerOptions(t, server))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)
	s.Trigger(context.Background(), "task_timeout", "critical", "task/test", "deadline exceeded")
	select {
	case <-received:
	case <-time.After(2 * time.Second):
		t.Fatal("webhook not delivered")
	}
	alerts, err := db.ListAlerts(context.Background(), 10, "", "open")
	if err != nil || len(alerts.Items) != 1 {
		t.Fatalf("alerts=%+v err=%v", alerts, err)
	}
}

func TestOutboxLeaseRecoveryAndDeadLetter(t *testing.T) {
	db, err := sqlstore.Open(context.Background(), "sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	failing := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer failing.Close()
	now := time.Now().UTC()
	create := func(resource string) domain.Alert {
		v := domain.Alert{ID: uuid.NewString(), Kind: "task_failed", Severity: "critical", State: "open", Resource: resource, Fingerprint: "task_failed:" + resource, Message: "failed", CreatedAt: now, UpdatedAt: now}
		if err := db.CreateAlert(store.WithWebhookDelivery(context.Background(), true), v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	create("task/dead")
	s := New(db, events.New(), slog.New(slog.NewTextHandler(io.Discard, nil)), failing.URL, "secret", privateTLSServerOptions(t, failing))
	clock := now
	s.now = func() time.Time { return clock }
	for attempt := 1; attempt <= 5; attempt++ {
		items, leaseErr := db.LeaseWebhookDeliveries(context.Background(), clock, 10*time.Second, 10)
		if leaseErr != nil || len(items) != 1 || items[0].Attempts != attempt {
			t.Fatalf("attempt=%d items=%+v err=%v", attempt, items, leaseErr)
		}
		s.deliver(context.Background(), items[0])
		clock = clock.Add(2 * time.Minute)
	}
	if items, leaseErr := db.LeaseWebhookDeliveries(context.Background(), clock.Add(time.Hour), 10*time.Second, 10); leaseErr != nil || len(items) != 0 {
		t.Fatalf("dead letter was reclaimed: %+v err=%v", items, leaseErr)
	}

	create("task/recover")
	first, err := db.LeaseWebhookDeliveries(context.Background(), clock, 10*time.Second, 10)
	if err != nil || len(first) != 1 {
		t.Fatalf("first lease=%+v err=%v", first, err)
	}
	if early, err := db.LeaseWebhookDeliveries(context.Background(), clock.Add(5*time.Second), 10*time.Second, 10); err != nil || len(early) != 0 {
		t.Fatalf("active lease reclaimed: %+v err=%v", early, err)
	}
	recovered, err := db.LeaseWebhookDeliveries(context.Background(), clock.Add(11*time.Second), 10*time.Second, 10)
	if err != nil || len(recovered) != 1 || recovered[0].Attempts != 2 {
		t.Fatalf("expired lease not recovered: %+v err=%v", recovered, err)
	}
}

func TestWebhookDisabledDoesNotAccumulateOutbox(t *testing.T) {
	db, err := sqlstore.Open(context.Background(), "sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now().UTC()
	v := domain.Alert{ID: uuid.NewString(), Kind: "task_failed", Severity: "critical", State: "open", Resource: "task/disabled", Fingerprint: "task_failed:task/disabled", Message: "failed", CreatedAt: now, UpdatedAt: now}
	if err = db.CreateAlert(context.Background(), v); err != nil {
		t.Fatal(err)
	}
	if _, err = db.UpdateAlertState(context.Background(), v.ID, "acknowledged", "operator", now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	items, err := db.LeaseWebhookDeliveries(context.Background(), now.Add(time.Hour), time.Minute, 10)
	if err != nil || len(items) != 0 {
		t.Fatalf("disabled webhook accumulated outbox: %+v err=%v", items, err)
	}
}

func TestWebhookResponseBodyIsDrainedAndClosed(t *testing.T) {
	db, err := sqlstore.Open(context.Background(), "sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now().UTC()
	v := domain.Alert{ID: uuid.NewString(), Kind: "task_failed", Severity: "critical", State: "open", Resource: "task/body", Fingerprint: "task_failed:task/body", Message: "failed", CreatedAt: now, UpdatedAt: now}
	if err = db.CreateAlert(store.WithWebhookDelivery(context.Background(), true), v); err != nil {
		t.Fatal(err)
	}
	items, err := db.LeaseWebhookDeliveries(context.Background(), now, time.Minute, 1)
	if err != nil || len(items) != 1 {
		t.Fatalf("deliveries=%+v err=%v", items, err)
	}
	body := &trackingBody{Reader: bytes.NewReader([]byte("small response body"))}
	s := New(db, events.New(), slog.New(slog.NewTextHandler(io.Discard, nil)), "https://webhook.example.test", "secret")
	s.now = func() time.Time { return now.Add(time.Second) }
	s.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusNoContent, Status: "204 No Content", Body: body, Header: make(http.Header)}, nil
	})
	s.deliver(context.Background(), items[0])
	if !body.closed || body.Len() != 0 {
		t.Fatalf("response drained=%v remaining=%d", body.closed, body.Len())
	}
}

func TestWebhookNetworkPolicy(t *testing.T) {
	if _, err := webhookClient("http://alerts.example.test/hook", Options{}); err == nil {
		t.Fatal("HTTP webhook URL accepted")
	}
	client, err := webhookClient("https://alerts.example.test/hook", Options{
		LookupIP: func(context.Context, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("127.0.0.1")}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	transport := client.Transport.(*http.Transport)
	if transport.Proxy != nil {
		t.Fatal("environment proxy remains enabled")
	}
	req, err := http.NewRequest(http.MethodPost, "https://alerts.example.test/hook?token=webhook-secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Do(req)
	if err == nil {
		t.Fatal("private webhook address accepted")
	}
}

func TestWebhookRejectsMixedDNSAnswersBeforeDial(t *testing.T) {
	dialed := make(chan string, 1)
	client, err := webhookClient("https://alerts.example.test/hook", Options{
		LookupIP: func(context.Context, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("169.254.169.254")}, nil
		},
		DialContext: func(_ context.Context, _, address string) (net.Conn, error) {
			dialed <- address
			return nil, errors.New("test dial failure")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = client.Post("https://alerts.example.test/hook", "application/json", nil); err == nil {
		t.Fatal("mixed public/private DNS answers were accepted")
	}
	select {
	case address := <-dialed:
		t.Fatalf("dial attempted before all DNS answers were validated: %s", address)
	default:
	}
}

func TestWebhookDialsValidatedIPAddress(t *testing.T) {
	dialed := make(chan string, 1)
	client, err := webhookClient("https://alerts.example.test/hook", Options{
		LookupIP: func(context.Context, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("1.1.1.1")}, nil
		},
		DialContext: func(_ context.Context, _, address string) (net.Conn, error) {
			dialed <- address
			return nil, errors.New("test dial failure")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = client.Post("https://alerts.example.test/hook", "application/json", nil)
	select {
	case address := <-dialed:
		if address != "1.1.1.1:443" {
			t.Fatalf("dial address=%s want validated IP", address)
		}
	case <-time.After(time.Second):
		t.Fatal("validated address was not dialed")
	}
}

func TestWebhookPublicIPPolicyRejectsSpecialUseNetworks(t *testing.T) {
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

func TestWebhookRedirectIsRejected(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("redirect target should not be reached")
	}))
	defer target.Close()
	source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer source.Close()
	client, err := webhookClient(source.URL, privateTLSServerOptions(t, source))
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Post(source.URL, "application/json", nil)
	if response != nil {
		_ = response.Body.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "redirects are not allowed") {
		t.Fatalf("redirect error=%v", err)
	}
}

func TestAlertStateTransitionCASAndAudit(t *testing.T) {
	db, err := sqlstore.Open(context.Background(), "sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now().UTC()
	v := domain.Alert{ID: uuid.NewString(), Kind: "task_timeout", Severity: "critical", State: "open", Resource: "task/cas", Fingerprint: "task_timeout:task/cas", Message: "timeout", CreatedAt: now, UpdatedAt: now}
	if err = db.CreateAlert(context.Background(), v); err != nil {
		t.Fatal(err)
	}
	ctx := store.WithMutationAudit(context.Background(), store.MutationAudit{Actor: "operator", Action: "alert.acknowledged", Resource: "alert/" + v.ID, RequestID: "request"})
	results := make(chan error, 2)
	for range 2 {
		go func() {
			_, updateErr := db.UpdateAlertState(ctx, v.ID, "acknowledged", "operator", now.Add(time.Second))
			results <- updateErr
		}()
	}
	success, conflict := 0, 0
	for range 2 {
		if e := <-results; e == nil {
			success++
		} else if errors.Is(e, store.ErrConflict) {
			conflict++
		} else {
			t.Fatal(e)
		}
	}
	if success != 1 || conflict != 1 {
		t.Fatalf("success=%d conflict=%d", success, conflict)
	}
	resolved, err := db.UpdateAlertState(context.Background(), v.ID, "resolved", "operator", now.Add(2*time.Second))
	if err != nil || resolved.ResolvedAt == nil {
		t.Fatalf("resolve=%+v err=%v", resolved, err)
	}
	closed, err := db.UpdateAlertState(context.Background(), v.ID, "closed", "admin", now.Add(3*time.Second))
	if err != nil || closed.ClosedAt == nil {
		t.Fatalf("close=%+v err=%v", closed, err)
	}
	if _, err = db.UpdateAlertState(context.Background(), v.ID, "acknowledged", "operator", now.Add(4*time.Second)); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("state regression err=%v", err)
	}
	recurrence := v
	recurrence.ID = uuid.NewString()
	recurrence.CreatedAt, recurrence.UpdatedAt = now.Add(5*time.Second), now.Add(5*time.Second)
	if err = db.CreateAlert(context.Background(), recurrence); err != nil {
		t.Fatalf("resolved fingerprint could not recur: %v", err)
	}
	audits, err := db.ListAuditLogs(context.Background(), domain.AuditFilter{Action: "alert.acknowledged"}, 10, "")
	if err != nil || len(audits.Items) != 1 {
		t.Fatalf("audits=%+v err=%v", audits, err)
	}
}
