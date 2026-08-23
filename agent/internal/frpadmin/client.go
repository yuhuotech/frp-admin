package frpadmin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/frp-admin/frp-admin/agent/internal/config"
	agentv1 "github.com/frp-admin/frp-admin/contracts/gen/go/frpadmin/agent/v1"
)

type Error struct {
	Code agentv1.ErrorCode
	err  error
}

func NewError(code agentv1.ErrorCode, err error) *Error { return &Error{Code: code, err: err} }
func (e *Error) Error() string {
	if e.err == nil {
		return e.Code.String()
	}
	return e.err.Error()
}
func (e *Error) Unwrap() error { return e.err }

type Collector interface {
	Collect(context.Context, string) (*agentv1.RuntimeSnapshot, error)
}

type Client struct {
	role, endpoint, username, password string
	maxResponseBytes                   int64
	http                               *http.Client
	now                                func() time.Time
}

var proxyTypes = []string{"tcp", "udp", "http", "https", "tcpmux", "stcp", "sudp", "xtcp"}

func New(role string, cfg config.AdminAPI) (*Client, error) {
	parsed, err := url.Parse(cfg.Endpoint)
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{Timeout: cfg.Timeout}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, _, splitErr := net.SplitHostPort(address)
			if splitErr != nil {
				return nil, errors.New("Admin API address is invalid")
			}
			ip := net.ParseIP(host)
			if ip == nil || !ip.IsLoopback() {
				return nil, errors.New("Admin API address is not loopback")
			}
			return dialer.DialContext(ctx, network, address)
		},
		DisableKeepAlives: true,
	}
	return &Client{role: role, endpoint: strings.TrimRight(parsed.String(), "/"), username: cfg.Username,
		password: cfg.Password, maxResponseBytes: cfg.MaxResponseBytes,
		http: &http.Client{Transport: transport, Timeout: cfg.Timeout}, now: time.Now}, nil
}

func (c *Client) Collect(ctx context.Context, detail string) (*agentv1.RuntimeSnapshot, error) {
	if detail != "" && detail != "summary" && detail != "full" {
		return nil, &Error{Code: agentv1.ErrorCode_ERROR_CODE_INVALID_COMMAND, err: errors.New("runtime detail level must be summary or full")}
	}
	snapshot := &agentv1.RuntimeSnapshot{CollectedAtUnixMs: c.now().UnixMilli()}
	if c.role == "client" {
		snapshot.Role = agentv1.NodeRole_NODE_ROLE_CLIENT
		if err := c.collectClient(ctx, snapshot); err != nil {
			return nil, err
		}
	} else if c.role == "server" {
		snapshot.Role = agentv1.NodeRole_NODE_ROLE_SERVER
		if err := c.collectServer(ctx, snapshot); err != nil {
			return nil, err
		}
	} else {
		return nil, &Error{Code: agentv1.ErrorCode_ERROR_CODE_INVALID_COMMAND, err: errors.New("runtime role is invalid")}
	}
	return snapshot, nil
}

func (c *Client) get(ctx context.Context, path string, target any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint+path, nil)
	if err != nil {
		return unavailable(path)
	}
	if c.username != "" || c.password != "" {
		req.SetBasicAuth(c.username, c.password)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return unavailable(path)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return &Error{Code: agentv1.ErrorCode_ERROR_CODE_ADMIN_API_UNAVAILABLE,
			err: fmt.Errorf("Admin API %s returned HTTP %d", path, resp.StatusCode)}
	}
	reader := io.LimitReader(resp.Body, c.maxResponseBytes+1)
	data, err := io.ReadAll(reader)
	if err != nil {
		return unavailable(path)
	}
	if int64(len(data)) > c.maxResponseBytes {
		return &Error{Code: agentv1.ErrorCode_ERROR_CODE_ADMIN_API_RESPONSE_TOO_LARGE,
			err: fmt.Errorf("Admin API %s response exceeded configured limit", path)}
	}
	if err := json.Unmarshal(data, target); err != nil {
		return &Error{Code: agentv1.ErrorCode_ERROR_CODE_ADMIN_API_INVALID_RESPONSE,
			err: fmt.Errorf("Admin API %s returned invalid JSON", path)}
	}
	return nil
}

func unavailable(path string) error {
	return &Error{Code: agentv1.ErrorCode_ERROR_CODE_ADMIN_API_UNAVAILABLE,
		err: fmt.Errorf("Admin API %s is unavailable", path)}
}

type clientProxy struct {
	Name       string `json:"name"`
	Type       string `json:"type"`
	Status     string `json:"status"`
	LocalAddr  string `json:"local_addr"`
	RemoteAddr string `json:"remote_addr"`
	Error      string `json:"err"`
}

func (c *Client) collectClient(ctx context.Context, snapshot *agentv1.RuntimeSnapshot) error {
	var raw map[string]json.RawMessage
	if err := c.get(ctx, "/api/status", &raw); err != nil {
		return err
	}
	for _, proxyType := range proxyTypes {
		data, ok := raw[proxyType]
		if !ok {
			continue
		}
		var proxies []clientProxy
		if err := json.Unmarshal(data, &proxies); err != nil {
			return &Error{Code: agentv1.ErrorCode_ERROR_CODE_ADMIN_API_INVALID_RESPONSE,
				err: fmt.Errorf("Admin API /api/status returned invalid %s proxies", proxyType)}
		}
		for _, value := range proxies {
			typ := value.Type
			if typ == "" {
				typ = proxyType
			}
			snapshot.Proxies = append(snapshot.Proxies, &agentv1.RuntimeProxy{Name: clean(value.Name, 256), Type: typ,
				Status: proxyStatus(value.Status), LocalAddress: clean(value.LocalAddr, 512), RemoteAddress: clean(value.RemoteAddr, 512),
				LastError: redact(value.Error)})
		}
	}
	return nil
}

type serverProxy struct {
	Name            string          `json:"name"`
	Type            string          `json:"type"`
	Status          string          `json:"status"`
	CurrentConns    int64           `json:"cur_conns"`
	TrafficIn       int64           `json:"traffic_in"`
	TrafficOut      int64           `json:"traffic_out"`
	TodayTrafficIn  int64           `json:"today_traffic_in"`
	TodayTrafficOut int64           `json:"today_traffic_out"`
	Error           string          `json:"last_start_error"`
	Conf            json.RawMessage `json:"conf"`
}

type proxyList struct {
	Proxies []serverProxy `json:"proxies"`
}

type proxyConf struct {
	LocalIP       string   `json:"local_ip"`
	LocalPort     int      `json:"local_port"`
	RemotePort    int      `json:"remote_port"`
	CustomDomains []string `json:"custom_domains"`
}

type serverInfo struct {
	Version  string `json:"version"`
	BindAddr string `json:"bind_addr"`
	BindPort int    `json:"bind_port"`
}

type rawClient struct {
	ID               string `json:"id"`
	ClientID         string `json:"clientID"`
	RunID            string `json:"runID"`
	LegacyRunID      string `json:"run_id"`
	Address          string `json:"address"`
	ClientIP         string `json:"clientIP"`
	RemoteAddr       string `json:"remote_addr"`
	ConnectedAt      string `json:"connected_at"`
	FirstConnectedAt int64  `json:"firstConnectedAt"`
}

func (c *Client) collectServer(ctx context.Context, snapshot *agentv1.RuntimeSnapshot) error {
	var info serverInfo
	if err := c.get(ctx, "/api/serverinfo", &info); err != nil {
		return err
	}
	snapshot.FrpVersion = clean(info.Version, 128)
	snapshot.Server = &agentv1.RuntimeServer{BindAddress: clean(info.BindAddr, 256), BindPort: safePort(info.BindPort)}
	for _, proxyType := range proxyTypes {
		var list proxyList
		path := "/api/proxy/" + proxyType
		if err := c.get(ctx, path, &list); err != nil {
			return err
		}
		for _, value := range list.Proxies {
			var conf proxyConf
			if len(value.Conf) > 0 && string(value.Conf) != "null" {
				if err := json.Unmarshal(value.Conf, &conf); err != nil {
					return &Error{Code: agentv1.ErrorCode_ERROR_CODE_ADMIN_API_INVALID_RESPONSE,
						err: fmt.Errorf("Admin API %s returned invalid proxy configuration", path)}
				}
			}
			typ := value.Type
			if typ == "" {
				typ = proxyType
			}
			snapshot.Proxies = append(snapshot.Proxies, &agentv1.RuntimeProxy{Name: clean(value.Name, 256), Type: typ,
				Status: proxyStatus(value.Status), LocalAddress: joinAddress(conf.LocalIP, conf.LocalPort),
				RemoteAddress: serverRemoteAddress(info.BindAddr, conf), LastError: redact(value.Error),
				Traffic: &agentv1.RuntimeTraffic{BytesIn: nonnegative(value.TrafficIn), BytesOut: nonnegative(value.TrafficOut), TodayBytesIn: nonnegative(value.TodayTrafficIn), TodayBytesOut: nonnegative(value.TodayTrafficOut), CurrentConnections: nonnegative(value.CurrentConns)}})
		}
	}
	var clientsRaw json.RawMessage
	if err := c.get(ctx, "/api/clients", &clientsRaw); err != nil {
		return err
	}
	var clients []rawClient
	if err := json.Unmarshal(clientsRaw, &clients); err != nil {
		var clientsEnvelope struct {
			Clients []rawClient `json:"clients"`
		}
		if envelopeErr := json.Unmarshal(clientsRaw, &clientsEnvelope); envelopeErr != nil {
			return &Error{Code: agentv1.ErrorCode_ERROR_CODE_ADMIN_API_INVALID_RESPONSE,
				err: errors.New("Admin API /api/clients returned invalid client list")}
		}
		clients = clientsEnvelope.Clients
	}
	for _, value := range clients {
		id, address := value.ID, value.Address
		if id == "" {
			id = value.ClientID
		}
		if id == "" {
			id = value.RunID
		}
		if id == "" {
			id = value.LegacyRunID
		}
		if address == "" {
			address = value.ClientIP
		}
		if address == "" {
			address = value.RemoteAddr
		}
		connectedAt := parseTime(value.ConnectedAt)
		if connectedAt == 0 && value.FirstConnectedAt > 0 {
			connectedAt = value.FirstConnectedAt * 1000
		}
		snapshot.Clients = append(snapshot.Clients, &agentv1.RuntimeClient{Id: clean(id, 256), Address: clean(address, 512), ConnectedAtUnixMs: connectedAt})
	}
	snapshot.Server.ProxyCount = uint32(len(snapshot.Proxies))
	snapshot.Server.ClientCount = uint32(len(snapshot.Clients))
	return nil
}

func proxyStatus(value string) agentv1.RuntimeProxyStatus {
	switch strings.ToLower(value) {
	case "running", "online", "active":
		return agentv1.RuntimeProxyStatus_RUNTIME_PROXY_STATUS_RUNNING
	case "offline", "stopped", "inactive":
		return agentv1.RuntimeProxyStatus_RUNTIME_PROXY_STATUS_OFFLINE
	case "error", "failed":
		return agentv1.RuntimeProxyStatus_RUNTIME_PROXY_STATUS_ERROR
	default:
		return agentv1.RuntimeProxyStatus_RUNTIME_PROXY_STATUS_UNKNOWN
	}
}

func joinAddress(host string, port int) string {
	if host == "" && port == 0 {
		return ""
	}
	if port <= 0 || port > 65535 {
		return clean(host, 256)
	}
	return net.JoinHostPort(clean(host, 256), strconv.Itoa(port))
}

func serverRemoteAddress(bind string, conf proxyConf) string {
	if conf.RemotePort > 0 {
		return joinAddress(bind, conf.RemotePort)
	}
	if len(conf.CustomDomains) > 0 {
		return clean(conf.CustomDomains[0], 512)
	}
	return ""
}

func safePort(port int) uint32 {
	if port <= 0 || port > 65535 {
		return 0
	}
	return uint32(port)
}

func nonnegative(value int64) int64 {
	if value < 0 {
		return 0
	}
	return value
}

func parseTime(value string) int64 {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return 0
	}
	return parsed.UnixMilli()
}

func clean(value string, limit int) string {
	value = strings.ReplaceAll(value, "\x00", "")
	if len(value) > limit {
		value = value[:limit]
	}
	return value
}

func redact(value string) string {
	lower := strings.ToLower(value)
	for _, marker := range []string{"password=", "passwd=", "token=", "authorization:", "basic "} {
		if strings.Contains(lower, marker) {
			return "runtime error details redacted"
		}
	}
	if parsed, err := url.Parse(value); err == nil && parsed.User != nil {
		return "runtime error details redacted"
	}
	return clean(value, 512)
}
