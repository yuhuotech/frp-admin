package channel

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/frp-admin/frp-admin/agent/internal/certmgr"
	"github.com/frp-admin/frp-admin/agent/internal/config"
	"github.com/frp-admin/frp-admin/agent/internal/executor"
	agentv1 "github.com/frp-admin/frp-admin/contracts/gen/go/frpadmin/agent/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type Client struct {
	cfg          config.Config
	version      string
	executor     *executor.Executor
	certs        *certmgr.Manager
	capabilities []string
}

func (c *Client) WithCertificateManager(certs *certmgr.Manager) *Client { c.certs = certs; return c }
func (c *Client) WithCapabilities(values ...string) *Client {
	c.capabilities = append([]string(nil), values...)
	return c
}

func New(cfg config.Config, version string, executor *executor.Executor) *Client {
	return &Client{cfg: cfg, version: version, executor: executor}
}

func (c *Client) Run(ctx context.Context) error {
	delay := c.cfg.Channel.ReconnectMin
	for ctx.Err() == nil {
		err := c.connect(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err == nil {
			delay = c.cfg.Channel.ReconnectMin
		}
		jitter := time.Duration(rand.Int64N(max(1, int64(delay/5))))
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay + jitter):
		}
		delay = min(delay*2, c.cfg.Channel.ReconnectMax)
	}
	return ctx.Err()
}

func (c *Client) connect(ctx context.Context) error {
	sessionCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	creds, err := c.credentials()
	if err != nil {
		return err
	}
	target, err := c.cfg.GRPCTarget()
	if err != nil {
		return err
	}
	conn, err := grpc.NewClient(target, grpc.WithTransportCredentials(creds))
	if err != nil {
		return err
	}
	defer conn.Close()
	stream, err := agentv1.NewAgentControlServiceClient(conn).Connect(sessionCtx)
	if err != nil {
		return err
	}
	out := make(chan *agentv1.AgentToServer, 32)
	errCh := make(chan error, 2)
	welcomeCh := make(chan *agentv1.Welcome, 1)
	go func() {
		for {
			select {
			case <-sessionCtx.Done():
				errCh <- sessionCtx.Err()
				return
			case msg := <-out:
				if err := stream.Send(msg); err != nil {
					errCh <- err
					return
				}
			}
		}
	}()
	go c.receive(sessionCtx, stream, out, welcomeCh, errCh)
	role := agentv1.NodeRole_NODE_ROLE_CLIENT
	if c.cfg.Role == "server" {
		role = agentv1.NodeRole_NODE_ROLE_SERVER
	}
	out <- &agentv1.AgentToServer{Payload: &agentv1.AgentToServer_Hello{Hello: &agentv1.Hello{
		NodeId: c.cfg.NodeID, BootId: bootID(), AgentVersion: c.version, Role: role, ProtocolVersion: 1,
		Capabilities: helloCapabilities(c.capabilities),
	}}}
	var welcome *agentv1.Welcome
	select {
	case <-sessionCtx.Done():
		return sessionCtx.Err()
	case err := <-errCh:
		return err
	case welcome = <-welcomeCh:
	}
	sessionID, interval, err := welcomeSettings(welcome, c.cfg.Channel.HeartbeatInterval)
	if err != nil {
		return err
	}
	c.sendRotationRequest(out)
	c.sendInventory(sessionCtx, out)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	inventoryTicker := time.NewTicker(5 * time.Minute)
	defer inventoryTicker.Stop()
	certificateTicker := time.NewTicker(12 * time.Hour)
	defer certificateTicker.Stop()
	var sequence atomic.Uint64
	for {
		select {
		case <-sessionCtx.Done():
			return sessionCtx.Err()
		case err := <-errCh:
			return err
		case <-ticker.C:
			out <- heartbeatMessage(sessionID, sequence.Add(1), time.Now())
		case <-inventoryTicker.C:
			c.sendInventory(sessionCtx, out)
		case <-certificateTicker.C:
			c.sendRotationRequest(out)
		}
	}
}

func helloCapabilities(extra []string) []string {
	seen := make(map[string]struct{}, len(extra))
	result := make([]string, 0, len(extra))
	for _, value := range extra {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func (c *Client) sendInventory(ctx context.Context, out chan<- *agentv1.AgentToServer) {
	inventory, err := c.executor.CollectInventory(ctx)
	if err != nil {
		slog.Warn("inventory collection failed", "error", err)
		return
	}
	out <- &agentv1.AgentToServer{Payload: &agentv1.AgentToServer_Inventory{Inventory: inventory}}
}

func (c *Client) sendRotationRequest(out chan<- *agentv1.AgentToServer) {
	if c.certs == nil {
		return
	}
	request, err := c.certs.RotationRequest(time.Now())
	if err != nil {
		slog.Error("certificate rotation request failed", "error", err)
		return
	}
	if request != nil {
		out <- &agentv1.AgentToServer{Payload: &agentv1.AgentToServer_CertificateRotationRequest{CertificateRotationRequest: request}}
	}
}

func (c *Client) receive(ctx context.Context, stream grpc.BidiStreamingClient[agentv1.AgentToServer, agentv1.ServerToAgent], out chan<- *agentv1.AgentToServer, welcome chan<- *agentv1.Welcome, errCh chan<- error) {
	var running sync.Map
	defer running.Range(func(_, value any) bool {
		value.(context.CancelCauseFunc)(context.Canceled)
		return true
	})
	for {
		msg, err := stream.Recv()
		if err != nil {
			if err == io.EOF {
				err = fmt.Errorf("server closed stream")
			}
			errCh <- err
			return
		}
		if value := msg.GetWelcome(); value != nil {
			select {
			case welcome <- value:
			default:
			}
			continue
		}
		if value := msg.GetRotateCertificate(); value != nil {
			if c.certs == nil {
				slog.Error("received certificate rotation without certificate manager")
			} else if err := c.certs.Apply(value, time.Now()); err != nil {
				slog.Error("certificate rotation failed; retaining current certificate", "error", err)
			}
			continue
		}
		if value := msg.GetCancelCommand(); value != nil {
			if cancel, ok := running.Load(value.GetCommandId()); ok {
				cancel.(context.CancelCauseFunc)(executor.ErrCommandCancelled)
			}
			continue
		}
		command := msg.GetCommand()
		if command == nil {
			continue
		}
		_, replayed, _ := c.executor.Cached(command)
		out <- &agentv1.AgentToServer{Payload: &agentv1.AgentToServer_CommandAck{CommandAck: &agentv1.CommandAck{
			CommandId: command.GetCommandId(), ReceivedAtUnixMs: time.Now().UnixMilli(), Replayed: replayed,
		}}}
		commandCtx := ctx
		deadlineCancel := func() {}
		if command.GetExpiresAtUnixMs() > 0 {
			commandCtx, deadlineCancel = context.WithDeadlineCause(ctx, time.UnixMilli(command.GetExpiresAtUnixMs()), executor.ErrCommandExpired)
		}
		commandCtx, commandCancel := context.WithCancelCause(commandCtx)
		running.Store(command.GetCommandId(), commandCancel)
		go func(cmd *agentv1.Command) {
			defer running.Delete(cmd.GetCommandId())
			defer commandCancel(context.Canceled)
			defer deadlineCancel()
			out <- &agentv1.AgentToServer{Payload: &agentv1.AgentToServer_CommandProgress{CommandProgress: &agentv1.CommandProgress{
				CommandId: cmd.GetCommandId(), Percent: 10, Stage: "running", OccurredAtUnixMs: time.Now().UnixMilli(),
			}}}
			result := c.executor.Execute(commandCtx, cmd)
			out <- &agentv1.AgentToServer{Payload: &agentv1.AgentToServer_CommandResult{CommandResult: result}}
		}(command)
	}
}

func heartbeatMessage(sessionID string, sequence uint64, now time.Time) *agentv1.AgentToServer {
	return &agentv1.AgentToServer{Payload: &agentv1.AgentToServer_Heartbeat{Heartbeat: &agentv1.Heartbeat{
		SentAtUnixMs: now.UnixMilli(), SessionId: sessionID, Sequence: sequence,
	}}}
}

func welcomeSettings(welcome *agentv1.Welcome, fallback time.Duration) (string, time.Duration, error) {
	if welcome.GetSessionId() == "" {
		return "", 0, fmt.Errorf("welcome did not include a session id")
	}
	if welcome.GetHeartbeatIntervalSeconds() > 0 {
		fallback = time.Duration(welcome.GetHeartbeatIntervalSeconds()) * time.Second
	}
	return welcome.GetSessionId(), fallback, nil
}

func (c *Client) credentials() (credentials.TransportCredentials, error) {
	var cert tls.Certificate
	var err error
	if c.certs != nil {
		cert, err = c.certs.LoadKeyPair()
	} else {
		cert, err = tls.LoadX509KeyPair(c.cfg.TLS.CertFile, c.cfg.TLS.KeyFile)
	}
	if err != nil {
		return nil, err
	}
	ca, err := os.ReadFile(c.cfg.TLS.CAFile)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, fmt.Errorf("invalid CA certificate")
	}
	return credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: pool,
		ServerName: c.cfg.TLS.ServerName, MinVersion: tls.VersionTLS13}), nil
}

func bootID() string {
	b, _ := os.ReadFile("/proc/sys/kernel/random/boot_id")
	return strings.TrimSpace(string(b))
}
