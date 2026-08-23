package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/frp-admin/frp-admin/server/internal/auth"
	"github.com/frp-admin/frp-admin/server/internal/configuration"
	"github.com/frp-admin/frp-admin/server/internal/domain"
	"github.com/frp-admin/frp-admin/server/internal/events"
	"github.com/frp-admin/frp-admin/server/internal/metrics"
	"github.com/frp-admin/frp-admin/server/internal/node"
	"github.com/frp-admin/frp-admin/server/internal/risk"
	"github.com/frp-admin/frp-admin/server/internal/secretmgr"
	"github.com/frp-admin/frp-admin/server/internal/store"
	"github.com/frp-admin/frp-admin/server/internal/task"
	"github.com/frp-admin/frp-admin/server/internal/upgrade"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
)

const sessionCookie = "frp_admin_session"
const csrfCookie = "csrf_token"

type contextKey string

const principalKey contextKey = "principal"

type principal struct {
	User    domain.User
	Session domain.Session
}
type API struct {
	auth           *auth.Service
	nodes          *node.Service
	tasks          *task.Service
	upgrades       *upgrade.Service
	configs        *configuration.Service
	secrets        *secretmgr.Service
	risks          *risk.Service
	store          store.Store
	events         *events.Bus
	logger         *slog.Logger
	secureCookies  bool
	agentCAPEM     []byte
	loginLimiter   *loginLimiter
	webhookEnabled bool
}

func New(a *auth.Service, n *node.Service, t *task.Service, u *upgrade.Service, c *configuration.Service, secrets *secretmgr.Service, risks *risk.Service, s store.Store, b *events.Bus, l *slog.Logger, secure bool, agentCAPEM []byte, webhook ...bool) http.Handler {
	api := &API{auth: a, nodes: n, tasks: t, upgrades: u, configs: c, secrets: secrets, risks: risks, store: s, events: b, logger: l, secureCookies: secure, agentCAPEM: append([]byte(nil), agentCAPEM...), loginLimiter: newLoginLimiter()}
	if len(webhook) > 0 {
		api.webhookEnabled = webhook[0]
	}
	r := chi.NewRouter()
	r.Use(middleware.Recoverer, api.requestID, api.accessLog)
	r.Get("/health/live", api.live)
	r.Get("/health/ready", api.ready)
	r.Route("/api/v1", func(r chi.Router) {
		r.Get("/auth/bootstrap-status", api.bootstrapStatus)
		r.Post("/auth/bootstrap", api.bootstrap)
		r.Post("/auth/login", api.login)
		r.Group(func(r chi.Router) {
			r.Use(api.authenticate)
			r.Post("/auth/logout", api.csrf(api.logout))
			r.Get("/users/me", api.me)
			r.Get("/events", api.sse)
			r.Get("/nodes", api.listNodes)
			r.Get("/nodes/{id}", api.getNode)
			r.With(api.requireRoles("admin")).Patch("/nodes/{id}/management-mode", api.csrf(api.setNodeManagementMode))
			r.Get("/nodes/{id}/runtime", api.getNodeRuntime)
			r.With(api.requireRoles("admin", "operator")).Post("/nodes/{id}/inspect", api.csrf(api.inspectNode))
			r.With(api.requireRoles("admin", "operator")).Post("/nodes/{id}/runtime-collections", api.csrf(api.collectNodeRuntime))
			r.With(api.requireRoles("admin", "operator")).Post("/nodes/{id}/risk-scans", api.csrf(api.scanNodeRisks))
			r.With(api.requireRoles("admin", "operator", "viewer", "auditor")).Get("/risks", api.listRisks)
			r.With(api.requireRoles("admin", "operator")).Post("/risks/{id}/repairs", api.csrf(api.repairRisk))
			r.With(api.requireRoles("admin", "operator")).Post("/nodes/{id}/service-actions", api.csrf(api.serviceAction))
			r.Get("/nodes/{id}/config-revisions", api.listConfigRevisions)
			r.With(api.requireRoles("admin", "operator")).Post("/nodes/{id}/config-revisions", api.csrf(api.createConfigRevision))
			r.With(api.requireRoles("admin", "operator")).Post("/config-revisions/{id}/deploy", api.csrf(api.deployConfigRevision))
			r.With(api.requireRoles("admin", "operator")).Post("/nodes/{id}/config-rollbacks", api.csrf(api.rollbackConfig))
			r.With(api.requireRoles("admin")).Post("/nodes/enrollment-tokens", api.csrf(api.createEnrollmentToken))
			r.Get("/tasks", api.listTasks)
			r.Get("/tasks/{id}", api.getTask)
			r.With(api.requireRoles("admin", "operator")).Post("/tasks/{id}/cancel", api.csrf(api.cancelTask))
			r.Get("/upgrade-plans", api.listUpgradePlans)
			r.Get("/upgrade-plans/{id}", api.getUpgradePlan)
			r.With(api.requireRoles("admin", "operator")).Post("/upgrade-plans", api.csrf(api.createUpgradePlan))
			r.With(api.requireRoles("admin", "operator")).Post("/upgrade-plans/{id}/cancel", api.csrf(api.cancelUpgradePlan))
			r.Get("/proxies", api.listRuntimeProxies)
			r.Get("/proxies/{nodeId}/{name}", api.getRuntimeProxy)
			r.With(api.requireRoles("admin", "operator", "viewer", "auditor")).Get("/alerts", api.listAlerts)
			r.With(api.requireRoles("admin", "operator")).Post("/alerts/{id}/acknowledge", api.csrf(api.acknowledgeAlert))
			r.With(api.requireRoles("admin", "operator")).Post("/alerts/{id}/resolve", api.csrf(api.resolveAlert))
			r.With(api.requireRoles("admin")).Post("/alerts/{id}/close", api.csrf(api.closeAlert))
			r.With(api.requireRoles("admin")).Get("/system/agent-ca", api.downloadAgentCA)
			r.With(api.requireRoles("admin", "operator")).Get("/secrets", api.listSecrets)
			r.With(api.requireRoles("admin", "operator")).Post("/secrets", api.csrf(api.createSecret))
			r.With(api.requireRoles("admin", "operator")).Put("/secrets/{id}", api.csrf(api.updateSecret))
			r.With(api.requireRoles("admin")).Get("/users", api.listUsers)
			r.With(api.requireRoles("admin")).Post("/users", api.csrf(api.createUser))
			r.With(api.requireRoles("admin")).Patch("/users/{id}", api.csrf(api.updateUser))
			r.With(api.requireRoles("admin", "auditor")).Get("/audit-logs", api.listAuditLogs)
			r.With(api.requireRoles("admin", "operator")).Get("/config-revisions/{id}/content", api.getConfigContent)
		})
	})
	return r
}

func (a *API) downloadAgentCA(w http.ResponseWriter, r *http.Request) {
	if len(a.agentCAPEM) == 0 {
		problem(w, r, http.StatusServiceUnavailable, "Agent CA unavailable", nil)
		return
	}
	p := mustPrincipal(r.Context())
	_ = a.store.AppendAudit(r.Context(), p.User.ID, "agent_ca.download", "system/agent-ca", requestID(r.Context()))
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="frp-admin-agent-ca.crt"`)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(a.agentCAPEM)
}

func (a *API) requestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimSpace(r.Header.Get("X-Request-ID"))
		if id == "" {
			id = uuid.NewString()
		}
		w.Header().Set("X-Request-ID", id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestIDKey, id)))
	})
}

const requestIDKey contextKey = "request_id"

func (a *API) accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(ww, r)
		elapsed := time.Since(start)
		metrics.Default.ObserveHTTP(r.Method, ww.Status(), elapsed)
		a.logger.InfoContext(r.Context(), "http request", "method", r.Method, "path", r.URL.Path, "status", ww.Status(), "duration_ms", elapsed.Milliseconds(), "request_id", requestID(r.Context()))
	})
}
func requestID(ctx context.Context) string { v, _ := ctx.Value(requestIDKey).(string); return v }
func (a *API) live(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}
func (a *API) ready(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if e := a.store.Ping(ctx); e != nil {
		problem(w, r, http.StatusServiceUnavailable, "database unavailable", e)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ready"})
}

type credentialsRequest struct {
	Username       string `json:"username"`
	Password       string `json:"password"`
	BootstrapToken string `json:"bootstrapToken"`
}

func (a *API) bootstrapStatus(w http.ResponseWriter, r *http.Request) {
	required, err := a.auth.NeedsBootstrap(r.Context())
	if err != nil {
		problem(w, r, http.StatusInternalServerError, "load bootstrap status failed", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"required": required})
}

func (a *API) bootstrap(w http.ResponseWriter, r *http.Request) {
	var in credentialsRequest
	if !decode(w, r, &in) {
		return
	}
	u, e := a.auth.Bootstrap(r.Context(), in.BootstrapToken, auth.Credentials{Username: in.Username, Password: in.Password})
	if e != nil {
		status := http.StatusBadRequest
		if errors.Is(e, auth.ErrInvalidCredentials) {
			status = http.StatusUnauthorized
		}
		if errors.Is(e, auth.ErrBootstrapDisabled) {
			status = http.StatusConflict
		}
		problem(w, r, status, "bootstrap failed", e)
		return
	}
	_ = a.store.AppendAudit(r.Context(), u.ID, "auth.bootstrap", "user/"+u.ID, requestID(r.Context()))
	writeJSON(w, http.StatusCreated, userDTO(u))
}
func (a *API) login(w http.ResponseWriter, r *http.Request) {
	var in credentialsRequest
	if !decode(w, r, &in) {
		return
	}
	key := loginKey(r.RemoteAddr, in.Username)
	if !a.loginLimiter.allowed(key) {
		w.Header().Set("Retry-After", "900")
		problem(w, r, http.StatusTooManyRequests, "too many authentication attempts", nil)
		return
	}
	u, t, e := a.auth.Login(r.Context(), auth.Credentials{Username: in.Username, Password: in.Password})
	if e != nil {
		if a.loginLimiter.recordFailure(key) {
			w.Header().Set("Retry-After", "900")
			problem(w, r, http.StatusTooManyRequests, "too many authentication attempts", nil)
			return
		}
		problem(w, r, http.StatusUnauthorized, "authentication failed", auth.ErrInvalidCredentials)
		return
	}
	a.loginLimiter.reset(key)
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: t.SessionToken, Path: "/", HttpOnly: true, Secure: a.secureCookies, SameSite: http.SameSiteLaxMode, Expires: t.ExpiresAt})
	http.SetCookie(w, &http.Cookie{Name: csrfCookie, Value: t.CSRFToken, Path: "/", HttpOnly: false, Secure: a.secureCookies, SameSite: http.SameSiteLaxMode, Expires: t.ExpiresAt})
	_ = a.store.AppendAudit(r.Context(), u.ID, "auth.login", "session", requestID(r.Context()))
	writeJSON(w, http.StatusOK, userDTO(u))
}
func (a *API) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, e := r.Cookie(sessionCookie)
		if e != nil {
			problem(w, r, http.StatusUnauthorized, "authentication required", nil)
			return
		}
		u, s, e := a.auth.Authenticate(r.Context(), c.Value)
		if e != nil {
			problem(w, r, http.StatusUnauthorized, "authentication required", nil)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalKey, principal{User: u, Session: s})))
	})
}
func (a *API) csrf(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p := mustPrincipal(r.Context())
		if !auth.VerifyCSRF(p.Session, r.Header.Get("X-CSRF-Token")) {
			problem(w, r, http.StatusForbidden, "invalid CSRF token", nil)
			return
		}
		next(w, r)
	}
}
func (a *API) requireRoles(roles ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !auth.Allowed(mustPrincipal(r.Context()).User.Role, roles...) {
				problem(w, r, http.StatusForbidden, "insufficient permissions", nil)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
func mustPrincipal(ctx context.Context) principal { return ctx.Value(principalKey).(principal) }
func (a *API) logout(w http.ResponseWriter, r *http.Request) {
	p := mustPrincipal(r.Context())
	if e := a.auth.Logout(r.Context(), p.Session.ID); e != nil {
		problem(w, r, http.StatusInternalServerError, "logout failed", e)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", HttpOnly: true, Secure: a.secureCookies, SameSite: http.SameSiteLaxMode, MaxAge: -1})
	http.SetCookie(w, &http.Cookie{Name: csrfCookie, Value: "", Path: "/", HttpOnly: false, Secure: a.secureCookies, SameSite: http.SameSiteLaxMode, MaxAge: -1})
	_ = a.store.AppendAudit(r.Context(), p.User.ID, "auth.logout", "session/"+p.Session.ID, requestID(r.Context()))
	w.WriteHeader(http.StatusNoContent)
}
func (a *API) me(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, userDTO(mustPrincipal(r.Context()).User))
}

func (a *API) listNodes(w http.ResponseWriter, r *http.Request) {
	page, e := a.nodes.List(r.Context(), queryInt(r, "limit"), r.URL.Query().Get("cursor"))
	if e != nil {
		problem(w, r, http.StatusInternalServerError, "list nodes failed", e)
		return
	}
	items := make([]any, 0, len(page.Items))
	for _, v := range page.Items {
		items = append(items, nodeDTO(v))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": page.NextCursor})
}
func (a *API) getNode(w http.ResponseWriter, r *http.Request) {
	v, e := a.nodes.Get(r.Context(), chi.URLParam(r, "id"))
	if e != nil {
		storeProblem(w, r, "node", e)
		return
	}
	writeJSON(w, http.StatusOK, nodeDTO(v))
}

type managementModeRequest struct {
	Mode string `json:"mode"`
}

func (a *API) setNodeManagementMode(w http.ResponseWriter, r *http.Request) {
	var in managementModeRequest
	if !decode(w, r, &in) {
		return
	}
	p := mustPrincipal(r.Context())
	ctx := store.WithMutationAudit(r.Context(), store.MutationAudit{Actor: p.User.ID, RequestID: requestID(r.Context())})
	v, err := a.nodes.SetManagementMode(ctx, chi.URLParam(r, "id"), strings.TrimSpace(in.Mode))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			problem(w, r, http.StatusNotFound, "node not found", nil)
		} else if errors.Is(err, store.ErrConflict) {
			problem(w, r, http.StatusConflict, "active managed tasks must be cancelled before switching to observe mode", err)
		} else {
			problem(w, r, http.StatusBadRequest, "update node management mode failed", err)
		}
		return
	}
	writeJSON(w, http.StatusOK, nodeDTO(v))
}
func (a *API) inspectNode(w http.ResponseWriter, r *http.Request) {
	p := mustPrincipal(r.Context())
	ctx := store.WithMutationAudit(r.Context(), store.MutationAudit{Actor: p.User.ID, RequestID: requestID(r.Context())})
	v, e := a.tasks.Inspect(ctx, chi.URLParam(r, "id"), p.User.ID, r.Header.Get("Idempotency-Key"))
	if e != nil {
		if errors.Is(e, store.ErrNotFound) {
			problem(w, r, http.StatusNotFound, "node not found", nil)
		} else if errors.Is(e, store.ErrConflict) {
			problem(w, r, http.StatusConflict, "duplicate operation", e)
		} else if errors.Is(e, store.ErrObserveOnly) {
			problem(w, r, http.StatusConflict, "node is in observe mode", e)
		} else if errors.Is(e, store.ErrCapabilityUnavailable) {
			problem(w, r, http.StatusConflict, "the Agent does not support inspect", e)
		} else {
			problem(w, r, http.StatusInternalServerError, "create inspect task failed", e)
		}
		return
	}
	writeJSON(w, http.StatusAccepted, taskDTO(v))
}

func (a *API) scanNodeRisks(w http.ResponseWriter, r *http.Request) {
	p := mustPrincipal(r.Context())
	ctx := store.WithMutationAudit(r.Context(), store.MutationAudit{Actor: p.User.ID, RequestID: requestID(r.Context())})
	v, err := a.risks.Scan(ctx, chi.URLParam(r, "id"), p.User.ID, r.Header.Get("Idempotency-Key"))
	if err != nil {
		if errors.Is(err, risk.ErrIdempotencyRequired) {
			problem(w, r, http.StatusBadRequest, "Idempotency-Key is required", nil)
		} else if errors.Is(err, store.ErrNotFound) {
			problem(w, r, http.StatusNotFound, "node not found", nil)
		} else if errors.Is(err, store.ErrConflict) {
			problem(w, r, http.StatusConflict, "duplicate risk scan", nil)
		} else if errors.Is(err, risk.ErrCapabilityUnavailable) {
			problem(w, r, http.StatusConflict, "the connected Agent does not support risk scanning", nil)
		} else {
			problem(w, r, http.StatusInternalServerError, "create risk scan failed", err)
		}
		return
	}
	writeJSON(w, http.StatusAccepted, taskDTO(v))
}

func (a *API) listRisks(w http.ResponseWriter, r *http.Request) {
	filter := domain.DeploymentRiskFilter{NodeID: strings.TrimSpace(r.URL.Query().Get("node_id")), Kind: strings.TrimSpace(r.URL.Query().Get("kind")), State: strings.TrimSpace(r.URL.Query().Get("state"))}
	page, err := a.risks.List(r.Context(), filter, normalizedLimit(queryInt(r, "limit")), r.URL.Query().Get("cursor"))
	if err != nil {
		problem(w, r, http.StatusInternalServerError, "list deployment risks failed", err)
		return
	}
	items := make([]any, 0, len(page.Items))
	for _, item := range page.Items {
		items = append(items, riskDTO(item))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": page.NextCursor})
}

type repairRiskRequest struct {
	Action               string `json:"action"`
	MaintenanceConfirmed bool   `json:"maintenance_confirmed"`
}

func (a *API) repairRisk(w http.ResponseWriter, r *http.Request) {
	var in repairRiskRequest
	if !decode(w, r, &in) {
		return
	}
	p := mustPrincipal(r.Context())
	ctx := store.WithMutationAudit(r.Context(), store.MutationAudit{Actor: p.User.ID, RequestID: requestID(r.Context())})
	v, err := a.risks.Repair(ctx, chi.URLParam(r, "id"), risk.RepairRequest{Action: in.Action, MaintenanceConfirmed: in.MaintenanceConfirmed}, p.User.ID, p.User.Role, r.Header.Get("Idempotency-Key"))
	if err != nil {
		switch {
		case errors.Is(err, store.ErrNotFound):
			problem(w, r, http.StatusNotFound, "deployment risk not found", nil)
		case errors.Is(err, store.ErrObserveOnly):
			problem(w, r, http.StatusConflict, "node is in observe mode", nil)
		case errors.Is(err, store.ErrConflict):
			problem(w, r, http.StatusConflict, "deployment risk changed or another mutation is active", nil)
		case errors.Is(err, risk.ErrAdminRequired):
			problem(w, r, http.StatusForbidden, "administrator role is required", nil)
		case errors.Is(err, risk.ErrMaintenanceConfirmationRequired):
			problem(w, r, http.StatusPreconditionRequired, "maintenance impact confirmation is required", nil)
		case errors.Is(err, risk.ErrIdempotencyRequired):
			problem(w, r, http.StatusBadRequest, "Idempotency-Key is required", nil)
		case errors.Is(err, risk.ErrRescanRequired):
			problem(w, r, http.StatusConflict, "a fresh risk scan is required before repair", nil)
		case errors.Is(err, risk.ErrDesiredRevisionRequired), errors.Is(err, configuration.ErrDesiredRevisionDrift):
			problem(w, r, http.StatusConflict, "an in-sync managed desired revision is required before this repair", nil)
		case errors.Is(err, risk.ErrCapabilityUnavailable):
			problem(w, r, http.StatusConflict, "the connected Agent does not support this repair", nil)
		default:
			problem(w, r, http.StatusBadRequest, "create deployment risk repair failed", nil)
		}
		return
	}
	writeJSON(w, http.StatusAccepted, taskDTO(v))
}

func riskDTO(v domain.DeploymentRisk) any {
	allowed := []string{}
	if v.State == "open" {
		allowed = risk.AllowedActions(v.Kind)
	}
	return map[string]any{"id": v.ID, "node_id": v.NodeID, "kind": v.Kind, "severity": v.Severity, "state": v.State, "evidence": v.Evidence, "confidence": v.Confidence, "rule_version": v.RuleVersion, "first_seen_at": v.FirstSeenAt, "last_seen_at": v.LastSeenAt, "pending_confirmation_at": v.PendingConfirmationAt, "resolved_at": v.ResolvedAt, "repair_task_id": v.RepairTaskID, "repairable": len(allowed) > 0, "allowed_actions": allowed}
}

type serviceActionRequest struct {
	Action string `json:"action"`
}

func (a *API) serviceAction(w http.ResponseWriter, r *http.Request) {
	var in serviceActionRequest
	if !decode(w, r, &in) {
		return
	}
	p := mustPrincipal(r.Context())
	ctx := store.WithMutationAudit(r.Context(), store.MutationAudit{Actor: p.User.ID, RequestID: requestID(r.Context())})
	v, e := a.tasks.ServiceAction(ctx, chi.URLParam(r, "id"), in.Action, p.User.ID, r.Header.Get("Idempotency-Key"))
	if e != nil {
		if errors.Is(e, store.ErrNotFound) {
			problem(w, r, http.StatusNotFound, "node not found", nil)
		} else if errors.Is(e, store.ErrConflict) {
			problem(w, r, http.StatusConflict, "duplicate operation", e)
		} else if errors.Is(e, store.ErrObserveOnly) {
			problem(w, r, http.StatusConflict, "node is in observe mode", e)
		} else if errors.Is(e, store.ErrCapabilityUnavailable) {
			problem(w, r, http.StatusConflict, "the Agent does not support this service action", e)
		} else {
			problem(w, r, http.StatusBadRequest, "create service action failed", e)
		}
		return
	}
	writeJSON(w, http.StatusAccepted, taskDTO(v))
}

type createConfigRequest struct {
	Content  string `json:"content"`
	Format   string `json:"format"`
	Strategy string `json:"strategy"`
}

func (a *API) createConfigRevision(w http.ResponseWriter, r *http.Request) {
	var in createConfigRequest
	if !decode(w, r, &in) {
		return
	}
	if in.Format != "" && in.Format != "toml" {
		problem(w, r, http.StatusBadRequest, "unsupported configuration format", nil)
		return
	}
	p := mustPrincipal(r.Context())
	ctx := store.WithMutationAudit(r.Context(), store.MutationAudit{Actor: p.User.ID, RequestID: requestID(r.Context())})
	v, e := a.configs.Create(ctx, chi.URLParam(r, "id"), p.User.ID, in.Strategy, []byte(in.Content))
	if e != nil {
		if errors.Is(e, store.ErrNotFound) {
			problem(w, r, http.StatusNotFound, "node not found", nil)
		} else if errors.Is(e, store.ErrObserveOnly) {
			problem(w, r, http.StatusConflict, "node is in observe mode", e)
		} else {
			problem(w, r, http.StatusBadRequest, "create config revision failed", e)
		}
		return
	}
	writeJSON(w, http.StatusCreated, configRevisionDTO(v))
}
func (a *API) listConfigRevisions(w http.ResponseWriter, r *http.Request) {
	page, e := a.configs.List(r.Context(), chi.URLParam(r, "id"), queryInt(r, "limit"), r.URL.Query().Get("cursor"))
	if e != nil {
		problem(w, r, http.StatusInternalServerError, "list config revisions failed", e)
		return
	}
	items := make([]any, 0, len(page.Items))
	for _, v := range page.Items {
		items = append(items, configRevisionDTO(v))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": page.NextCursor})
}
func (a *API) deployConfigRevision(w http.ResponseWriter, r *http.Request) {
	p := mustPrincipal(r.Context())
	ctx := store.WithMutationAudit(r.Context(), store.MutationAudit{Actor: p.User.ID, RequestID: requestID(r.Context())})
	v, e := a.configs.Deploy(ctx, chi.URLParam(r, "id"), p.User.ID, r.Header.Get("Idempotency-Key"))
	if e != nil {
		configTaskProblem(w, r, e)
		return
	}
	writeJSON(w, http.StatusAccepted, taskDTO(v))
}

type rollbackRequest struct {
	RevisionID       string `json:"revision_id"`
	LegacyRevisionID string `json:"config_revision_id"`
}

func (a *API) rollbackConfig(w http.ResponseWriter, r *http.Request) {
	var in rollbackRequest
	if !decode(w, r, &in) {
		return
	}
	p := mustPrincipal(r.Context())
	revisionID := in.RevisionID
	if revisionID == "" {
		revisionID = in.LegacyRevisionID
	}
	ctx := store.WithMutationAudit(r.Context(), store.MutationAudit{Actor: p.User.ID, RequestID: requestID(r.Context())})
	v, e := a.configs.Rollback(ctx, chi.URLParam(r, "id"), revisionID, p.User.ID, r.Header.Get("Idempotency-Key"))
	if e != nil {
		configTaskProblem(w, r, e)
		return
	}
	writeJSON(w, http.StatusAccepted, taskDTO(v))
}
func configTaskProblem(w http.ResponseWriter, r *http.Request, e error) {
	if errors.Is(e, store.ErrNotFound) {
		problem(w, r, http.StatusNotFound, "config revision not found", nil)
	} else if errors.Is(e, store.ErrConflict) {
		problem(w, r, http.StatusConflict, "duplicate or conflicting operation", e)
	} else if errors.Is(e, store.ErrObserveOnly) {
		problem(w, r, http.StatusConflict, "node is in observe mode", e)
	} else if errors.Is(e, store.ErrCapabilityUnavailable) {
		problem(w, r, http.StatusConflict, "the Agent does not support configuration deployment", e)
	} else {
		problem(w, r, http.StatusInternalServerError, "create configuration task failed", e)
	}
}
func configRevisionDTO(v domain.ConfigRevision) any {
	sensitive := []string{}
	_ = json.Unmarshal([]byte(v.SensitiveFields), &sensitive)
	return map[string]any{"id": v.ID, "node_id": v.NodeID, "version": v.Version, "sha256": v.SHA256, "strategy": v.Strategy, "format": "toml", "mode": v.Mode, "sensitive_fields_detected": sensitive, "created_by": v.CreatedBy, "created_at": v.CreatedAt}
}
func (a *API) getConfigContent(w http.ResponseWriter, r *http.Request) {
	v, e := a.configs.Content(r.Context(), chi.URLParam(r, "id"))
	if e != nil {
		storeProblem(w, r, "config revision", e)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": v.ID, "format": "toml", "mode": v.Mode, "content": v.Content})
}

type secretRequest struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

func (a *API) createSecret(w http.ResponseWriter, r *http.Request) {
	var in secretRequest
	if !decode(w, r, &in) {
		return
	}
	p := mustPrincipal(r.Context())
	ctx := store.WithMutationAudit(r.Context(), store.MutationAudit{Actor: p.User.ID, RequestID: requestID(r.Context())})
	v, e := a.secrets.Create(ctx, in.Name, in.Value, p.User.ID)
	if e != nil {
		_ = a.store.AppendAuditResult(r.Context(), p.User.ID, "secret.create", "secret", requestID(r.Context()), "failure")
		status := http.StatusBadRequest
		if errors.Is(e, store.ErrConflict) {
			status = http.StatusConflict
		}
		problem(w, r, status, "create secret failed", e)
		return
	}
	writeJSON(w, http.StatusCreated, secretDTO(v))
}
func (a *API) updateSecret(w http.ResponseWriter, r *http.Request) {
	var in secretRequest
	if !decode(w, r, &in) {
		return
	}
	p := mustPrincipal(r.Context())
	ctx := store.WithMutationAudit(r.Context(), store.MutationAudit{Actor: p.User.ID, RequestID: requestID(r.Context())})
	v, e := a.secrets.Update(ctx, chi.URLParam(r, "id"), in.Value, p.User.ID)
	if e != nil {
		_ = a.store.AppendAuditResult(r.Context(), p.User.ID, "secret.update", "secret/"+chi.URLParam(r, "id"), requestID(r.Context()), "failure")
		storeProblem(w, r, "secret", e)
		return
	}
	writeJSON(w, http.StatusOK, secretDTO(v))
}
func (a *API) listSecrets(w http.ResponseWriter, r *http.Request) {
	page, e := a.secrets.List(r.Context(), queryInt(r, "limit"), r.URL.Query().Get("cursor"))
	if e != nil {
		problem(w, r, http.StatusInternalServerError, "list secrets failed", e)
		return
	}
	items := make([]any, 0, len(page.Items))
	for _, v := range page.Items {
		items = append(items, secretDTO(v))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": page.NextCursor})
}
func secretDTO(v domain.Secret) any {
	return map[string]any{"id": v.ID, "name": v.Name, "configured": true, "key_version": v.KeyVersion, "created_at": v.CreatedAt, "updated_at": v.UpdatedAt}
}

type createUserRequest struct{ Username, Password, Role string }

func (a *API) createUser(w http.ResponseWriter, r *http.Request) {
	var in createUserRequest
	if !decode(w, r, &in) {
		return
	}
	p := mustPrincipal(r.Context())
	ctx := store.WithMutationAudit(r.Context(), store.MutationAudit{Actor: p.User.ID, RequestID: requestID(r.Context())})
	v, e := a.auth.CreateUser(ctx, auth.Credentials{Username: in.Username, Password: in.Password}, in.Role)
	if e != nil {
		problem(w, r, http.StatusBadRequest, "create user failed", e)
		return
	}
	writeJSON(w, http.StatusCreated, userDTO(v))
}

type updateUserRequest struct {
	Status string `json:"status"`
	Role   string `json:"role"`
}

func (a *API) updateUser(w http.ResponseWriter, r *http.Request) {
	var in updateUserRequest
	if !decode(w, r, &in) {
		return
	}
	p := mustPrincipal(r.Context())
	ctx := store.WithMutationAudit(r.Context(), store.MutationAudit{Actor: p.User.ID, RequestID: requestID(r.Context())})
	e := a.auth.UpdateUser(ctx, chi.URLParam(r, "id"), in.Status, in.Role)
	if e != nil {
		status := http.StatusBadRequest
		if errors.Is(e, store.ErrConflict) {
			status = http.StatusConflict
		}
		problem(w, r, status, "update user failed", e)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"updated": true})
}
func (a *API) listUsers(w http.ResponseWriter, r *http.Request) {
	page, e := a.auth.ListUsers(r.Context(), queryInt(r, "limit"), r.URL.Query().Get("cursor"))
	if e != nil {
		problem(w, r, http.StatusInternalServerError, "list users failed", e)
		return
	}
	items := make([]any, 0, len(page.Items))
	for _, v := range page.Items {
		items = append(items, userDTO(v))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": page.NextCursor})
}
func (a *API) listAuditLogs(w http.ResponseWriter, r *http.Request) {
	f := domain.AuditFilter{Actor: r.URL.Query().Get("actor"), Action: r.URL.Query().Get("action"), Resource: r.URL.Query().Get("resource")}
	for key, target := range map[string]**time.Time{"from": &f.From, "to": &f.To} {
		if raw := r.URL.Query().Get(key); raw != "" {
			v, e := time.Parse(time.RFC3339, raw)
			if e != nil {
				problem(w, r, http.StatusBadRequest, "invalid audit time filter", e)
				return
			}
			*target = &v
		}
	}
	limit := queryInt(r, "limit")
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	page, e := a.store.ListAuditLogs(r.Context(), f, limit, r.URL.Query().Get("cursor"))
	if e != nil {
		problem(w, r, http.StatusInternalServerError, "list audit logs failed", e)
		return
	}
	items := make([]any, 0, len(page.Items))
	for _, v := range page.Items {
		items = append(items, map[string]any{"id": v.ID, "actor": v.Actor, "action": v.Action, "resource": v.Resource, "request_id": v.RequestID, "outcome": v.Outcome, "created_at": v.CreatedAt})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": page.NextCursor})
}

type enrollmentRequest struct {
	Role       string `json:"role"`
	TTLSeconds int    `json:"ttlSeconds"`
}

func (a *API) createEnrollmentToken(w http.ResponseWriter, r *http.Request) {
	var in enrollmentRequest
	if !decode(w, r, &in) {
		return
	}
	p := mustPrincipal(r.Context())
	v, raw, e := a.nodes.CreateEnrollmentToken(r.Context(), in.Role, p.User.ID, time.Duration(in.TTLSeconds)*time.Second)
	if e != nil {
		problem(w, r, http.StatusBadRequest, "create enrollment token failed", e)
		return
	}
	_ = a.store.AppendAudit(r.Context(), p.User.ID, "enrollment_token.create", "enrollment_token/"+v.ID, requestID(r.Context()))
	a.events.Publish(events.Event{ID: v.ID, Type: "enrollment-token.created", Data: []byte(`{}`)})
	writeJSON(w, http.StatusCreated, map[string]any{"id": v.ID, "token": raw, "role": v.Role, "expiresAt": v.ExpiresAt})
}
func (a *API) listTasks(w http.ResponseWriter, r *http.Request) {
	page, e := a.tasks.List(r.Context(), queryInt(r, "limit"), r.URL.Query().Get("cursor"), r.URL.Query().Get("state"), r.URL.Query().Get("nodeId"))
	if e != nil {
		problem(w, r, http.StatusInternalServerError, "list tasks failed", e)
		return
	}
	items := make([]any, 0, len(page.Items))
	for _, v := range page.Items {
		items = append(items, taskDTO(v))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": page.NextCursor})
}

func (a *API) listAlerts(w http.ResponseWriter, r *http.Request) {
	page, e := a.store.ListAlerts(r.Context(), normalizedLimit(queryInt(r, "limit")), r.URL.Query().Get("cursor"), r.URL.Query().Get("state"))
	if e != nil {
		problem(w, r, http.StatusInternalServerError, "list alerts failed", e)
		return
	}
	writeJSON(w, http.StatusOK, page)
}
func (a *API) acknowledgeAlert(w http.ResponseWriter, r *http.Request) {
	a.transitionAlert(w, r, "acknowledged")
}
func (a *API) resolveAlert(w http.ResponseWriter, r *http.Request) {
	a.transitionAlert(w, r, "resolved")
}
func (a *API) closeAlert(w http.ResponseWriter, r *http.Request) { a.transitionAlert(w, r, "closed") }
func (a *API) transitionAlert(w http.ResponseWriter, r *http.Request, target string) {
	p := mustPrincipal(r.Context())
	id := chi.URLParam(r, "id")
	ctx := store.WithMutationAudit(r.Context(), store.MutationAudit{Actor: p.User.ID, RequestID: requestID(r.Context())})
	ctx = store.WithWebhookDelivery(ctx, a.webhookEnabled)
	v, e := a.store.UpdateAlertState(store.WithMutationAction(ctx, "alert."+target, "alert/"+id), id, target, p.User.ID, time.Now().UTC())
	if e != nil {
		if errors.Is(e, store.ErrNotFound) {
			problem(w, r, http.StatusNotFound, "alert not found", nil)
		} else if errors.Is(e, store.ErrConflict) {
			problem(w, r, http.StatusConflict, "invalid alert state transition", nil)
		} else {
			problem(w, r, http.StatusInternalServerError, "update alert failed", e)
		}
		return
	}
	if a.events != nil {
		a.events.Publish(events.Event{ID: v.ID, Type: "alert." + target, Data: []byte(`{}`)})
	}
	writeJSON(w, http.StatusOK, v)
}
func (a *API) getTask(w http.ResponseWriter, r *http.Request) {
	v, e := a.tasks.Get(r.Context(), chi.URLParam(r, "id"))
	if e != nil {
		storeProblem(w, r, "task", e)
		return
	}
	writeJSON(w, http.StatusOK, taskDTO(v))
}
func (a *API) cancelTask(w http.ResponseWriter, r *http.Request) {
	p := mustPrincipal(r.Context())
	ctx := store.WithMutationAudit(r.Context(), store.MutationAudit{Actor: p.User.ID, RequestID: requestID(r.Context())})
	v, e := a.tasks.Cancel(ctx, chi.URLParam(r, "id"))
	if e != nil {
		if errors.Is(e, store.ErrNotFound) {
			problem(w, r, http.StatusNotFound, "task not found", nil)
		} else if errors.Is(e, store.ErrConflict) {
			problem(w, r, http.StatusConflict, "task is already terminal", nil)
		} else {
			problem(w, r, http.StatusInternalServerError, "cancel task failed", e)
		}
		return
	}
	writeJSON(w, http.StatusOK, taskDTO(v))
}

type createUpgradePlanRequest struct {
	NodeID      string `json:"node_id"`
	Version     string `json:"version"`
	ArtifactURL string `json:"artifact_url"`
	SHA256      string `json:"sha256"`
}

func (a *API) createUpgradePlan(w http.ResponseWriter, r *http.Request) {
	var in createUpgradePlanRequest
	if !decode(w, r, &in) {
		return
	}
	p := mustPrincipal(r.Context())
	ctx := store.WithMutationAudit(r.Context(), store.MutationAudit{Actor: p.User.ID, RequestID: requestID(r.Context())})
	v, e := a.upgrades.Create(ctx, in.NodeID, in.Version, in.ArtifactURL, in.SHA256, p.User.ID, r.Header.Get("Idempotency-Key"))
	if e != nil {
		if errors.Is(e, store.ErrNotFound) {
			problem(w, r, http.StatusNotFound, "node not found", nil)
		} else if errors.Is(e, store.ErrConflict) {
			problem(w, r, http.StatusConflict, "duplicate upgrade operation", e)
		} else if errors.Is(e, store.ErrObserveOnly) {
			problem(w, r, http.StatusConflict, "node is in observe mode", e)
		} else if errors.Is(e, store.ErrCapabilityUnavailable) {
			problem(w, r, http.StatusConflict, "the Agent does not support upgrades", e)
		} else {
			problem(w, r, http.StatusBadRequest, "create upgrade plan failed", e)
		}
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"plan": upgradePlanDTO(v.Plan), "task": taskDTO(v.Task)})
}
func (a *API) listUpgradePlans(w http.ResponseWriter, r *http.Request) {
	page, e := a.upgrades.List(r.Context(), queryInt(r, "limit"), r.URL.Query().Get("cursor"), r.URL.Query().Get("nodeId"), r.URL.Query().Get("state"))
	if e != nil {
		problem(w, r, http.StatusBadRequest, "list upgrade plans failed", e)
		return
	}
	items := make([]any, 0, len(page.Items))
	for _, v := range page.Items {
		items = append(items, upgradePlanDTO(v))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": page.NextCursor})
}
func (a *API) getUpgradePlan(w http.ResponseWriter, r *http.Request) {
	v, t, e := a.upgrades.Get(r.Context(), chi.URLParam(r, "id"))
	if e != nil {
		storeProblem(w, r, "upgrade plan", e)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"plan": upgradePlanDTO(v), "task": taskDTO(t)})
}
func (a *API) cancelUpgradePlan(w http.ResponseWriter, r *http.Request) {
	p := mustPrincipal(r.Context())
	ctx := store.WithMutationAudit(r.Context(), store.MutationAudit{Actor: p.User.ID, RequestID: requestID(r.Context())})
	v, t, e := a.upgrades.Cancel(ctx, chi.URLParam(r, "id"))
	if e != nil {
		if errors.Is(e, store.ErrNotFound) {
			problem(w, r, http.StatusNotFound, "upgrade plan not found", nil)
		} else if errors.Is(e, store.ErrConflict) {
			problem(w, r, http.StatusConflict, "upgrade plan is already terminal", nil)
		} else {
			problem(w, r, http.StatusInternalServerError, "cancel upgrade plan failed", e)
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"plan": upgradePlanDTO(v), "task": taskDTO(t)})
}
func upgradePlanDTO(v domain.UpgradePlan) any {
	artifact := v.ArtifactURL
	if parsed, e := url.Parse(artifact); e == nil {
		parsed.RawQuery, parsed.Fragment, parsed.RawFragment = "", "", ""
		artifact = parsed.String()
	}
	return map[string]any{"id": v.ID, "node_id": v.NodeID, "version": v.Version, "artifact_url": artifact, "sha256": v.SHA256, "state": v.State, "task_id": v.TaskID, "created_by": v.CreatedBy, "created_at": v.CreatedAt, "updated_at": v.UpdatedAt}
}

func (a *API) getNodeRuntime(w http.ResponseWriter, r *http.Request) {
	nodeID := chi.URLParam(r, "id")
	if _, err := a.store.NodeByID(r.Context(), nodeID); err != nil {
		storeProblem(w, r, "node", err)
		return
	}
	v, err := a.store.RuntimeSnapshotByNode(r.Context(), nodeID)
	if err != nil {
		storeProblem(w, r, "runtime snapshot", err)
		return
	}
	writeJSON(w, http.StatusOK, runtimeSnapshotDTO(v))
}

func (a *API) collectNodeRuntime(w http.ResponseWriter, r *http.Request) {
	p := mustPrincipal(r.Context())
	ctx := store.WithMutationAudit(r.Context(), store.MutationAudit{Actor: p.User.ID, RequestID: requestID(r.Context())})
	v, err := a.tasks.CollectRuntime(ctx, chi.URLParam(r, "id"), p.User.ID, strings.TrimSpace(r.Header.Get("Idempotency-Key")))
	if err != nil {
		if errors.Is(err, store.ErrConflict) {
			problem(w, r, http.StatusConflict, "duplicate runtime collection", err)
		} else if errors.Is(err, store.ErrCapabilityUnavailable) {
			problem(w, r, http.StatusConflict, "the Agent does not support runtime collection", err)
		} else {
			storeProblem(w, r, "node", err)
		}
		return
	}
	writeJSON(w, http.StatusAccepted, taskDTO(v))
}

func (a *API) listRuntimeProxies(w http.ResponseWriter, r *http.Request) {
	limit := queryInt(r, "limit")
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	statusValue := strings.TrimSpace(r.URL.Query().Get("status"))
	if statusValue != "" && statusValue != "running" && statusValue != "offline" && statusValue != "error" && statusValue != "unknown" {
		problem(w, r, http.StatusBadRequest, "invalid proxy status", nil)
		return
	}
	page, err := a.store.ListRuntimeProxies(r.Context(), limit, r.URL.Query().Get("cursor"), r.URL.Query().Get("nodeId"), statusValue, r.URL.Query().Get("type"))
	if err != nil {
		problem(w, r, http.StatusInternalServerError, "list runtime proxies failed", err)
		return
	}
	items := make([]any, 0, len(page.Items))
	for _, v := range page.Items {
		items = append(items, runtimeProxyDTO(v))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": page.NextCursor})
}

func (a *API) getRuntimeProxy(w http.ResponseWriter, r *http.Request) {
	v, err := a.store.RuntimeProxyByKey(r.Context(), chi.URLParam(r, "nodeId"), chi.URLParam(r, "name"))
	if err != nil {
		storeProblem(w, r, "runtime proxy", err)
		return
	}
	writeJSON(w, http.StatusOK, runtimeProxyDTO(v))
}

func runtimeSnapshotDTO(v domain.RuntimeSnapshot) any {
	proxies := make([]any, 0, len(v.Proxies))
	for _, proxy := range v.Proxies {
		proxies = append(proxies, runtimeProxyDTO(proxy))
	}
	clients := make([]any, 0, len(v.Clients))
	for _, client := range v.Clients {
		clients = append(clients, map[string]any{"id": client.ID, "address": client.Address, "connected_at": client.ConnectedAt})
	}
	return map[string]any{"node_id": v.NodeID, "role": v.Role, "frp_version": v.FRPVersion, "collected_at": v.CollectedAt, "bind_address": v.BindAddress, "bind_port": v.BindPort, "proxy_count": v.ProxyCount, "client_count": v.ClientCount, "proxies": proxies, "clients": clients}
}

func runtimeProxyDTO(v domain.RuntimeProxy) any {
	traffic := map[string]any{"bytes_in": v.Traffic.BytesIn, "bytes_out": v.Traffic.BytesOut, "today_bytes_in": v.Traffic.TodayBytesIn, "today_bytes_out": v.Traffic.TodayBytesOut, "current_connections": v.Traffic.CurrentConnections}
	return map[string]any{"node_id": v.NodeID, "node_name": v.NodeName, "name": v.Name, "type": v.Type, "status": v.Status, "local_address": v.LocalAddress, "remote_address": v.RemoteAddress, "last_error": v.LastError, "traffic": traffic, "collected_at": v.CollectedAt}
}

func (a *API) sse(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		problem(w, r, http.StatusInternalServerError, "streaming unsupported", nil)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	controller := http.NewResponseController(w)
	extendDeadline := func() { _ = controller.SetWriteDeadline(time.Now().Add(30 * time.Second)) }
	_, ch, cancel := a.events.Subscribe()
	defer cancel()
	extendDeadline()
	fmt.Fprint(w, ": connected\n\n")
	flusher.Flush()
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			extendDeadline()
			fmt.Fprint(w, ": keepalive\n\n")
			flusher.Flush()
		case e := <-ch:
			extendDeadline()
			fmt.Fprintf(w, "id: %s\nevent: %s\ndata: %s\n\n", safeSSE(e.ID), safeSSE(e.Type), e.Data)
			flusher.Flush()
		}
	}
}
func safeSSE(v string) string { return strings.NewReplacer("\r", "", "\n", "").Replace(v) }

func decode(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if e := dec.Decode(dst); e != nil {
		problem(w, r, http.StatusBadRequest, "invalid JSON request", e)
		return false
	}
	return true
}
func queryInt(r *http.Request, key string) int {
	v, _ := strconv.Atoi(r.URL.Query().Get(key))
	return v
}
func normalizedLimit(v int) int {
	if v <= 0 {
		return 50
	}
	if v > 200 {
		return 200
	}
	return v
}
func writeJSON(w http.ResponseWriter, status int, v any) {
	if w.Header().Get("Content-Type") == "" {
		w.Header().Set("Content-Type", "application/json")
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func problem(w http.ResponseWriter, r *http.Request, status int, title string, detail error) {
	body := map[string]any{"type": "about:blank", "title": title, "status": status, "requestId": requestID(r.Context())}
	if detail != nil && status >= 500 {
		slog.ErrorContext(r.Context(), title, "error_type", fmt.Sprintf("%T", detail), "request_id", requestID(r.Context()))
	}
	w.Header().Set("Content-Type", "application/problem+json")
	writeJSON(w, status, body)
}
func storeProblem(w http.ResponseWriter, r *http.Request, resource string, e error) {
	if errors.Is(e, store.ErrNotFound) {
		problem(w, r, http.StatusNotFound, resource+" not found", nil)
	} else {
		problem(w, r, http.StatusInternalServerError, "load "+resource+" failed", e)
	}
}
func userDTO(u domain.User) any {
	return map[string]any{"id": u.ID, "username": u.Username, "status": u.Status, "role": u.Role, "createdAt": u.CreatedAt}
}
func nodeDTO(n domain.Node) any {
	status, serviceStatus := "unknown", "unknown"
	var agentVersion, frpVersion, lastHeartbeat any
	var observedRevision any
	capabilities := []string{}
	if n.Observation != nil {
		if n.Observation.Online {
			status = "online"
		} else {
			status = "offline"
		}
		if n.Observation.ServiceState != "" {
			serviceStatus = n.Observation.ServiceState
		}
		if n.Observation.AgentVersion != "" {
			agentVersion = n.Observation.AgentVersion
		}
		if n.Observation.FRPVersion != "" {
			frpVersion = n.Observation.FRPVersion
		}
		if !n.Observation.LastHeartbeat.IsZero() {
			lastHeartbeat = n.Observation.LastHeartbeat
		}
		if n.Observation.ObservedRevisionID != nil {
			observedRevision = *n.Observation.ObservedRevisionID
		}
		_ = json.Unmarshal([]byte(n.Observation.Capabilities), &capabilities)
	}
	var desiredRevision any
	if n.DesiredRevisionID != nil {
		desiredRevision = *n.DesiredRevisionID
	}
	labels := map[string]string{}
	_ = json.Unmarshal([]byte(n.Labels), &labels)
	return map[string]any{"id": n.ID, "name": n.Name, "role": n.Role, "labels": labels, "management_mode": n.ManagementMode, "status": status, "service_status": serviceStatus, "agent_version": agentVersion, "frp_version": frpVersion, "capabilities": capabilities, "desired_revision": desiredRevision, "observed_revision": observedRevision, "drifted": desiredRevision != nil && desiredRevision != observedRevision, "last_heartbeat_at": lastHeartbeat, "created_at": n.CreatedAt}
}
func taskDTO(t domain.Task) any {
	steps := make([]any, 0, len(t.Steps))
	for _, step := range t.Steps {
		message := step.Output
		if step.ErrorCode != "" {
			message = publicTaskError(t.Type, step.ErrorCode)
		}
		steps = append(steps, map[string]any{"id": step.ID, "name": step.Name, "status": step.State, "error_code": step.ErrorCode, "error_message": message})
	}
	message := t.ErrorMessage
	if t.ErrorCode != "" {
		message = publicTaskError(t.Type, t.ErrorCode)
	}
	return map[string]any{"id": t.ID, "type": t.Type, "status": t.State, "node_id": t.NodeID, "actor": t.RequestedBy, "error_code": t.ErrorCode, "error_message": message, "steps": steps, "expires_at": t.ExpiresAt, "cancel_requested_at": t.CancelRequestedAt, "created_at": t.CreatedAt}
}

func publicTaskError(taskType, errorCode string) string {
	switch taskType {
	case "config_apply", "config_rollback":
		if errorCode == "VERIFY_FAILED" {
			return "candidate configuration verification failed"
		}
		return "configuration operation failed"
	case "frp_upgrade":
		if errorCode == "VERIFY_FAILED" {
			return "upgrade candidate configuration verification failed"
		}
		return "upgrade operation failed"
	case "risk_repair":
		return "deployment risk repair failed"
	default:
		return "command failed"
	}
}
