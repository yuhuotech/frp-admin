package sqlstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/frp-admin/frp-admin/server/internal/domain"
	"github.com/frp-admin/frp-admin/server/internal/metrics"
	storepkg "github.com/frp-admin/frp-admin/server/internal/store"
	"github.com/frp-admin/frp-admin/server/migrations"
	_ "github.com/go-sql-driver/mysql"
	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
)

type Store struct {
	db      *sql.DB
	dialect string
}

func (s *Store) ReferencedKeyVersions(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT key_version FROM secrets UNION SELECT artifact_key_version FROM upgrade_plans ORDER BY 1")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	versions := []string{}
	for rows.Next() {
		var version string
		if err = rows.Scan(&version); err != nil {
			return nil, err
		}
		versions = append(versions, version)
	}
	return versions, rows.Err()
}

func Open(ctx context.Context, dialect, dsn string) (*Store, error) {
	driver := dialect
	if dialect == "sqlite" {
		driver = "sqlite"
		if !strings.HasPrefix(dsn, "file:") && dsn != ":memory:" {
			if err := os.MkdirAll(filepath.Dir(dsn), 0o750); err != nil {
				return nil, fmt.Errorf("create database directory: %w", err)
			}
			dsn = "file:" + dsn + "?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"
		}
	} else if dialect == "postgres" {
		driver = "pgx"
	}
	db, err := sql.Open(driver, dsn)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	if dialect == "sqlite" {
		db.SetMaxOpenConns(1)
	} else {
		db.SetMaxOpenConns(20)
		db.SetMaxIdleConns(5)
	}
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}
	if dialect == "mysql" {
		if _, err := db.ExecContext(ctx, "SET time_zone = '+00:00'"); err != nil {
			db.Close()
			return nil, fmt.Errorf("set mysql timezone: %w", err)
		}
	}
	if dialect == "postgres" {
		if _, err := db.ExecContext(ctx, "SET TIME ZONE 'UTC'"); err != nil {
			db.Close()
			return nil, fmt.Errorf("set postgres timezone: %w", err)
		}
	}
	if err := migrations.Apply(ctx, db, dialect); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db, dialect: dialect}, nil
}

func (s *Store) Close() error                   { return s.db.Close() }
func (s *Store) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }
func (s *Store) DBStats() sql.DBStats           { return s.db.Stats() }
func observeSQL(start time.Time)                { metrics.Default.ObserveSQL(time.Since(start)) }
func micros(t time.Time) int64                  { return t.UTC().UnixMicro() }
func instant(v int64) time.Time                 { return time.UnixMicro(v).UTC() }
func nullable(t *time.Time) any {
	if t == nil {
		return nil
	}
	return micros(*t)
}

func (s *Store) q(query string) string {
	if s.dialect != "postgres" {
		return query
	}
	var b strings.Builder
	n := 1
	for _, r := range query {
		if r == '?' {
			b.WriteString("$")
			b.WriteString(strconv.Itoa(n))
			n++
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func translate(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return storepkg.ErrNotFound
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "unique") || strings.Contains(msg, "duplicate") {
		return fmt.Errorf("%w: %v", storepkg.ErrConflict, err)
	}
	return err
}
func (s *Store) appendMutationAudit(ctx context.Context, tx *sql.Tx) error {
	a, ok := storepkg.MutationAuditFrom(ctx)
	if !ok || a.Action == "" {
		return nil
	}
	_, e := tx.ExecContext(ctx, s.q("INSERT INTO audit_logs(id,actor,action,resource,request_id,created_at,outcome) VALUES(?,?,?,?,?,?,?)"), uuid.Must(uuid.NewV7()).String(), a.Actor, a.Action, a.Resource, a.RequestID, micros(time.Now()), "success")
	return e
}

func (s *Store) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM users").Scan(&n)
	return n, err
}

func (s *Store) CreateUser(ctx context.Context, u domain.User) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, s.q("INSERT INTO users(id,username,password_hash,status,created_at) VALUES(?,?,?,?,?)"), u.ID, u.Username, u.PasswordHash, u.Status, micros(u.CreatedAt)); err != nil {
		return translate(err)
	}
	if _, err = tx.ExecContext(ctx, s.q("INSERT INTO user_roles(user_id,role) VALUES(?,?)"), u.ID, u.Role); err != nil {
		return translate(err)
	}
	if err = s.appendMutationAudit(ctx, tx); err != nil {
		return err
	}
	return tx.Commit()
}

func scanUser(row interface{ Scan(...any) error }) (domain.User, error) {
	var u domain.User
	var created int64
	err := row.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Status, &u.Role, &created)
	u.CreatedAt = instant(created)
	return u, translate(err)
}
func (s *Store) UserByUsername(ctx context.Context, name string) (domain.User, error) {
	return scanUser(s.db.QueryRowContext(ctx, s.q("SELECT u.id,u.username,u.password_hash,u.status,r.role,u.created_at FROM users u JOIN user_roles r ON r.user_id=u.id WHERE u.username=?"), name))
}
func (s *Store) UserByID(ctx context.Context, id string) (domain.User, error) {
	return scanUser(s.db.QueryRowContext(ctx, s.q("SELECT u.id,u.username,u.password_hash,u.status,r.role,u.created_at FROM users u JOIN user_roles r ON r.user_id=u.id WHERE u.id=?"), id))
}

func (s *Store) CreateSession(ctx context.Context, v domain.Session) error {
	_, err := s.db.ExecContext(ctx, s.q("INSERT INTO sessions(id,user_id,token_hash,csrf_hash,expires_at,revoked_at,created_at) VALUES(?,?,?,?,?,?,?)"), v.ID, v.UserID, v.TokenHash, v.CSRFHash, micros(v.ExpiresAt), nullable(v.RevokedAt), micros(time.Now()))
	return translate(err)
}
func (s *Store) SessionByTokenHash(ctx context.Context, h string, now time.Time) (domain.Session, error) {
	var v domain.Session
	var ex int64
	var rev sql.NullInt64
	err := s.db.QueryRowContext(ctx, s.q("SELECT id,user_id,token_hash,csrf_hash,expires_at,revoked_at FROM sessions WHERE token_hash=? AND expires_at>? AND revoked_at IS NULL"), h, micros(now)).Scan(&v.ID, &v.UserID, &v.TokenHash, &v.CSRFHash, &ex, &rev)
	v.ExpiresAt = instant(ex)
	return v, translate(err)
}
func (s *Store) RevokeSession(ctx context.Context, id string, at time.Time) error {
	r, e := s.db.ExecContext(ctx, s.q("UPDATE sessions SET revoked_at=? WHERE id=? AND revoked_at IS NULL"), micros(at), id)
	if e != nil {
		return e
	}
	n, _ := r.RowsAffected()
	if n == 0 {
		return storepkg.ErrNotFound
	}
	return nil
}
func (s *Store) CreateEnrollmentToken(ctx context.Context, v domain.EnrollmentToken) error {
	_, e := s.db.ExecContext(ctx, s.q("INSERT INTO enrollment_tokens(id,token_hash,role,expires_at,used_at,created_by,created_at) VALUES(?,?,?,?,?,?,?)"), v.ID, v.TokenHash, v.Role, micros(v.ExpiresAt), nullable(v.UsedAt), v.CreatedBy, micros(v.CreatedAt))
	return translate(e)
}

func (s *Store) ConsumeEnrollmentTokenAndCreateNode(ctx context.Context, tokenHash, role string, node domain.Node, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, s.q("UPDATE enrollment_tokens SET used_at=? WHERE token_hash=? AND role=? AND used_at IS NULL AND expires_at>?"), micros(now), tokenHash, role, micros(now))
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return storepkg.ErrNotFound
	}
	_, err = tx.ExecContext(ctx, s.q("INSERT INTO nodes(id,name,role,labels,management_mode,desired_revision_id,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)"), node.ID, node.Name, node.Role, node.Labels, node.ManagementMode, nil, micros(node.CreatedAt), micros(node.UpdatedAt))
	if err != nil {
		return translate(err)
	}
	return tx.Commit()
}

func (s *Store) UpsertObservation(ctx context.Context, o domain.NodeObservation) error {
	defer observeSQL(time.Now())
	query := s.q("UPDATE node_observations SET online=?,agent_version=?,frp_version=?,service_state=?,observed_hash=?,observed_revision_id=?,capabilities=?,last_heartbeat=? WHERE node_id=?")
	args := []any{o.Online, o.AgentVersion, o.FRPVersion, o.ServiceState, o.ObservedHash, o.ObservedRevisionID, o.Capabilities, micros(o.LastHeartbeat), o.NodeID}
	result, err := s.db.ExecContext(ctx, query, args...)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		_, err = s.db.ExecContext(ctx, s.q("INSERT INTO node_observations(node_id,online,agent_version,frp_version,service_state,observed_hash,observed_revision_id,capabilities,last_heartbeat) VALUES(?,?,?,?,?,?,?,?,?)"), o.NodeID, o.Online, o.AgentVersion, o.FRPVersion, o.ServiceState, o.ObservedHash, o.ObservedRevisionID, o.Capabilities, micros(o.LastHeartbeat))
		if err != nil {
			if errors.Is(translate(err), storepkg.ErrConflict) {
				_, err = s.db.ExecContext(ctx, query, args...)
				return err
			}
			return err
		}
	}
	return nil
}

func (s *Store) SetNodeOnline(ctx context.Context, nodeID string, online bool, at time.Time) error {
	result, err := s.db.ExecContext(ctx, s.q("UPDATE node_observations SET online=?,last_heartbeat=? WHERE node_id=?"), online, micros(at), nodeID)
	if err != nil {
		return err
	}
	rows, e := result.RowsAffected()
	if e != nil {
		return e
	}
	if rows == 0 {
		return storepkg.ErrNotFound
	}
	return nil
}

func scanNode(row interface{ Scan(...any) error }) (domain.Node, error) {
	var n domain.Node
	var desired sql.NullString
	var ca, ua int64
	var online sql.NullBool
	var av, fv, ss, oh, capabilities sql.NullString
	var observed sql.NullString
	var hb sql.NullInt64
	err := row.Scan(&n.ID, &n.Name, &n.Role, &n.Labels, &n.ManagementMode, &desired, &ca, &ua, &online, &av, &fv, &ss, &oh, &observed, &capabilities, &hb)
	if err != nil {
		return n, translate(err)
	}
	if desired.Valid {
		n.DesiredRevisionID = &desired.String
	}
	n.CreatedAt = instant(ca)
	n.UpdatedAt = instant(ua)
	if online.Valid {
		o := domain.NodeObservation{NodeID: n.ID, Online: online.Bool, AgentVersion: av.String, FRPVersion: fv.String, ServiceState: ss.String, ObservedHash: oh.String, Capabilities: capabilities.String}
		if observed.Valid {
			o.ObservedRevisionID = &observed.String
		}
		if hb.Valid {
			o.LastHeartbeat = instant(hb.Int64)
		}
		n.Observation = &o
	}
	return n, nil
}

const nodeSelect = "SELECT n.id,n.name,n.role,n.labels,n.management_mode,n.desired_revision_id,n.created_at,n.updated_at,o.online,o.agent_version,o.frp_version,o.service_state,o.observed_hash,o.observed_revision_id,o.capabilities,o.last_heartbeat FROM nodes n LEFT JOIN node_observations o ON o.node_id=n.id"

func (s *Store) ListNodes(ctx context.Context, limit int, cursor string) (domain.Page[domain.Node], error) {
	defer observeSQL(time.Now())
	offset := decodeCursor(cursor)
	rows, e := s.db.QueryContext(ctx, s.q(nodeSelect+" ORDER BY n.created_at DESC,n.id DESC LIMIT ? OFFSET ?"), limit+1, offset)
	if e != nil {
		return domain.Page[domain.Node]{}, e
	}
	defer rows.Close()
	out := domain.Page[domain.Node]{Items: []domain.Node{}}
	for rows.Next() {
		n, e := scanNode(rows)
		if e != nil {
			return out, e
		}
		out.Items = append(out.Items, n)
	}
	if len(out.Items) > limit {
		out.Items = out.Items[:limit]
		out.NextCursor = strconv.Itoa(offset + limit)
	}
	return out, rows.Err()
}
func (s *Store) NodeByID(ctx context.Context, id string) (domain.Node, error) {
	defer observeSQL(time.Now())
	return scanNode(s.db.QueryRowContext(ctx, s.q(nodeSelect+" WHERE n.id=?"), id))
}

func (s *Store) SetNodeManagementMode(ctx context.Context, id, mode string, at time.Time) (domain.Node, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.Node{}, err
	}
	defer tx.Rollback()
	if _, err = s.lockNodeMode(ctx, tx, id); err != nil {
		return domain.Node{}, err
	}
	if mode == "observe" {
		active, countErr := s.activeDangerousTasks(ctx, tx, id)
		if countErr != nil {
			return domain.Node{}, countErr
		}
		if active > 0 {
			return domain.Node{}, storepkg.ErrConflict
		}
	}
	result, err := tx.ExecContext(ctx, s.q("UPDATE nodes SET management_mode=?,updated_at=? WHERE id=?"), mode, micros(at), id)
	if err != nil {
		return domain.Node{}, err
	}
	if rows, _ := result.RowsAffected(); rows != 1 {
		return domain.Node{}, storepkg.ErrNotFound
	}
	if err = s.appendMutationAudit(ctx, tx); err != nil {
		return domain.Node{}, err
	}
	if err = tx.Commit(); err != nil {
		return domain.Node{}, err
	}
	return s.NodeByID(ctx, id)
}

func (s *Store) lockNodeMode(ctx context.Context, tx *sql.Tx, nodeID string) (string, error) {
	if _, err := tx.ExecContext(ctx, s.q("UPDATE nodes SET updated_at=updated_at WHERE id=?"), nodeID); err != nil {
		return "", err
	}
	var mode string
	if err := tx.QueryRowContext(ctx, s.q("SELECT management_mode FROM nodes WHERE id=?"), nodeID).Scan(&mode); err != nil {
		return "", translate(err)
	}
	return mode, nil
}

func (s *Store) activeDangerousTasks(ctx context.Context, tx *sql.Tx, nodeID string) (int, error) {
	var active int
	query := "SELECT COUNT(*) FROM tasks WHERE node_id=? AND state IN ('queued','dispatched','running') AND type IN ('service_start','service_stop','service_restart','config_apply','config_rollback','frp_upgrade','risk_repair')"
	err := tx.QueryRowContext(ctx, s.q(query), nodeID).Scan(&active)
	return active, err
}

func dangerousTaskType(taskType string) bool {
	switch taskType {
	case "service_start", "service_stop", "service_restart", "config_apply", "config_rollback", "frp_upgrade", "risk_repair":
		return true
	default:
		return false
	}
}

func (s *Store) ensureDangerousTaskAllowed(ctx context.Context, tx *sql.Tx, nodeID string) error {
	mode, err := s.lockNodeMode(ctx, tx, nodeID)
	if err != nil {
		return err
	}
	if mode != "managed" {
		return storepkg.ErrObserveOnly
	}
	active, err := s.activeDangerousTasks(ctx, tx, nodeID)
	if err != nil {
		return err
	}
	if active > 0 {
		return storepkg.ErrConflict
	}
	return nil
}

func (s *Store) NextConfigVersion(ctx context.Context, nodeID string) (int64, error) {
	var max sql.NullInt64
	if e := s.db.QueryRowContext(ctx, s.q("SELECT MAX(version) FROM config_revisions WHERE node_id=?"), nodeID).Scan(&max); e != nil {
		return 0, e
	}
	if !max.Valid {
		return 1, nil
	}
	return max.Int64 + 1, nil
}
func (s *Store) CreateConfigRevision(ctx context.Context, v domain.ConfigRevision) error {
	defer observeSQL(time.Now())
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	mode, e := s.lockNodeMode(ctx, tx, v.NodeID)
	if e != nil {
		return e
	}
	if mode != "managed" {
		return storepkg.ErrObserveOnly
	}
	if _, e = tx.ExecContext(ctx, s.q("INSERT INTO config_revisions(id,node_id,version,encrypted_content,nonce,sha256,strategy,created_by,created_at,mode,sensitive_fields) VALUES(?,?,?,?,?,?,?,?,?,?,?)"), v.ID, v.NodeID, v.Version, v.EncryptedContent, v.Nonce, v.SHA256, v.Strategy, v.CreatedBy, micros(v.CreatedAt), v.Mode, v.SensitiveFields); e != nil {
		return translate(e)
	}
	if e = s.appendMutationAudit(ctx, tx); e != nil {
		return e
	}
	return tx.Commit()
}
func scanConfig(row interface{ Scan(...any) error }) (domain.ConfigRevision, error) {
	var v domain.ConfigRevision
	var created int64
	e := row.Scan(&v.ID, &v.NodeID, &v.Version, &v.EncryptedContent, &v.Nonce, &v.SHA256, &v.Strategy, &v.CreatedBy, &created, &v.Mode, &v.SensitiveFields)
	v.CreatedAt = instant(created)
	return v, translate(e)
}
func (s *Store) ConfigRevisionByID(ctx context.Context, id string) (domain.ConfigRevision, error) {
	return scanConfig(s.db.QueryRowContext(ctx, s.q("SELECT id,node_id,version,encrypted_content,nonce,sha256,strategy,created_by,created_at,mode,sensitive_fields FROM config_revisions WHERE id=?"), id))
}
func (s *Store) ListConfigRevisions(ctx context.Context, nodeID string, limit int, cursor string) (domain.Page[domain.ConfigRevision], error) {
	defer observeSQL(time.Now())
	offset := decodeCursor(cursor)
	rows, e := s.db.QueryContext(ctx, s.q("SELECT id,node_id,version,encrypted_content,nonce,sha256,strategy,created_by,created_at,mode,sensitive_fields FROM config_revisions WHERE node_id=? ORDER BY version DESC LIMIT ? OFFSET ?"), nodeID, limit+1, offset)
	if e != nil {
		return domain.Page[domain.ConfigRevision]{}, e
	}
	defer rows.Close()
	out := domain.Page[domain.ConfigRevision]{Items: []domain.ConfigRevision{}}
	for rows.Next() {
		v, e := scanConfig(rows)
		if e != nil {
			return out, e
		}
		out.Items = append(out.Items, v)
	}
	if len(out.Items) > limit {
		out.Items = out.Items[:limit]
		out.NextCursor = strconv.Itoa(offset + limit)
	}
	return out, rows.Err()
}

func (s *Store) CreateSecret(ctx context.Context, v domain.Secret) error {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if _, e = tx.ExecContext(ctx, s.q("INSERT INTO secrets(id,name,ciphertext,nonce,key_version,created_by,updated_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)"), v.ID, v.Name, v.Ciphertext, v.Nonce, v.KeyVersion, v.CreatedBy, v.UpdatedBy, micros(v.CreatedAt), micros(v.UpdatedAt)); e != nil {
		return translate(e)
	}
	if e = s.appendMutationAudit(ctx, tx); e != nil {
		return e
	}
	return tx.Commit()
}
func (s *Store) UpdateSecret(ctx context.Context, v domain.Secret) error {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	r, e := tx.ExecContext(ctx, s.q("UPDATE secrets SET ciphertext=?,nonce=?,key_version=?,updated_by=?,updated_at=? WHERE id=?"), v.Ciphertext, v.Nonce, v.KeyVersion, v.UpdatedBy, micros(v.UpdatedAt), v.ID)
	if e != nil {
		return e
	}
	n, _ := r.RowsAffected()
	if n == 0 {
		return storepkg.ErrNotFound
	}
	if e = s.appendMutationAudit(ctx, tx); e != nil {
		return e
	}
	return tx.Commit()
}
func scanSecret(row interface{ Scan(...any) error }) (domain.Secret, error) {
	var v domain.Secret
	var ca, ua int64
	e := row.Scan(&v.ID, &v.Name, &v.Ciphertext, &v.Nonce, &v.KeyVersion, &v.CreatedBy, &v.UpdatedBy, &ca, &ua)
	v.CreatedAt = instant(ca)
	v.UpdatedAt = instant(ua)
	return v, translate(e)
}
func (s *Store) SecretByName(ctx context.Context, name string) (domain.Secret, error) {
	return scanSecret(s.db.QueryRowContext(ctx, s.q("SELECT id,name,ciphertext,nonce,key_version,created_by,updated_by,created_at,updated_at FROM secrets WHERE name=?"), name))
}
func (s *Store) SecretByID(ctx context.Context, id string) (domain.Secret, error) {
	return scanSecret(s.db.QueryRowContext(ctx, s.q("SELECT id,name,ciphertext,nonce,key_version,created_by,updated_by,created_at,updated_at FROM secrets WHERE id=?"), id))
}
func (s *Store) ListSecrets(ctx context.Context, limit int, cursor string) (domain.Page[domain.Secret], error) {
	offset := decodeCursor(cursor)
	rows, e := s.db.QueryContext(ctx, s.q("SELECT id,name,ciphertext,nonce,key_version,created_by,updated_by,created_at,updated_at FROM secrets ORDER BY name,id LIMIT ? OFFSET ?"), limit+1, offset)
	if e != nil {
		return domain.Page[domain.Secret]{}, e
	}
	defer rows.Close()
	out := domain.Page[domain.Secret]{Items: []domain.Secret{}}
	for rows.Next() {
		v, e := scanSecret(rows)
		if e != nil {
			return out, e
		}
		out.Items = append(out.Items, v)
	}
	if len(out.Items) > limit {
		out.Items = out.Items[:limit]
		out.NextCursor = strconv.Itoa(offset + limit)
	}
	return out, rows.Err()
}

func (s *Store) ListUsers(ctx context.Context, limit int, cursor string) (domain.Page[domain.User], error) {
	offset := decodeCursor(cursor)
	rows, e := s.db.QueryContext(ctx, s.q("SELECT u.id,u.username,u.password_hash,u.status,r.role,u.created_at FROM users u JOIN user_roles r ON r.user_id=u.id ORDER BY u.username,u.id LIMIT ? OFFSET ?"), limit+1, offset)
	if e != nil {
		return domain.Page[domain.User]{}, e
	}
	defer rows.Close()
	out := domain.Page[domain.User]{Items: []domain.User{}}
	for rows.Next() {
		v, e := scanUser(rows)
		if e != nil {
			return out, e
		}
		v.PasswordHash = ""
		out.Items = append(out.Items, v)
	}
	if len(out.Items) > limit {
		out.Items = out.Items[:limit]
		out.NextCursor = strconv.Itoa(offset + limit)
	}
	return out, rows.Err()
}
func (s *Store) UpdateUserAccess(ctx context.Context, id, statusValue, role string, at time.Time) error {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var currentStatus, currentRole string
	if e = tx.QueryRowContext(ctx, s.q("SELECT u.status,r.role FROM users u JOIN user_roles r ON r.user_id=u.id WHERE u.id=?"), id).Scan(&currentStatus, &currentRole); e != nil {
		return translate(e)
	}
	if statusValue == "" {
		statusValue = currentStatus
	}
	if role == "" {
		role = currentRole
	}
	if currentStatus == "active" && currentRole == "admin" && (statusValue != "active" || role != "admin") {
		var count int
		if e = tx.QueryRowContext(ctx, s.q("SELECT COUNT(*) FROM users u JOIN user_roles r ON r.user_id=u.id WHERE u.status='active' AND r.role='admin' AND u.id<>?"), id).Scan(&count); e != nil {
			return e
		}
		if count == 0 {
			return storepkg.ErrConflict
		}
	}
	if _, e = tx.ExecContext(ctx, s.q("UPDATE users SET status=? WHERE id=?"), statusValue, id); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, s.q("UPDATE user_roles SET role=? WHERE user_id=?"), role, id); e != nil {
		return e
	}
	if statusValue != "active" {
		if _, e = tx.ExecContext(ctx, s.q("UPDATE sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL"), micros(at), id); e != nil {
			return e
		}
	}
	if e = s.appendMutationAudit(ctx, tx); e != nil {
		return e
	}
	return tx.Commit()
}

func scanTask(row interface{ Scan(...any) error }) (domain.Task, error) {
	var t domain.Task
	var ca, ua int64
	var node, configRevision, expected, upgradePlan sql.NullString
	var expires, cancelled sql.NullInt64
	err := row.Scan(&t.ID, &t.Type, &t.State, &node, &t.IdempotencyKey, &t.RequestedBy, &t.ErrorCode, &t.ErrorMessage, &t.Payload, &configRevision, &expected, &upgradePlan, &expires, &cancelled, &ca, &ua)
	if node.Valid {
		t.NodeID = node.String
	}
	if configRevision.Valid {
		t.ConfigRevisionID = &configRevision.String
	}
	if expected.Valid {
		t.ExpectedRevisionID = &expected.String
	}
	if upgradePlan.Valid {
		t.UpgradePlanID = &upgradePlan.String
	}
	if expires.Valid {
		v := instant(expires.Int64)
		t.ExpiresAt = &v
	}
	if cancelled.Valid {
		v := instant(cancelled.Int64)
		t.CancelRequestedAt = &v
	}
	t.CreatedAt = instant(ca)
	t.UpdatedAt = instant(ua)
	return t, translate(err)
}
func (s *Store) ListTasks(ctx context.Context, limit int, cursor, state, nodeID string) (domain.Page[domain.Task], error) {
	defer observeSQL(time.Now())
	offset := decodeCursor(cursor)
	q := "SELECT id,type,state,node_id,idempotency_key,requested_by,error_code,error_message,payload,config_revision_id,expected_revision_id,upgrade_plan_id,expires_at,cancel_requested_at,created_at,updated_at FROM tasks WHERE 1=1"
	args := []any{}
	if state != "" {
		q += " AND state=?"
		args = append(args, state)
	}
	if nodeID != "" {
		q += " AND node_id=?"
		args = append(args, nodeID)
	}
	q += " ORDER BY created_at DESC,id DESC LIMIT ? OFFSET ?"
	args = append(args, limit+1, offset)
	rows, e := s.db.QueryContext(ctx, s.q(q), args...)
	if e != nil {
		return domain.Page[domain.Task]{}, e
	}
	defer rows.Close()
	out := domain.Page[domain.Task]{Items: []domain.Task{}}
	for rows.Next() {
		t, e := scanTask(rows)
		if e != nil {
			return out, e
		}
		out.Items = append(out.Items, t)
	}
	if len(out.Items) > limit {
		out.Items = out.Items[:limit]
		out.NextCursor = strconv.Itoa(offset + limit)
	}
	return out, rows.Err()
}
func (s *Store) TaskByID(ctx context.Context, id string) (domain.Task, error) {
	defer observeSQL(time.Now())
	t, e := scanTask(s.db.QueryRowContext(ctx, s.q("SELECT id,type,state,node_id,idempotency_key,requested_by,error_code,error_message,payload,config_revision_id,expected_revision_id,upgrade_plan_id,expires_at,cancel_requested_at,created_at,updated_at FROM tasks WHERE id=?"), id))
	if e != nil {
		return t, e
	}
	rows, e := s.db.QueryContext(ctx, s.q("SELECT id,task_id,name,state,attempt,error_code,output,created_at,updated_at FROM task_steps WHERE task_id=? ORDER BY created_at,id"), id)
	if e != nil {
		return t, e
	}
	defer rows.Close()
	t.Steps = []domain.TaskStep{}
	for rows.Next() {
		var v domain.TaskStep
		var ca, ua int64
		if e := rows.Scan(&v.ID, &v.TaskID, &v.Name, &v.State, &v.Attempt, &v.ErrorCode, &v.Output, &ca, &ua); e != nil {
			return t, e
		}
		v.CreatedAt = instant(ca)
		v.UpdatedAt = instant(ua)
		t.Steps = append(t.Steps, v)
	}
	return t, rows.Err()
}

func (s *Store) TaskByIdempotency(ctx context.Context, nodeID, key string) (domain.Task, error) {
	return scanTask(s.db.QueryRowContext(ctx, s.q("SELECT id,type,state,node_id,idempotency_key,requested_by,error_code,error_message,payload,config_revision_id,expected_revision_id,upgrade_plan_id,expires_at,cancel_requested_at,created_at,updated_at FROM tasks WHERE node_id=? AND idempotency_key=?"), nodeID, key))
}
func (s *Store) CreateTask(ctx context.Context, t domain.Task, step domain.TaskStep) error {
	defer observeSQL(time.Now())
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if dangerousTaskType(t.Type) {
		if e = s.ensureDangerousTaskAllowed(ctx, tx, t.NodeID); e != nil {
			return e
		}
	}
	_, e = tx.ExecContext(ctx, s.q("INSERT INTO tasks(id,type,state,node_id,idempotency_key,requested_by,error_code,error_message,payload,config_revision_id,expected_revision_id,upgrade_plan_id,expires_at,cancel_requested_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"), t.ID, t.Type, t.State, t.NodeID, t.IdempotencyKey, t.RequestedBy, t.ErrorCode, t.ErrorMessage, t.Payload, t.ConfigRevisionID, t.ExpectedRevisionID, t.UpgradePlanID, nullable(t.ExpiresAt), nullable(t.CancelRequestedAt), micros(t.CreatedAt), micros(t.UpdatedAt))
	if e != nil {
		return translate(e)
	}
	_, e = tx.ExecContext(ctx, s.q("INSERT INTO task_steps(id,task_id,name,state,attempt,error_code,output,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)"), step.ID, t.ID, step.Name, step.State, step.Attempt, step.ErrorCode, step.Output, micros(step.CreatedAt), micros(step.UpdatedAt))
	if e != nil {
		return translate(e)
	}
	if e = s.appendMutationAudit(ctx, tx); e != nil {
		return e
	}
	return tx.Commit()
}

func (s *Store) CreateUpgradePlanTask(ctx context.Context, v domain.UpgradePlan, t domain.Task, step domain.TaskStep) error {
	defer observeSQL(time.Now())
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = s.ensureDangerousTaskAllowed(ctx, tx, t.NodeID); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, s.q("INSERT INTO upgrade_plans(id,node_id,version,artifact_ciphertext,artifact_nonce,artifact_key_version,sha256,state,task_id,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)"), v.ID, v.NodeID, v.Version, v.ArtifactCiphertext, v.ArtifactNonce, v.ArtifactKeyVersion, v.SHA256, v.State, v.TaskID, v.CreatedBy, micros(v.CreatedAt), micros(v.UpdatedAt)); e != nil {
		return translate(e)
	}
	if _, e = tx.ExecContext(ctx, s.q("INSERT INTO tasks(id,type,state,node_id,idempotency_key,requested_by,error_code,error_message,payload,config_revision_id,expected_revision_id,upgrade_plan_id,expires_at,cancel_requested_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"), t.ID, t.Type, t.State, t.NodeID, t.IdempotencyKey, t.RequestedBy, t.ErrorCode, t.ErrorMessage, t.Payload, t.ConfigRevisionID, t.ExpectedRevisionID, t.UpgradePlanID, nullable(t.ExpiresAt), nullable(t.CancelRequestedAt), micros(t.CreatedAt), micros(t.UpdatedAt)); e != nil {
		return translate(e)
	}
	if _, e = tx.ExecContext(ctx, s.q("INSERT INTO task_steps(id,task_id,name,state,attempt,error_code,output,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)"), step.ID, t.ID, step.Name, step.State, step.Attempt, step.ErrorCode, step.Output, micros(step.CreatedAt), micros(step.UpdatedAt)); e != nil {
		return translate(e)
	}
	if e = s.appendMutationAudit(ctx, tx); e != nil {
		return e
	}
	return tx.Commit()
}

func scanUpgradePlan(row interface{ Scan(...any) error }) (domain.UpgradePlan, error) {
	var v domain.UpgradePlan
	var created, updated int64
	e := row.Scan(&v.ID, &v.NodeID, &v.Version, &v.ArtifactCiphertext, &v.ArtifactNonce, &v.ArtifactKeyVersion, &v.SHA256, &v.State, &v.TaskID, &v.CreatedBy, &created, &updated)
	v.CreatedAt, v.UpdatedAt = instant(created), instant(updated)
	return v, translate(e)
}
func (s *Store) UpgradePlanByID(ctx context.Context, id string) (domain.UpgradePlan, error) {
	defer observeSQL(time.Now())
	return scanUpgradePlan(s.db.QueryRowContext(ctx, s.q("SELECT id,node_id,version,artifact_ciphertext,artifact_nonce,artifact_key_version,sha256,state,task_id,created_by,created_at,updated_at FROM upgrade_plans WHERE id=?"), id))
}
func (s *Store) ListUpgradePlans(ctx context.Context, limit int, cursor, nodeID, state string) (domain.Page[domain.UpgradePlan], error) {
	defer observeSQL(time.Now())
	offset := decodeCursor(cursor)
	q := "SELECT id,node_id,version,artifact_ciphertext,artifact_nonce,artifact_key_version,sha256,state,task_id,created_by,created_at,updated_at FROM upgrade_plans WHERE 1=1"
	args := []any{}
	if nodeID != "" {
		q += " AND node_id=?"
		args = append(args, nodeID)
	}
	if state != "" {
		q += " AND state=?"
		args = append(args, state)
	}
	q += " ORDER BY created_at DESC,id DESC LIMIT ? OFFSET ?"
	args = append(args, limit+1, offset)
	rows, e := s.db.QueryContext(ctx, s.q(q), args...)
	if e != nil {
		return domain.Page[domain.UpgradePlan]{}, e
	}
	defer rows.Close()
	out := domain.Page[domain.UpgradePlan]{Items: []domain.UpgradePlan{}}
	for rows.Next() {
		v, scanErr := scanUpgradePlan(rows)
		if scanErr != nil {
			return out, scanErr
		}
		out.Items = append(out.Items, v)
	}
	if len(out.Items) > limit {
		out.Items = out.Items[:limit]
		out.NextCursor = strconv.Itoa(offset + limit)
	}
	return out, rows.Err()
}

func (s *Store) ReplaceRuntimeSnapshot(ctx context.Context, v domain.RuntimeSnapshot) error {
	defer observeSQL(time.Now())
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	lockQuery := "SELECT collected_at FROM runtime_snapshots WHERE node_id=?"
	if s.dialect != "sqlite" {
		lockQuery += " FOR UPDATE"
	}
	var currentCollected int64
	e = tx.QueryRowContext(ctx, s.q(lockQuery), v.NodeID).Scan(&currentCollected)
	if e != nil && !errors.Is(e, sql.ErrNoRows) {
		return e
	}
	if e == nil && currentCollected > micros(v.CollectedAt) {
		return tx.Commit()
	}
	query := "INSERT INTO runtime_snapshots(node_id,role,frp_version,collected_at,bind_address,bind_port,proxy_count,client_count,updated_at) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(node_id) DO UPDATE SET role=excluded.role,frp_version=excluded.frp_version,collected_at=excluded.collected_at,bind_address=excluded.bind_address,bind_port=excluded.bind_port,proxy_count=excluded.proxy_count,client_count=excluded.client_count,updated_at=excluded.updated_at"
	if s.dialect == "mysql" {
		query = "INSERT INTO runtime_snapshots(node_id,role,frp_version,collected_at,bind_address,bind_port,proxy_count,client_count,updated_at) VALUES(?,?,?,?,?,?,?,?,?) ON DUPLICATE KEY UPDATE role=VALUES(role),frp_version=VALUES(frp_version),collected_at=VALUES(collected_at),bind_address=VALUES(bind_address),bind_port=VALUES(bind_port),proxy_count=VALUES(proxy_count),client_count=VALUES(client_count),updated_at=VALUES(updated_at)"
	}
	if _, e = tx.ExecContext(ctx, s.q(query), v.NodeID, v.Role, v.FRPVersion, micros(v.CollectedAt), v.BindAddress, v.BindPort, v.ProxyCount, v.ClientCount, micros(time.Now())); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, s.q("DELETE FROM runtime_proxies WHERE node_id=?"), v.NodeID); e != nil {
		return e
	}
	for _, p := range v.Proxies {
		if _, e = tx.ExecContext(ctx, s.q("INSERT INTO runtime_proxies(node_id,name,type,status,local_address,remote_address,last_error,bytes_in,bytes_out,today_bytes_in,today_bytes_out,current_connections,collected_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)"), v.NodeID, p.Name, p.Type, p.Status, p.LocalAddress, p.RemoteAddress, p.LastError, p.Traffic.BytesIn, p.Traffic.BytesOut, p.Traffic.TodayBytesIn, p.Traffic.TodayBytesOut, p.Traffic.CurrentConnections, micros(v.CollectedAt)); e != nil {
			return e
		}
	}
	if _, e = tx.ExecContext(ctx, s.q("DELETE FROM runtime_clients WHERE node_id=?"), v.NodeID); e != nil {
		return e
	}
	for _, c := range v.Clients {
		if _, e = tx.ExecContext(ctx, s.q("INSERT INTO runtime_clients(node_id,id,address,connected_at,collected_at) VALUES(?,?,?,?,?)"), v.NodeID, c.ID, c.Address, micros(c.ConnectedAt), micros(v.CollectedAt)); e != nil {
			return e
		}
	}
	return tx.Commit()
}
func scanRuntimeProxy(row interface{ Scan(...any) error }) (domain.RuntimeProxy, error) {
	var v domain.RuntimeProxy
	var collected int64
	e := row.Scan(&v.NodeID, &v.NodeName, &v.Name, &v.Type, &v.Status, &v.LocalAddress, &v.RemoteAddress, &v.LastError, &v.Traffic.BytesIn, &v.Traffic.BytesOut, &v.Traffic.TodayBytesIn, &v.Traffic.TodayBytesOut, &v.Traffic.CurrentConnections, &collected)
	v.CollectedAt = instant(collected)
	return v, translate(e)
}
func (s *Store) ListRuntimeProxies(ctx context.Context, limit int, cursor, nodeID, statusValue, typeValue string) (domain.Page[domain.RuntimeProxy], error) {
	defer observeSQL(time.Now())
	offset := decodeCursor(cursor)
	q := "SELECT p.node_id,n.name,p.name,p.type,p.status,p.local_address,p.remote_address,p.last_error,p.bytes_in,p.bytes_out,p.today_bytes_in,p.today_bytes_out,p.current_connections,p.collected_at FROM runtime_proxies p JOIN nodes n ON n.id=p.node_id WHERE 1=1"
	args := []any{}
	if nodeID != "" {
		q += " AND p.node_id=?"
		args = append(args, nodeID)
	}
	if statusValue != "" {
		q += " AND p.status=?"
		args = append(args, statusValue)
	}
	if typeValue != "" {
		q += " AND p.type=?"
		args = append(args, typeValue)
	}
	q += " ORDER BY p.node_id,p.name LIMIT ? OFFSET ?"
	args = append(args, limit+1, offset)
	rows, e := s.db.QueryContext(ctx, s.q(q), args...)
	if e != nil {
		return domain.Page[domain.RuntimeProxy]{}, e
	}
	defer rows.Close()
	out := domain.Page[domain.RuntimeProxy]{Items: []domain.RuntimeProxy{}}
	for rows.Next() {
		v, scanErr := scanRuntimeProxy(rows)
		if scanErr != nil {
			return out, scanErr
		}
		out.Items = append(out.Items, v)
	}
	if len(out.Items) > limit {
		out.Items = out.Items[:limit]
		out.NextCursor = strconv.Itoa(offset + limit)
	}
	return out, rows.Err()
}
func (s *Store) RuntimeProxyByKey(ctx context.Context, nodeID, name string) (domain.RuntimeProxy, error) {
	defer observeSQL(time.Now())
	return scanRuntimeProxy(s.db.QueryRowContext(ctx, s.q("SELECT p.node_id,n.name,p.name,p.type,p.status,p.local_address,p.remote_address,p.last_error,p.bytes_in,p.bytes_out,p.today_bytes_in,p.today_bytes_out,p.current_connections,p.collected_at FROM runtime_proxies p JOIN nodes n ON n.id=p.node_id WHERE p.node_id=? AND p.name=?"), nodeID, name))
}

const deploymentRiskSelect = "SELECT id,node_id,kind,severity,state,evidence,confidence,rule_version,resource_fingerprint,repair_task_id,missed_scans,first_seen_at,last_seen_at,pending_confirmation_at,resolved_at,updated_at FROM deployment_risks"

func scanDeploymentRisk(row interface{ Scan(...any) error }) (domain.DeploymentRisk, error) {
	var v domain.DeploymentRisk
	var repair sql.NullString
	var first, last, updated int64
	var pending, resolved sql.NullInt64
	err := row.Scan(&v.ID, &v.NodeID, &v.Kind, &v.Severity, &v.State, &v.Evidence, &v.Confidence, &v.RuleVersion, &v.ResourceFingerprint, &repair, &v.MissedScans, &first, &last, &pending, &resolved, &updated)
	if repair.Valid {
		v.RepairTaskID = &repair.String
	}
	v.FirstSeenAt, v.LastSeenAt, v.UpdatedAt = instant(first), instant(last), instant(updated)
	if pending.Valid {
		value := instant(pending.Int64)
		v.PendingConfirmationAt = &value
	}
	if resolved.Valid {
		value := instant(resolved.Int64)
		v.ResolvedAt = &value
	}
	return v, translate(err)
}

func (s *Store) ListDeploymentRisks(ctx context.Context, filter domain.DeploymentRiskFilter, limit int, cursor string) (domain.Page[domain.DeploymentRisk], error) {
	defer observeSQL(time.Now())
	offset := decodeCursor(cursor)
	q, args := deploymentRiskSelect+" WHERE 1=1", []any{}
	if filter.NodeID != "" {
		q += " AND node_id=?"
		args = append(args, filter.NodeID)
	}
	if filter.Kind != "" {
		q += " AND kind=?"
		args = append(args, filter.Kind)
	}
	if filter.State == "active" {
		q += " AND state IN ('open','pending_confirmation')"
	} else if filter.State != "" {
		q += " AND state=?"
		args = append(args, filter.State)
	}
	q += " ORDER BY updated_at DESC,id DESC LIMIT ? OFFSET ?"
	args = append(args, limit+1, offset)
	rows, err := s.db.QueryContext(ctx, s.q(q), args...)
	if err != nil {
		return domain.Page[domain.DeploymentRisk]{}, err
	}
	defer rows.Close()
	out := domain.Page[domain.DeploymentRisk]{Items: []domain.DeploymentRisk{}}
	for rows.Next() {
		v, scanErr := scanDeploymentRisk(rows)
		if scanErr != nil {
			return out, scanErr
		}
		out.Items = append(out.Items, v)
	}
	if len(out.Items) > limit {
		out.Items = out.Items[:limit]
		out.NextCursor = strconv.Itoa(offset + limit)
	}
	return out, rows.Err()
}

func (s *Store) DeploymentRiskByID(ctx context.Context, id string) (domain.DeploymentRisk, error) {
	return scanDeploymentRisk(s.db.QueryRowContext(ctx, s.q(deploymentRiskSelect+" WHERE id=?"), id))
}

func (s *Store) ReconcileDeploymentRisks(ctx context.Context, nodeID, taskID, statusValue, errorCode string, findings []domain.DeploymentRiskObservation, completedKinds []string, at time.Time) error {
	_, err := s.ReconcileDeploymentRisksOnce(ctx, nodeID, taskID, statusValue, errorCode, findings, completedKinds, at)
	return err
}

func (s *Store) ReconcileDeploymentRisksOnce(ctx context.Context, nodeID, taskID, statusValue, errorCode string, findings []domain.DeploymentRiskObservation, completedKinds []string, at time.Time) (bool, error) {
	defer observeSQL(time.Now())
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	applied, err := s.reconcileDeploymentRisksTx(ctx, tx, nodeID, taskID, statusValue, errorCode, findings, completedKinds, at)
	if err != nil {
		return false, err
	}
	if err = tx.Commit(); err != nil {
		return false, err
	}
	return applied, nil
}

func (s *Store) reconcileDeploymentRisksTx(ctx context.Context, tx *sql.Tx, nodeID, taskID, statusValue, errorCode string, findings []domain.DeploymentRiskObservation, completedKinds []string, at time.Time) (bool, error) {
	var err error
	if _, err := s.lockNodeMode(ctx, tx, nodeID); err != nil {
		return false, err
	}
	if taskID != "" {
		var existing int
		if err := tx.QueryRowContext(ctx, s.q("SELECT COUNT(*) FROM deployment_risk_scans WHERE task_id=?"), taskID).Scan(&existing); err != nil {
			return false, err
		}
		if existing > 0 {
			return false, nil
		}
	}
	var scanTaskID any
	if taskID != "" {
		scanTaskID = taskID
	}
	if _, err := tx.ExecContext(ctx, s.q("INSERT INTO deployment_risk_scans(id,node_id,task_id,status,error_code,finding_count,scanned_at) VALUES(?,?,?,?,?,?,?)"), uuid.Must(uuid.NewV7()).String(), nodeID, scanTaskID, statusValue, errorCode, len(findings), micros(at)); err != nil {
		return false, translate(err)
	}
	seen := make(map[string]struct{}, len(findings))
	for _, finding := range findings {
		if _, duplicate := seen[finding.Kind]; duplicate {
			continue
		}
		seen[finding.Kind] = struct{}{}
		result, updateErr := tx.ExecContext(ctx, s.q("UPDATE deployment_risks SET severity=?,state='open',evidence=?,confidence=?,rule_version=?,resource_fingerprint=?,missed_scans=0,last_seen_at=?,pending_confirmation_at=NULL,resolved_at=NULL,updated_at=? WHERE node_id=? AND kind=?"), finding.Severity, finding.Evidence, finding.Confidence, finding.RuleVersion, finding.ResourceFingerprint, micros(at), micros(at), nodeID, finding.Kind)
		if updateErr != nil {
			return false, updateErr
		}
		rows, _ := result.RowsAffected()
		if rows == 0 {
			if _, err = tx.ExecContext(ctx, s.q("INSERT INTO deployment_risks(id,node_id,kind,severity,state,evidence,confidence,rule_version,resource_fingerprint,repair_task_id,missed_scans,first_seen_at,last_seen_at,pending_confirmation_at,resolved_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"), uuid.Must(uuid.NewV7()).String(), nodeID, finding.Kind, finding.Severity, "open", finding.Evidence, finding.Confidence, finding.RuleVersion, finding.ResourceFingerprint, nil, 0, micros(at), micros(at), nil, nil, micros(at)); err != nil {
				return false, translate(err)
			}
		}
	}
	completed := make(map[string]struct{}, len(completedKinds))
	for _, kind := range completedKinds {
		completed[kind] = struct{}{}
	}
	if len(completed) == 0 {
		return true, nil
	}
	rows, err := tx.QueryContext(ctx, s.q("SELECT id,kind,missed_scans FROM deployment_risks WHERE node_id=? AND state IN ('open','pending_confirmation')"), nodeID)
	if err != nil {
		return false, err
	}
	type absent struct {
		id     string
		missed int
	}
	missing := []absent{}
	for rows.Next() {
		var id, kind string
		var missed int
		if err = rows.Scan(&id, &kind, &missed); err != nil {
			rows.Close()
			return false, err
		}
		_, ruleComplete := completed[kind]
		if _, ok := seen[kind]; !ok && ruleComplete {
			missing = append(missing, absent{id, missed})
		}
	}
	if err = rows.Close(); err != nil {
		return false, err
	}
	for _, item := range missing {
		missed := item.missed + 1
		if missed >= 2 {
			if _, err = tx.ExecContext(ctx, s.q("UPDATE deployment_risks SET state='resolved',missed_scans=?,resolved_at=?,updated_at=? WHERE id=?"), missed, micros(at), micros(at), item.id); err != nil {
				return false, err
			}
		} else if _, err = tx.ExecContext(ctx, s.q("UPDATE deployment_risks SET state='pending_confirmation',missed_scans=?,pending_confirmation_at=?,updated_at=? WHERE id=?"), missed, micros(at), micros(at), item.id); err != nil {
			return false, err
		}
	}
	return true, nil
}

func (s *Store) CompleteRiskScanTask(ctx context.Context, t domain.Task, state, errorCode, diagnostic, stepOutput, scanStatus, scanError string, findings []domain.DeploymentRiskObservation, completedKinds []string, at time.Time) (domain.TaskCompletionOutcome, error) {
	defer observeSQL(time.Now())
	outcome := domain.TaskCompletionOutcome{}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return outcome, err
	}
	defer tx.Rollback()
	var current, nodeID string
	if err = tx.QueryRowContext(ctx, s.q("SELECT state,node_id FROM tasks WHERE id=?"), t.ID).Scan(&current, &nodeID); err != nil {
		return outcome, translate(err)
	}
	if nodeID != t.NodeID || (t.Type != "risk_scan" && t.Type != "inspect") {
		return outcome, storepkg.ErrConflict
	}
	outcome.FinalState = current
	if terminalTaskState(current) {
		if current == state {
			return outcome, nil
		}
		return outcome, storepkg.ErrConflict
	}
	if !allowedTaskTransition(current, state) {
		return outcome, storepkg.ErrConflict
	}
	result, err := tx.ExecContext(ctx, s.q("UPDATE tasks SET state=?,error_code=?,error_message=?,updated_at=? WHERE id=? AND state=?"), state, errorCode, diagnostic, micros(at), t.ID, current)
	if err != nil {
		return outcome, err
	}
	if rows, _ := result.RowsAffected(); rows != 1 {
		return outcome, storepkg.ErrConflict
	}
	if stepOutput == "" {
		stepOutput = diagnostic
	}
	if _, err = tx.ExecContext(ctx, s.q("UPDATE task_steps SET state=?,error_code=?,output=?,updated_at=? WHERE task_id=?"), state, errorCode, stepOutput, micros(at), t.ID); err != nil {
		return outcome, err
	}
	applied, err := s.reconcileDeploymentRisksTx(ctx, tx, t.NodeID, t.ID, scanStatus, scanError, findings, completedKinds, at)
	if err != nil {
		return outcome, err
	}
	if !applied {
		return outcome, storepkg.ErrConflict
	}
	if err = tx.Commit(); err != nil {
		return outcome, err
	}
	outcome.FinalState, outcome.Transitioned = state, true
	return outcome, nil
}

func (s *Store) CreateDeploymentRiskRepairTask(ctx context.Context, findingID string, t domain.Task, step domain.TaskStep) error {
	return s.createDeploymentRiskRepairTask(ctx, findingID, nil, t, step)
}

func (s *Store) CreateDerivedDeploymentRiskRepairTask(ctx context.Context, findingID string, revision domain.ConfigRevision, t domain.Task, step domain.TaskStep) error {
	return s.createDeploymentRiskRepairTask(ctx, findingID, &revision, t, step)
}

func (s *Store) createDeploymentRiskRepairTask(ctx context.Context, findingID string, revision *domain.ConfigRevision, t domain.Task, step domain.TaskStep) error {
	defer observeSQL(time.Now())
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	lock := "SELECT node_id,state FROM deployment_risks WHERE id=?"
	if s.dialect != "sqlite" {
		lock += " FOR UPDATE"
	}
	var nodeID, state string
	if err = tx.QueryRowContext(ctx, s.q(lock), findingID).Scan(&nodeID, &state); err != nil {
		return translate(err)
	}
	if nodeID != t.NodeID || state != "open" {
		return storepkg.ErrConflict
	}
	if err = s.ensureDangerousTaskAllowed(ctx, tx, nodeID); err != nil {
		return err
	}
	if revision != nil {
		if revision.NodeID != nodeID || t.ConfigRevisionID == nil || *t.ConfigRevisionID != revision.ID {
			return storepkg.ErrConflict
		}
		if _, err = tx.ExecContext(ctx, s.q("INSERT INTO config_revisions(id,node_id,version,encrypted_content,nonce,sha256,strategy,created_by,created_at,mode,sensitive_fields) VALUES(?,?,?,?,?,?,?,?,?,?,?)"), revision.ID, revision.NodeID, revision.Version, revision.EncryptedContent, revision.Nonce, revision.SHA256, revision.Strategy, revision.CreatedBy, micros(revision.CreatedAt), revision.Mode, revision.SensitiveFields); err != nil {
			return translate(err)
		}
	}
	if _, err = tx.ExecContext(ctx, s.q("INSERT INTO tasks(id,type,state,node_id,idempotency_key,requested_by,error_code,error_message,payload,config_revision_id,expected_revision_id,upgrade_plan_id,expires_at,cancel_requested_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"), t.ID, t.Type, t.State, t.NodeID, t.IdempotencyKey, t.RequestedBy, t.ErrorCode, t.ErrorMessage, t.Payload, t.ConfigRevisionID, t.ExpectedRevisionID, t.UpgradePlanID, nullable(t.ExpiresAt), nullable(t.CancelRequestedAt), micros(t.CreatedAt), micros(t.UpdatedAt)); err != nil {
		return translate(err)
	}
	if _, err = tx.ExecContext(ctx, s.q("INSERT INTO task_steps(id,task_id,name,state,attempt,error_code,output,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)"), step.ID, t.ID, step.Name, step.State, step.Attempt, step.ErrorCode, step.Output, micros(step.CreatedAt), micros(step.UpdatedAt)); err != nil {
		return translate(err)
	}
	if _, err = tx.ExecContext(ctx, s.q("UPDATE deployment_risks SET repair_task_id=?,updated_at=? WHERE id=?"), t.ID, micros(t.UpdatedAt), findingID); err != nil {
		return err
	}
	if err = s.appendMutationAudit(ctx, tx); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) RuntimeSnapshotByNode(ctx context.Context, nodeID string) (domain.RuntimeSnapshot, error) {
	defer observeSQL(time.Now())
	var v domain.RuntimeSnapshot
	var collected int64
	e := s.db.QueryRowContext(ctx, s.q("SELECT node_id,role,frp_version,collected_at,bind_address,bind_port,proxy_count,client_count FROM runtime_snapshots WHERE node_id=?"), nodeID).Scan(&v.NodeID, &v.Role, &v.FRPVersion, &collected, &v.BindAddress, &v.BindPort, &v.ProxyCount, &v.ClientCount)
	if e != nil {
		return v, translate(e)
	}
	v.CollectedAt = instant(collected)
	v.Proxies = []domain.RuntimeProxy{}
	proxyRows, e := s.db.QueryContext(ctx, s.q("SELECT p.node_id,n.name,p.name,p.type,p.status,p.local_address,p.remote_address,p.last_error,p.bytes_in,p.bytes_out,p.today_bytes_in,p.today_bytes_out,p.current_connections,p.collected_at FROM runtime_proxies p JOIN nodes n ON n.id=p.node_id WHERE p.node_id=? ORDER BY p.name"), nodeID)
	if e != nil {
		return v, e
	}
	for proxyRows.Next() {
		proxy, scanErr := scanRuntimeProxy(proxyRows)
		if scanErr != nil {
			proxyRows.Close()
			return v, scanErr
		}
		v.Proxies = append(v.Proxies, proxy)
	}
	if e = proxyRows.Close(); e != nil {
		return v, e
	}
	v.Clients = []domain.RuntimeClient{}
	rows, e := s.db.QueryContext(ctx, s.q("SELECT id,address,connected_at FROM runtime_clients WHERE node_id=? ORDER BY id"), nodeID)
	if e != nil {
		return v, e
	}
	defer rows.Close()
	for rows.Next() {
		var c domain.RuntimeClient
		var connected int64
		if e = rows.Scan(&c.ID, &c.Address, &connected); e != nil {
			return v, e
		}
		c.ConnectedAt = instant(connected)
		v.Clients = append(v.Clients, c)
	}
	return v, rows.Err()
}
func (s *Store) CompleteConfigTask(ctx context.Context, t domain.Task, state, errorCode, diagnostic, stepOutput, observedHash string, at time.Time) (domain.TaskCompletionOutcome, error) {
	outcome := domain.TaskCompletionOutcome{}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return outcome, e
	}
	defer tx.Rollback()
	var current, nodeID string
	var configID, expected sql.NullString
	if e = tx.QueryRowContext(ctx, s.q("SELECT state,node_id,config_revision_id,expected_revision_id FROM tasks WHERE id=?"), t.ID).Scan(&current, &nodeID, &configID, &expected); e != nil {
		return outcome, translate(e)
	}
	outcome.FinalState = current
	if nodeID != t.NodeID || (!configID.Valid && t.Type != "risk_repair") {
		return outcome, storepkg.ErrConflict
	}
	if terminalTaskState(current) {
		if current == state {
			return outcome, nil
		}
		if t.Type == "risk_repair" && state == "succeeded" {
			changed := false
			if configID.Valid {
				if observedHash == "" {
					return outcome, storepkg.ErrConflict
				}
				var proofErr error
				changed, proofErr = s.storeObservedConfigProof(ctx, tx, nodeID, configID.String, observedHash)
				if proofErr != nil {
					return outcome, proofErr
				}
			}
			audited, auditErr := s.riskRepairAppliedResultAudited(ctx, tx, t.ID)
			if auditErr != nil {
				return outcome, auditErr
			}
			if !audited {
				if _, e = tx.ExecContext(ctx, s.q("INSERT INTO audit_logs(id,actor,action,resource,request_id,created_at,outcome) VALUES(?,?,?,?,?,?,?)"), uuid.Must(uuid.NewV7()).String(), t.RequestedBy, "deployment_risk.repair.result", "task/"+t.ID, t.ID, micros(at), "late_applied"); e != nil {
					return outcome, e
				}
				changed = true
			}
			if changed {
				if e = tx.Commit(); e != nil {
					return outcome, e
				}
				outcome.AppliedDrift = true
			}
			return outcome, nil
		}
		return outcome, storepkg.ErrConflict
	}
	if !allowedTaskTransition(current, state) {
		return outcome, storepkg.ErrConflict
	}
	if state == "succeeded" && configID.Valid {
		if _, e = s.storeObservedConfigProof(ctx, tx, nodeID, configID.String, observedHash); e != nil {
			return outcome, e
		}
		var result sql.Result
		if expected.Valid {
			result, e = tx.ExecContext(ctx, s.q("UPDATE nodes SET desired_revision_id=?,updated_at=? WHERE id=? AND desired_revision_id=?"), configID.String, micros(at), nodeID, expected.String)
		} else {
			result, e = tx.ExecContext(ctx, s.q("UPDATE nodes SET desired_revision_id=?,updated_at=? WHERE id=? AND desired_revision_id IS NULL"), configID.String, micros(at), nodeID)
		}
		if e != nil {
			return outcome, e
		}
		rows, _ := result.RowsAffected()
		if rows != 1 {
			if _, e = tx.ExecContext(ctx, s.q("UPDATE tasks SET state='failed',error_code='PRECONDITION_FAILED',error_message='node revision changed before task completion',updated_at=? WHERE id=? AND state=?"), micros(at), t.ID, current); e != nil {
				return outcome, e
			}
			if _, e = tx.ExecContext(ctx, s.q("UPDATE task_steps SET state='failed',error_code='PRECONDITION_FAILED',output='node revision changed before task completion',updated_at=? WHERE task_id=?"), micros(at), t.ID); e != nil {
				return outcome, e
			}
			if t.Type == "risk_repair" {
				if _, e = tx.ExecContext(ctx, s.q("INSERT INTO audit_logs(id,actor,action,resource,request_id,created_at,outcome) VALUES(?,?,?,?,?,?,?)"), uuid.Must(uuid.NewV7()).String(), t.RequestedBy, "deployment_risk.repair.result", "task/"+t.ID, t.ID, micros(at), "applied_drift"); e != nil {
					return outcome, e
				}
			}
			if e = tx.Commit(); e != nil {
				return outcome, e
			}
			outcome.FinalState, outcome.Transitioned, outcome.AppliedDrift = "failed", true, true
			return outcome, nil
		}
	}
	result, e := tx.ExecContext(ctx, s.q("UPDATE tasks SET state=?,error_code=?,error_message=?,updated_at=? WHERE id=? AND state=?"), state, errorCode, diagnostic, micros(at), t.ID, current)
	if e != nil {
		return outcome, e
	}
	rows, _ := result.RowsAffected()
	if rows != 1 {
		return outcome, storepkg.ErrConflict
	}
	if stepOutput == "" {
		stepOutput = diagnostic
	}
	if _, e = tx.ExecContext(ctx, s.q("UPDATE task_steps SET state=?,error_code=?,output=?,updated_at=? WHERE task_id=?"), state, errorCode, stepOutput, micros(at), t.ID); e != nil {
		return outcome, e
	}
	if t.Type == "risk_repair" {
		if _, e = tx.ExecContext(ctx, s.q("INSERT INTO audit_logs(id,actor,action,resource,request_id,created_at,outcome) VALUES(?,?,?,?,?,?,?)"), uuid.Must(uuid.NewV7()).String(), t.RequestedBy, "deployment_risk.repair.result", "task/"+t.ID, t.ID, micros(at), state); e != nil {
			return outcome, e
		}
	}
	if e = tx.Commit(); e != nil {
		return outcome, e
	}
	outcome.FinalState, outcome.Transitioned = state, true
	return outcome, nil
}

func (s *Store) storeObservedConfigProof(ctx context.Context, tx *sql.Tx, nodeID, revisionID, observedHash string) (bool, error) {
	var result sql.Result
	var err error
	if observedHash != "" {
		result, err = tx.ExecContext(ctx, s.q("UPDATE node_observations SET observed_revision_id=?,observed_hash=? WHERE node_id=? AND (observed_revision_id IS NULL OR observed_revision_id<>? OR observed_hash<>?)"), revisionID, observedHash, nodeID, revisionID, observedHash)
	} else {
		result, err = tx.ExecContext(ctx, s.q("UPDATE node_observations SET observed_revision_id=? WHERE node_id=? AND (observed_revision_id IS NULL OR observed_revision_id<>?)"), revisionID, nodeID, revisionID)
	}
	if err != nil {
		return false, err
	}
	rows, err := result.RowsAffected()
	return rows > 0, err
}

func (s *Store) riskRepairAppliedResultAudited(ctx context.Context, tx *sql.Tx, taskID string) (bool, error) {
	var count int
	err := tx.QueryRowContext(ctx, s.q("SELECT COUNT(*) FROM audit_logs WHERE action='deployment_risk.repair.result' AND request_id=? AND outcome IN ('late_applied','applied_drift')"), taskID).Scan(&count)
	return count > 0, err
}

func (s *Store) CompleteTaskResult(ctx context.Context, task domain.Task, state, errorCode, errorMessage, stepOutput string, at time.Time) (domain.TaskCompletionOutcome, error) {
	outcome := domain.TaskCompletionOutcome{}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return outcome, err
	}
	defer tx.Rollback()
	var current, nodeID string
	var upgradePlan sql.NullString
	if err = tx.QueryRowContext(ctx, s.q("SELECT state,node_id,upgrade_plan_id FROM tasks WHERE id=?"), task.ID).Scan(&current, &nodeID, &upgradePlan); err != nil {
		return outcome, translate(err)
	}
	outcome.FinalState = current
	if nodeID != task.NodeID {
		return outcome, storepkg.ErrConflict
	}
	if terminalTaskState(current) {
		if current == state {
			return outcome, nil
		}
		return outcome, storepkg.ErrConflict
	}
	if !allowedTaskTransition(current, state) {
		return outcome, storepkg.ErrConflict
	}
	result, err := tx.ExecContext(ctx, s.q("UPDATE tasks SET state=?,error_code=?,error_message=?,updated_at=? WHERE id=? AND state=?"), state, errorCode, errorMessage, micros(at), task.ID, current)
	if err != nil {
		return outcome, err
	}
	if rows, _ := result.RowsAffected(); rows != 1 {
		return outcome, storepkg.ErrConflict
	}
	if stepOutput == "" {
		stepOutput = errorMessage
	}
	if _, err = tx.ExecContext(ctx, s.q("UPDATE task_steps SET state=?,error_code=?,output=?,updated_at=? WHERE task_id=?"), state, errorCode, stepOutput, micros(at), task.ID); err != nil {
		return outcome, err
	}
	if upgradePlan.Valid {
		planState := state
		if state == "dispatched" || state == "running" {
			planState = "running"
		}
		if _, err = tx.ExecContext(ctx, s.q("UPDATE upgrade_plans SET state=?,updated_at=? WHERE id=?"), planState, micros(at), upgradePlan.String); err != nil {
			return outcome, err
		}
	}
	if err = tx.Commit(); err != nil {
		return outcome, err
	}
	outcome.FinalState, outcome.Transitioned = state, true
	return outcome, nil
}

func (s *Store) UpdateTask(ctx context.Context, id, state, errorCode, errorMessage, stepState, stepOutput string, at time.Time) error {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var current string
	var upgradePlan sql.NullString
	if e = tx.QueryRowContext(ctx, s.q("SELECT state,upgrade_plan_id FROM tasks WHERE id=?"), id).Scan(&current, &upgradePlan); e != nil {
		return translate(e)
	}
	if terminalTaskState(current) {
		if current == state {
			return nil
		}
		return storepkg.ErrConflict
	}
	if !allowedTaskTransition(current, state) {
		return storepkg.ErrConflict
	}
	result, e := tx.ExecContext(ctx, s.q("UPDATE tasks SET state=?,error_code=?,error_message=?,updated_at=? WHERE id=? AND state=?"), state, errorCode, errorMessage, micros(at), id, current)
	if e != nil {
		return e
	}
	rows, e := result.RowsAffected()
	if e != nil {
		return e
	}
	if rows == 0 {
		return storepkg.ErrConflict
	}
	_, e = tx.ExecContext(ctx, s.q("UPDATE task_steps SET state=?,error_code=?,output=?,updated_at=? WHERE task_id=?"), stepState, errorCode, stepOutput, micros(at), id)
	if e != nil {
		return e
	}
	if upgradePlan.Valid {
		planState := state
		if state == "dispatched" || state == "running" {
			planState = "running"
		}
		if _, e = tx.ExecContext(ctx, s.q("UPDATE upgrade_plans SET state=?,updated_at=? WHERE id=?"), planState, micros(at), upgradePlan.String); e != nil {
			return e
		}
	}
	return tx.Commit()
}
func terminalTaskState(v string) bool { return v == "succeeded" || v == "failed" || v == "cancelled" }
func allowedTaskTransition(from, to string) bool {
	if from == to {
		return true
	}
	switch from {
	case "queued":
		return to == "dispatched"
	case "dispatched":
		return to == "queued" || to == "running" || terminalTaskState(to)
	case "running":
		return terminalTaskState(to)
	}
	return false
}

func (s *Store) CancelTask(ctx context.Context, id string, at time.Time) (domain.Task, error) {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return domain.Task{}, e
	}
	defer tx.Rollback()
	var state string
	var upgradePlan sql.NullString
	if e = tx.QueryRowContext(ctx, s.q("SELECT state,upgrade_plan_id FROM tasks WHERE id=?"), id).Scan(&state, &upgradePlan); e != nil {
		return domain.Task{}, translate(e)
	}
	if terminalTaskState(state) {
		return domain.Task{}, storepkg.ErrConflict
	}
	r, e := tx.ExecContext(ctx, s.q("UPDATE tasks SET state='cancelled',error_code='CANCELLED',error_message='cancelled by user',cancel_requested_at=?,updated_at=? WHERE id=? AND state=?"), micros(at), micros(at), id, state)
	if e != nil {
		return domain.Task{}, e
	}
	if n, _ := r.RowsAffected(); n != 1 {
		return domain.Task{}, storepkg.ErrConflict
	}
	if _, e = tx.ExecContext(ctx, s.q("UPDATE task_steps SET state='cancelled',error_code='CANCELLED',output='cancelled by user',updated_at=? WHERE task_id=?"), micros(at), id); e != nil {
		return domain.Task{}, e
	}
	if upgradePlan.Valid {
		if _, e = tx.ExecContext(ctx, s.q("UPDATE upgrade_plans SET state='cancelled',updated_at=? WHERE id=?"), micros(at), upgradePlan.String); e != nil {
			return domain.Task{}, e
		}
	}
	if e = s.appendMutationAudit(ctx, tx); e != nil {
		return domain.Task{}, e
	}
	if e = tx.Commit(); e != nil {
		return domain.Task{}, e
	}
	return s.TaskByID(ctx, id)
}

func (s *Store) ExpireTasks(ctx context.Context, at time.Time, limit int) ([]domain.Task, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, e := s.db.QueryContext(ctx, s.q("SELECT id FROM tasks WHERE state IN ('queued','dispatched','running') AND expires_at IS NOT NULL AND expires_at<=? ORDER BY expires_at LIMIT ?"), micros(at), limit)
	if e != nil {
		return nil, e
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			rows.Close()
			return nil, e
		}
		ids = append(ids, id)
	}
	if e = rows.Close(); e != nil {
		return nil, e
	}
	out := make([]domain.Task, 0, len(ids))
	for _, id := range ids {
		tx, updateErr := s.db.BeginTx(ctx, nil)
		if updateErr != nil {
			return out, updateErr
		}
		r, updateErr := tx.ExecContext(ctx, s.q("UPDATE tasks SET state='failed',error_code='TIMEOUT',error_message='task deadline exceeded',updated_at=? WHERE id=? AND state IN ('queued','dispatched','running')"), micros(at), id)
		if updateErr != nil {
			tx.Rollback()
			return out, updateErr
		}
		if n, _ := r.RowsAffected(); n != 1 {
			tx.Rollback()
			continue
		}
		if _, updateErr = tx.ExecContext(ctx, s.q("UPDATE task_steps SET state='failed',error_code='TIMEOUT',output='task deadline exceeded',updated_at=? WHERE task_id=?"), micros(at), id); updateErr != nil {
			tx.Rollback()
			return out, updateErr
		}
		if _, updateErr = tx.ExecContext(ctx, s.q("UPDATE upgrade_plans SET state='failed',updated_at=? WHERE id=(SELECT upgrade_plan_id FROM tasks WHERE id=?)"), micros(at), id); updateErr != nil {
			tx.Rollback()
			return out, updateErr
		}
		if updateErr = tx.Commit(); updateErr != nil {
			return out, updateErr
		}
		v, loadErr := s.TaskByID(ctx, id)
		if loadErr != nil {
			return out, loadErr
		}
		out = append(out, v)
	}
	return out, nil
}

func (s *Store) CreateAlert(ctx context.Context, v domain.Alert) error {
	defer observeSQL(time.Now())
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if _, e = tx.ExecContext(ctx, s.q("INSERT INTO alerts(id,kind,severity,state,resource,fingerprint,active_fingerprint,message,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)"), v.ID, v.Kind, v.Severity, v.State, v.Resource, v.Fingerprint, v.Fingerprint, v.Message, micros(v.CreatedAt), micros(v.UpdatedAt)); e != nil {
		return translate(e)
	}
	if storepkg.WebhookDeliveryEnabled(ctx) {
		if e = insertWebhookDelivery(ctx, tx, s.q, v, "alert.opened"); e != nil {
			return e
		}
	}
	return tx.Commit()
}

func insertWebhookDelivery(ctx context.Context, tx *sql.Tx, quote func(string) string, v domain.Alert, eventType string) error {
	payload, e := json.Marshal(v)
	if e != nil {
		return e
	}
	now := v.UpdatedAt
	_, e = tx.ExecContext(ctx, quote("INSERT INTO webhook_deliveries(id,alert_id,event_type,payload,state,attempts,next_attempt_at,last_error,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)"), uuid.Must(uuid.NewV7()).String(), v.ID, eventType, string(payload), "pending", 0, micros(now), "", micros(now), micros(now))
	return translate(e)
}

func scanAlert(row interface{ Scan(...any) error }) (domain.Alert, error) {
	var v domain.Alert
	var created, updated int64
	var acknowledgedBy, resolvedBy, closedBy sql.NullString
	var acknowledgedAt, resolvedAt, closedAt sql.NullInt64
	e := row.Scan(&v.ID, &v.Kind, &v.Severity, &v.State, &v.Resource, &v.Fingerprint, &v.Message, &created, &updated, &acknowledgedBy, &acknowledgedAt, &resolvedBy, &resolvedAt, &closedBy, &closedAt)
	if e != nil {
		return v, translate(e)
	}
	v.CreatedAt, v.UpdatedAt = instant(created), instant(updated)
	if acknowledgedBy.Valid {
		v.AcknowledgedBy = acknowledgedBy.String
	}
	if acknowledgedAt.Valid {
		t := instant(acknowledgedAt.Int64)
		v.AcknowledgedAt = &t
	}
	if resolvedBy.Valid {
		v.ResolvedBy = resolvedBy.String
	}
	if resolvedAt.Valid {
		t := instant(resolvedAt.Int64)
		v.ResolvedAt = &t
	}
	if closedBy.Valid {
		v.ClosedBy = closedBy.String
	}
	if closedAt.Valid {
		t := instant(closedAt.Int64)
		v.ClosedAt = &t
	}
	return v, nil
}

func (s *Store) ListAlerts(ctx context.Context, limit int, cursor, state string) (domain.Page[domain.Alert], error) {
	defer observeSQL(time.Now())
	offset := decodeCursor(cursor)
	q := "SELECT id,kind,severity,state,resource,fingerprint,message,created_at,updated_at,acknowledged_by,acknowledged_at,resolved_by,resolved_at,closed_by,closed_at FROM alerts WHERE 1=1"
	args := []any{}
	if state != "" {
		q += " AND state=?"
		args = append(args, state)
	}
	q += " ORDER BY created_at DESC,id DESC LIMIT ? OFFSET ?"
	args = append(args, limit+1, offset)
	rows, e := s.db.QueryContext(ctx, s.q(q), args...)
	if e != nil {
		return domain.Page[domain.Alert]{}, e
	}
	defer rows.Close()
	out := domain.Page[domain.Alert]{Items: []domain.Alert{}}
	for rows.Next() {
		v, scanErr := scanAlert(rows)
		if scanErr != nil {
			return out, scanErr
		}
		out.Items = append(out.Items, v)
	}
	if len(out.Items) > limit {
		out.Items = out.Items[:limit]
		out.NextCursor = strconv.Itoa(offset + limit)
	}
	return out, rows.Err()
}

func (s *Store) UpdateAlertState(ctx context.Context, id, target, actor string, at time.Time) (domain.Alert, error) {
	defer observeSQL(time.Now())
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return domain.Alert{}, e
	}
	defer tx.Rollback()
	selectSQL := "SELECT id,kind,severity,state,resource,fingerprint,message,created_at,updated_at,acknowledged_by,acknowledged_at,resolved_by,resolved_at,closed_by,closed_at FROM alerts WHERE id=?"
	v, e := scanAlert(tx.QueryRowContext(ctx, s.q(selectSQL), id))
	if e != nil {
		return domain.Alert{}, e
	}
	allowed := (target == "acknowledged" && v.State == "open") || (target == "resolved" && (v.State == "open" || v.State == "acknowledged")) || (target == "closed" && (v.State == "acknowledged" || v.State == "resolved"))
	if !allowed {
		return domain.Alert{}, storepkg.ErrConflict
	}
	var query string
	switch target {
	case "acknowledged":
		query = "UPDATE alerts SET state=?,updated_at=?,acknowledged_by=?,acknowledged_at=? WHERE id=? AND state=?"
		v.AcknowledgedBy, v.AcknowledgedAt = actor, &at
	case "resolved":
		query = "UPDATE alerts SET state=?,updated_at=?,resolved_by=?,resolved_at=?,active_fingerprint=NULL WHERE id=? AND state=?"
		v.ResolvedBy, v.ResolvedAt = actor, &at
	case "closed":
		query = "UPDATE alerts SET state=?,updated_at=?,closed_by=?,closed_at=?,active_fingerprint=NULL WHERE id=? AND state=?"
		v.ClosedBy, v.ClosedAt = actor, &at
	default:
		return domain.Alert{}, storepkg.ErrConflict
	}
	r, e := tx.ExecContext(ctx, s.q(query), target, micros(at), actor, micros(at), id, v.State)
	if e != nil {
		return domain.Alert{}, e
	}
	if n, _ := r.RowsAffected(); n != 1 {
		return domain.Alert{}, storepkg.ErrConflict
	}
	v.State, v.UpdatedAt = target, at
	if storepkg.WebhookDeliveryEnabled(ctx) {
		if e = insertWebhookDelivery(ctx, tx, s.q, v, "alert."+target); e != nil {
			return domain.Alert{}, e
		}
	}
	if e = s.appendMutationAudit(ctx, tx); e != nil {
		return domain.Alert{}, e
	}
	if e = tx.Commit(); e != nil {
		return domain.Alert{}, e
	}
	return v, nil
}

func scanDelivery(row interface{ Scan(...any) error }) (domain.WebhookDelivery, error) {
	var v domain.WebhookDelivery
	var next, created, updated int64
	var lease, delivered sql.NullInt64
	e := row.Scan(&v.ID, &v.AlertID, &v.EventType, &v.Payload, &v.State, &v.Attempts, &next, &lease, &v.LastError, &created, &updated, &delivered)
	if e != nil {
		return v, translate(e)
	}
	v.NextAttemptAt, v.CreatedAt, v.UpdatedAt = instant(next), instant(created), instant(updated)
	if lease.Valid {
		t := instant(lease.Int64)
		v.LeaseUntil = &t
	}
	if delivered.Valid {
		t := instant(delivered.Int64)
		v.DeliveredAt = &t
	}
	return v, nil
}

func (s *Store) LeaseWebhookDeliveries(ctx context.Context, at time.Time, lease time.Duration, limit int) ([]domain.WebhookDelivery, error) {
	defer observeSQL(time.Now())
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	rows, e := s.db.QueryContext(ctx, s.q("SELECT id FROM webhook_deliveries WHERE (state='pending' AND next_attempt_at<=?) OR (state='leased' AND lease_until<=?) ORDER BY next_attempt_at,id LIMIT ?"), micros(at), micros(at), limit)
	if e != nil {
		return nil, e
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			rows.Close()
			return nil, e
		}
		ids = append(ids, id)
	}
	if e = rows.Close(); e != nil {
		return nil, e
	}
	out := make([]domain.WebhookDelivery, 0, len(ids))
	for _, id := range ids {
		tx, txErr := s.db.BeginTx(ctx, nil)
		if txErr != nil {
			return out, txErr
		}
		until := at.Add(lease)
		r, updateErr := tx.ExecContext(ctx, s.q("UPDATE webhook_deliveries SET state='leased',attempts=attempts+1,lease_until=?,updated_at=? WHERE id=? AND ((state='pending' AND next_attempt_at<=?) OR (state='leased' AND lease_until<=?))"), micros(until), micros(at), id, micros(at), micros(at))
		if updateErr != nil {
			tx.Rollback()
			return out, updateErr
		}
		if n, _ := r.RowsAffected(); n != 1 {
			tx.Rollback()
			continue
		}
		v, loadErr := scanDelivery(tx.QueryRowContext(ctx, s.q("SELECT id,alert_id,event_type,payload,state,attempts,next_attempt_at,lease_until,last_error,created_at,updated_at,delivered_at FROM webhook_deliveries WHERE id=?"), id))
		if loadErr != nil {
			tx.Rollback()
			return out, loadErr
		}
		if txErr = tx.Commit(); txErr != nil {
			return out, txErr
		}
		out = append(out, v)
	}
	return out, nil
}

func (s *Store) CompleteWebhookDelivery(ctx context.Context, id string, success bool, next time.Time, lastError string, maxAttempts int) error {
	defer observeSQL(time.Now())
	state := "pending"
	if success {
		state = "delivered"
	}
	if len(lastError) > 1024 {
		lastError = lastError[:1024]
	}
	var attempts int
	if e := s.db.QueryRowContext(ctx, s.q("SELECT attempts FROM webhook_deliveries WHERE id=? AND state='leased'"), id).Scan(&attempts); e != nil {
		return translate(e)
	}
	if !success && attempts >= maxAttempts {
		state = "dead"
	}
	delivered := any(nil)
	if success {
		delivered = micros(next)
	}
	r, e := s.db.ExecContext(ctx, s.q("UPDATE webhook_deliveries SET state=?,next_attempt_at=?,lease_until=NULL,last_error=?,updated_at=?,delivered_at=? WHERE id=? AND state='leased'"), state, micros(next), lastError, micros(next), delivered, id)
	if e != nil {
		return e
	}
	if n, _ := r.RowsAffected(); n != 1 {
		return storepkg.ErrConflict
	}
	return nil
}
func (s *Store) AppendAudit(ctx context.Context, actor, action, resource, requestID string) error {
	return s.AppendAuditResult(ctx, actor, action, resource, requestID, "success")
}
func (s *Store) AppendAuditResult(ctx context.Context, actor, action, resource, requestID, outcome string) error {
	_, e := s.db.ExecContext(ctx, s.q("INSERT INTO audit_logs(id,actor,action,resource,request_id,created_at,outcome) VALUES(?,?,?,?,?,?,?)"), uuid.Must(uuid.NewV7()).String(), actor, action, resource, requestID, micros(time.Now()), outcome)
	return e
}
func (s *Store) ListAuditLogs(ctx context.Context, f domain.AuditFilter, limit int, cursor string) (domain.Page[domain.AuditLog], error) {
	defer observeSQL(time.Now())
	offset := decodeCursor(cursor)
	q := "SELECT id,actor,action,resource,request_id,outcome,created_at FROM audit_logs WHERE 1=1"
	args := []any{}
	if f.Actor != "" {
		q += " AND actor=?"
		args = append(args, f.Actor)
	}
	if f.Action != "" {
		q += " AND action=?"
		args = append(args, f.Action)
	}
	if f.Resource != "" {
		q += " AND resource=?"
		args = append(args, f.Resource)
	}
	if f.From != nil {
		q += " AND created_at>=?"
		args = append(args, micros(*f.From))
	}
	if f.To != nil {
		q += " AND created_at<=?"
		args = append(args, micros(*f.To))
	}
	q += " ORDER BY created_at DESC,id DESC LIMIT ? OFFSET ?"
	args = append(args, limit+1, offset)
	rows, e := s.db.QueryContext(ctx, s.q(q), args...)
	if e != nil {
		return domain.Page[domain.AuditLog]{}, e
	}
	defer rows.Close()
	out := domain.Page[domain.AuditLog]{Items: []domain.AuditLog{}}
	for rows.Next() {
		var v domain.AuditLog
		var created int64
		if e = rows.Scan(&v.ID, &v.Actor, &v.Action, &v.Resource, &v.RequestID, &v.Outcome, &created); e != nil {
			return out, e
		}
		v.CreatedAt = instant(created)
		out.Items = append(out.Items, v)
	}
	if len(out.Items) > limit {
		out.Items = out.Items[:limit]
		out.NextCursor = strconv.Itoa(offset + limit)
	}
	return out, rows.Err()
}
func decodeCursor(v string) int {
	if v == "" {
		return 0
	}
	n, e := strconv.Atoi(v)
	if e != nil || n < 0 {
		return 0
	}
	return n
}

var _ storepkg.Store = (*Store)(nil)
