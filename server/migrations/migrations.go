package migrations

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
)

//go:embed sqlite/*.sql mysql/*.sql postgres/*.sql
var files embed.FS

func Apply(ctx context.Context, db *sql.DB, dialect string) error {
	entries, err := files.ReadDir(dialect)
	if err != nil {
		return err
	}
	paths := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".sql") {
			paths = append(paths, filepath.Join(dialect, entry.Name()))
		}
	}
	sort.Strings(paths)
	for _, path := range paths {
		version, err := strconv.Atoi(strings.SplitN(filepath.Base(path), "_", 2)[0])
		if err != nil {
			return fmt.Errorf("invalid migration filename %s", path)
		}
		if version > 1 {
			query := "SELECT COUNT(*) FROM schema_migrations WHERE version = ?"
			if dialect == "postgres" {
				query = "SELECT COUNT(*) FROM schema_migrations WHERE version = $1"
			}
			var count int
			if err = db.QueryRowContext(ctx, query, version).Scan(&count); err != nil {
				return err
			}
			if count > 0 {
				continue
			}
		}
		data, err := files.ReadFile(path)
		if err != nil {
			return err
		}
		if dialect == "mysql" {
			if err = applyOne(ctx, db, dialect, path, version, data); err != nil {
				return err
			}
			continue
		}
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if err = applyOne(ctx, tx, dialect, path, version, data); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err = tx.Commit(); err != nil {
			return fmt.Errorf("commit migration %s: %w", path, err)
		}
	}
	return nil
}

type migrationDB interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func applyOne(ctx context.Context, db migrationDB, dialect, path string, version int, data []byte) error {
	for _, statement := range strings.Split(string(data), "-- statement") {
		if strings.TrimSpace(statement) == "" {
			continue
		}
		if _, err := db.ExecContext(ctx, statement); err != nil {
			var mysqlErr *mysql.MySQLError
			if dialect == "mysql" && errors.As(err, &mysqlErr) && (mysqlErr.Number == 1060 || mysqlErr.Number == 1061 || mysqlErr.Number == 1091) {
				continue
			}
			if dialect == "sqlite" && strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
				continue
			}
			return fmt.Errorf("apply migration %s: %w", path, err)
		}
	}
	if version <= 1 {
		return nil
	}
	query := "INSERT INTO schema_migrations(version,applied_at) VALUES(?,?)"
	if dialect == "postgres" {
		query = "INSERT INTO schema_migrations(version,applied_at) VALUES($1,$2)"
	}
	if _, err := db.ExecContext(ctx, query, version, time.Now().UTC().UnixMicro()); err != nil {
		return fmt.Errorf("record migration %s: %w", path, err)
	}
	return nil
}
