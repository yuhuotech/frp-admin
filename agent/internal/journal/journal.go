package journal

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	agentv1 "github.com/frp-admin/frp-admin/contracts/gen/go/frpadmin/agent/v1"
	bolt "go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"
)

var results = []byte("results")

type Journal struct {
	db  *bolt.DB
	max int
}

func Open(path string, max int) (*Journal, error) {
	if info, err := os.Lstat(filepath.Dir(path)); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("journal directory must not be a symlink")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	if err := os.Chmod(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	db, err := bolt.Open(path, 0600, nil)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0600); err != nil {
		db.Close()
		return nil, err
	}
	j := &Journal{db: db, max: max}
	if max <= 0 {
		j.max = 1000
	}
	if err := db.Update(func(tx *bolt.Tx) error { _, err := tx.CreateBucketIfNotExists(results); return err }); err != nil {
		db.Close()
		return nil, err
	}
	return j, nil
}

func (j *Journal) Close() error { return j.db.Close() }

func (j *Journal) Get(key string) (*agentv1.CommandResult, bool, error) {
	var data []byte
	err := j.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(results).Get([]byte(key))
		if v != nil {
			data = append([]byte(nil), v...)
		}
		return nil
	})
	if err != nil || data == nil {
		return nil, false, err
	}
	r := new(agentv1.CommandResult)
	if err := proto.Unmarshal(data, r); err != nil {
		return nil, false, fmt.Errorf("decode journal result: %w", err)
	}
	return r, true, nil
}

func (j *Journal) Put(keys []string, result *agentv1.CommandResult) error {
	b, err := proto.Marshal(result)
	if err != nil {
		return err
	}
	return j.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(results)
		for _, key := range keys {
			if key != "" {
				if err := bucket.Put([]byte(key), b); err != nil {
					return err
				}
			}
		}
		for bucket.Stats().KeyN > j.max {
			k, _ := bucket.Cursor().First()
			if k == nil {
				return errors.New("journal pruning failed")
			}
			if err := bucket.Delete(k); err != nil {
				return err
			}
		}
		return nil
	})
}
