CREATE TABLE IF NOT EXISTS runtime_snapshots (node_id CHAR(36) PRIMARY KEY REFERENCES nodes(id), role VARCHAR(16) NOT NULL, frp_version VARCHAR(64) NOT NULL, collected_at BIGINT NOT NULL, bind_address VARCHAR(255) NOT NULL, bind_port INTEGER NOT NULL, proxy_count INTEGER NOT NULL, client_count INTEGER NOT NULL, updated_at BIGINT NOT NULL);
-- statement
CREATE TABLE IF NOT EXISTS runtime_proxies (node_id CHAR(36) NOT NULL REFERENCES nodes(id), name VARCHAR(255) NOT NULL, type VARCHAR(32) NOT NULL, status VARCHAR(32) NOT NULL, local_address VARCHAR(512) NOT NULL, remote_address VARCHAR(512) NOT NULL, last_error TEXT NOT NULL, bytes_in BIGINT NOT NULL, bytes_out BIGINT NOT NULL, today_bytes_in BIGINT NOT NULL, today_bytes_out BIGINT NOT NULL, current_connections BIGINT NOT NULL, collected_at BIGINT NOT NULL, PRIMARY KEY(node_id,name));
-- statement
CREATE INDEX IF NOT EXISTS idx_runtime_proxies_filter ON runtime_proxies(status,type,node_id,name);
-- statement
CREATE TABLE IF NOT EXISTS runtime_clients (node_id CHAR(36) NOT NULL REFERENCES nodes(id), id VARCHAR(255) NOT NULL, address VARCHAR(512) NOT NULL, connected_at BIGINT NOT NULL, collected_at BIGINT NOT NULL, PRIMARY KEY(node_id,id));
