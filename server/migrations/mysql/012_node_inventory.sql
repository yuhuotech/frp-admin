ALTER TABLE node_observations ADD COLUMN operating_system VARCHAR(32) NOT NULL DEFAULT ''
-- statement
ALTER TABLE node_observations ADD COLUMN architecture VARCHAR(32) NOT NULL DEFAULT ''
-- statement
ALTER TABLE node_observations ADD COLUMN frp_binary_path VARCHAR(512) NOT NULL DEFAULT ''
-- statement
ALTER TABLE node_observations ADD COLUMN frp_config_path VARCHAR(512) NOT NULL DEFAULT ''
-- statement
ALTER TABLE node_observations ADD COLUMN config_discovery_state VARCHAR(32) NOT NULL DEFAULT ''
-- statement
ALTER TABLE node_observations ADD COLUMN config_sha256 VARCHAR(128) NOT NULL DEFAULT ''
