ALTER TABLE node_observations ADD COLUMN IF NOT EXISTS operating_system VARCHAR(32) NOT NULL DEFAULT ''
-- statement
ALTER TABLE node_observations ADD COLUMN IF NOT EXISTS architecture VARCHAR(32) NOT NULL DEFAULT ''
-- statement
ALTER TABLE node_observations ADD COLUMN IF NOT EXISTS frp_binary_path VARCHAR(512) NOT NULL DEFAULT ''
-- statement
ALTER TABLE node_observations ADD COLUMN IF NOT EXISTS frp_config_path VARCHAR(512) NOT NULL DEFAULT ''
-- statement
ALTER TABLE node_observations ADD COLUMN IF NOT EXISTS config_discovery_state VARCHAR(32) NOT NULL DEFAULT ''
-- statement
ALTER TABLE node_observations ADD COLUMN IF NOT EXISTS config_sha256 VARCHAR(128) NOT NULL DEFAULT ''
