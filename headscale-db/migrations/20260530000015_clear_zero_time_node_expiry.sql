-- Match headscale-go v0.29.0-beta.2 migration
-- 202605221435-clear-zero-time-node-expiry.
UPDATE nodes
SET expiry = NULL
WHERE expiry IS NOT NULL AND expiry < '1900-01-01';
