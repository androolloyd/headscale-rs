-- Headscale v0.29.5: repair rows detached by the earlier null-tags bug.
-- Historical migrations stay byte-identical for existing SQLx checksums.
UPDATE nodes
SET user_id = (SELECT pak.user_id FROM pre_auth_keys pak WHERE pak.id = nodes.auth_key_id)
WHERE user_id IS NULL AND auth_key_id IS NOT NULL
  AND (tags IS NULL OR tags = '' OR tags = '[]' OR tags = 'null');

-- Tagged logout never expires the node; repair old logout stamps once on upgrade.
UPDATE nodes SET expiry = NULL
WHERE tags IS NOT NULL AND tags != '[]' AND tags != '' AND tags != 'null'
  AND expiry IS NOT NULL;
