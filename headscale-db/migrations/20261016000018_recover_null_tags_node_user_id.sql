-- Match headscale-go 202606181200-recover-null-tags-node-user-id.
-- Only untagged nodes with a pre-auth key have a recoverable owner.
UPDATE nodes
SET user_id = (
    SELECT pak.user_id FROM pre_auth_keys pak WHERE pak.id = nodes.auth_key_id
)
WHERE user_id IS NULL
  AND auth_key_id IS NOT NULL
  AND (tags IS NULL OR tags = '' OR tags = '[]' OR tags = 'null');
