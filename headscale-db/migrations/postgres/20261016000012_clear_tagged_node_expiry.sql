-- Match headscale-go 202607241200-clear-tagged-node-expiry.
UPDATE nodes
SET expiry = NULL
WHERE tags IS NOT NULL AND tags != '[]' AND tags != '' AND tags != 'null'
  AND expiry IS NOT NULL;
