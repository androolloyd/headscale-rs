-- Current headscale-go migration
-- 202602201200-clear-tagged-node-user-id.
--
-- Tagged nodes are owned by their tags, not by the user who created
-- them. Keeping user_id set makes user deletion fail or cascade-delete
-- tagged nodes through the nodes.user_id FK.
UPDATE nodes
SET user_id = NULL
WHERE tags IS NOT NULL AND tags != '[]' AND tags != '';
