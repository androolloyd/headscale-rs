-- headscale-go v0.28 denormalized approved route state onto nodes.
--
-- Older SQLite databases can still have the deprecated GORM-managed
-- `routes` table. Preserve enabled, non-deleted route approvals by
-- merging them into `nodes.approved_routes`, then remove the legacy
-- table. Fresh databases create an empty compatibility table so this
-- migration remains safe when no legacy table exists.
CREATE TABLE IF NOT EXISTS routes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at DATETIME,
    updated_at DATETIME,
    deleted_at DATETIME,
    node_id INTEGER NOT NULL,
    prefix TEXT,
    advertised BOOLEAN,
    enabled BOOLEAN,
    is_primary BOOLEAN
);

UPDATE nodes
SET approved_routes = COALESCE(
    (
        SELECT json_group_array(route)
        FROM (
            SELECT DISTINCT route
            FROM (
                SELECT value AS route
                FROM json_each(
                    CASE
                        WHEN json_valid(COALESCE(nodes.approved_routes, '[]'))
                        THEN COALESCE(nodes.approved_routes, '[]')
                        ELSE '[]'
                    END
                )
                WHERE typeof(value) = 'text' AND value != ''

                UNION
                SELECT prefix AS route
                FROM routes
                WHERE routes.node_id = nodes.id
                  AND routes.deleted_at IS NULL
                  AND COALESCE(routes.prefix, '') != ''
                  AND (
                      routes.enabled = 1
                      OR lower(CAST(routes.enabled AS TEXT)) = 'true'
                  )

                UNION
                SELECT '::/0' AS route
                FROM routes
                WHERE routes.node_id = nodes.id
                  AND routes.deleted_at IS NULL
                  AND routes.prefix = '0.0.0.0/0'
                  AND (
                      routes.enabled = 1
                      OR lower(CAST(routes.enabled AS TEXT)) = 'true'
                  )

                UNION
                SELECT '0.0.0.0/0' AS route
                FROM routes
                WHERE routes.node_id = nodes.id
                  AND routes.deleted_at IS NULL
                  AND routes.prefix = '::/0'
                  AND (
                      routes.enabled = 1
                      OR lower(CAST(routes.enabled AS TEXT)) = 'true'
                  )
            )
            ORDER BY route
        )
    ),
    '[]'
)
WHERE EXISTS (
    SELECT 1
    FROM routes
    WHERE routes.node_id = nodes.id
      AND routes.deleted_at IS NULL
      AND COALESCE(routes.prefix, '') != ''
      AND (
          routes.enabled = 1
          OR lower(CAST(routes.enabled AS TEXT)) = 'true'
      )
);

DROP TABLE IF EXISTS routes;
