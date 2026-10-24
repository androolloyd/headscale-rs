-- Match defaults in a fresh headscale-go v0.29.5 Postgres database without
-- changing an imported Go sequence or advancing it backwards.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = current_schema()
          AND table_name = 'database_versions'
          AND column_name = 'id'
          AND column_default IS NOT NULL
    ) THEN
        CREATE SEQUENCE IF NOT EXISTS database_versions_id_seq;
        ALTER SEQUENCE database_versions_id_seq OWNED BY database_versions.id;
        ALTER TABLE database_versions ALTER COLUMN id
            SET DEFAULT nextval('database_versions_id_seq'::regclass);
        PERFORM setval(
            'database_versions_id_seq'::regclass,
            GREATEST(COALESCE((SELECT MAX(id) FROM database_versions), 0), 1),
            EXISTS (SELECT 1 FROM database_versions)
        );
    END IF;
END $$;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = current_schema()
          AND table_name = 'pre_auth_keys'
          AND column_name = 'reusable'
    ) THEN
        ALTER TABLE pre_auth_keys ALTER COLUMN reusable DROP DEFAULT;
    END IF;
END $$;
