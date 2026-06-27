-- Read-only compliance role for the decision ledger (design Phase 4: read-only
-- evidence access without a physical DB split).
--
-- Idempotent / re-runnable. `vat_compliance_ro` is a NOLOGIN group role holding
-- SELECT on the `decisions` schema ONLY (no access to operational tables in
-- public). Attach a login user out of band so the credential stays a secret:
--
--   CREATE ROLE compliance_export LOGIN PASSWORD '<from-secret>';
--   GRANT vat_compliance_ro TO compliance_export;
--
-- Apply (run as a superuser/createrole, e.g. the `vat` owner):
--   kubectl exec -i -n vat postgres-0 -- psql -U vat -d vat < compliance_ro_role.sql

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vat_compliance_ro') THEN
    CREATE ROLE vat_compliance_ro NOLOGIN;
  END IF;
END
$$;

GRANT USAGE ON SCHEMA decisions TO vat_compliance_ro;
GRANT SELECT ON ALL TABLES IN SCHEMA decisions TO vat_compliance_ro;

-- Future ledger tables created by the app owner stay readable automatically.
ALTER DEFAULT PRIVILEGES IN SCHEMA decisions
  GRANT SELECT ON TABLES TO vat_compliance_ro;
