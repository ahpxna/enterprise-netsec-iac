# Authentik lifecycle migration runbook

## Current state

Fresh repository deployments pin the supported Authentik 2026.8 package by
immutable OCI index digest. This remediates the ForwardAuth vulnerability
present in the legacy 2024.8 train.

An existing 2024.8 Authentik database is not auto-upgraded by this repository.
It must follow Authentik's supported sequential-major upgrade path. A direct
jump from 2024.8 to the fresh-deployment 2026.8 image can turn a security
upgrade into an unrecoverable schema/application migration failure.

Official references used for this runbook:

- https://docs.goauthentik.io/security/policy/
- https://docs.goauthentik.io/install-config/upgrade/

Review date: 2026-08-25.

## Mandatory migration rules

1. Back up the PostgreSQL database and the local Authentik secret/configuration
   material before every release-train transition.
2. Upgrade to the latest patch in the **next supported upgrade step**; never
   skip an Authentik major release in an existing installation.
3. Start both server and worker and wait for migrations/background tasks to
   settle before proceeding to the next step.
4. Validate the declarative `cxyz-ztna.yaml` Blueprint after every step:
   provider, application and embedded-outpost mapping must remain present.
5. Run the ZTNA negative/positive checkpoint after every step.  An
   unauthenticated client must be redirected over trusted TLS and the protected
   backend must remain unpublished.
6. Take a new backup only after the current step is healthy.  Do not use image
   rollback as a substitute for database restore after a schema migration.

## Checkpoint commands

```bash
# Backup before changing the Authentik image.
docker compose exec -T authentik-postgres \
  pg_dump -U authentik -d authentik -Fc > authentik-before-upgrade.dump

# Record current containers/logs before each step.
docker compose ps authentik-server authentik-worker authentik-postgres authentik-redis
docker compose logs --tail=200 authentik-server authentik-worker

# After changing exactly one release-train step:
docker compose --profile ztna --profile dmz up -d authentik-postgres authentik-redis authentik-server authentik-worker traefik ztna-demo-app

docker compose ps authentik-server authentik-worker
# Then run the repository ZTNA validation as part of the normal live suite.
make validate
```

For a failed schema migration, restore the database backup into a clean
PostgreSQL volume matching the pre-upgrade release rather than attempting an
unsupported downgrade against the migrated database.

## Exit criteria for the lifecycle debt

The Authentik entry can be moved from `migration-required` to `reviewed` only
when all of the following exist for the target supported train:

- immutable multi-platform OCI index digest verified for amd64 and arm64;
- sequential migration completed on a copy of the existing 2024.8 database;
- Blueprint reconciles without manual UI state;
- ZTNA-01 passes without `curl --insecure`;
- server/worker health and database backup/restore are demonstrated;
- Compose and Path C manifests use the same accepted release.

Until then, do not point a legacy database volume at the 2026.8 default. Keep
the legacy migration isolated and follow this runbook.
