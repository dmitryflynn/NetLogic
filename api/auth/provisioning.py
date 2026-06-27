"""
NetLogic — Clerk user/org provisioning into Postgres.

On a verified Clerk login we upsert the user (keyed by the IdP `sub`), ensure the
tenant org exists, and attach a membership — so logins land on persistent rows.

Returns the resolved org_id (always the SAME value as oidc.org_id_from_claims, so
behavior is identical whether or not the DB is enabled). Disabled DB → returns
None and the caller uses the claim-derived org. A DB hiccup never blocks a login:
the token is already verified, so we fall back to the claim-derived org_id.
"""

from __future__ import annotations

import logging
from typing import Optional

from api import db
from api.auth.oidc import org_id_from_claims

log = logging.getLogger("netlogic.provisioning")


def provision_user_and_org(claims: dict) -> Optional[str]:
    if not db.is_enabled():
        return None

    org_id = org_id_from_claims(claims)
    if not org_id:
        return None

    sub = claims.get("sub")
    if not sub:
        return None
    # Clerk's default session token is minimal; email/name appear only if a JWT
    # template adds them. Use a stable placeholder so the NOT NULL + unique-email
    # constraint can't collide across users that omit email.
    email = (claims.get("email") or claims.get("email_address") or "").strip() or f"{sub}@users.noreply"
    name = claims.get("name") or claims.get("given_name")
    org_name = claims.get("org_name") or (email.split("@")[0] if "@" in email else org_id) or "Workspace"

    try:
        with db.connection() as conn:
            conn.execute(
                "INSERT INTO organizations (slug, name) VALUES (%s, %s) "
                "ON CONFLICT (slug) DO NOTHING",
                (org_id, org_name),
            )
            org_uuid = conn.execute(
                "SELECT id FROM organizations WHERE slug = %s", (org_id,)
            ).fetchone()[0]

            conn.execute(
                "INSERT INTO users (idp_subject, email, name, last_login_at) "
                "VALUES (%s, %s, %s, now()) "
                "ON CONFLICT (idp_subject) DO UPDATE SET "
                "  email = EXCLUDED.email, "
                "  name = COALESCE(EXCLUDED.name, users.name), "
                "  last_login_at = now()",
                (sub, email, name),
            )
            user_uuid = conn.execute(
                "SELECT id FROM users WHERE idp_subject = %s", (sub,)
            ).fetchone()[0]

            conn.execute(
                "INSERT INTO org_memberships (org_id, user_id, role) VALUES (%s, %s, 'owner') "
                "ON CONFLICT (org_id, user_id) DO NOTHING",
                (org_uuid, user_uuid),
            )
        return org_id
    except Exception as exc:  # noqa: BLE001 — never block a verified login on DB issues
        log.warning("User/org provisioning failed for sub=%s (using claim-derived org): %s", sub, exc)
        return org_id
