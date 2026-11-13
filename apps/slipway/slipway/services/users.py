"""Built-in role seeding. Accounts are mirrored from Keycloak (see ``slipway.services.identity``)."""

from __future__ import annotations

import logging

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from slipway.core.permissions import SYSTEM_ROLES
from slipway.models import Role

log = logging.getLogger(__name__)


async def seed_system_roles(db: AsyncSession) -> None:
    """Create or refresh the built-in roles so upgrades pick up new permissions."""
    existing = {r.name: r for r in (await db.scalars(select(Role))).all()}
    for name, spec in SYSTEM_ROLES.items():
        perms = sorted(str(p) for p in spec["permissions"])  # type: ignore[union-attr]
        role = existing.get(name)
        if role is None:
            db.add(Role(name=name, description=str(spec["description"]), permissions=perms, is_system=True))
        else:
            role.permissions = perms
            role.description = str(spec["description"])
            role.is_system = True
    await db.flush()


async def bootstrap(db: AsyncSession) -> None:
    """Startup hook: seed the built-in roles."""
    await seed_system_roles(db)
    await db.commit()
