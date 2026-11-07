"""Import every model so ``Base.metadata`` is complete (Alembic and create_all rely on this)."""

from kiln.models.audit import AuditEvent
from kiln.models.host import Host, HostAuthMethod, HostStatus
from kiln.models.instance import BuildSource, Deployment, DeploymentStatus, Instance, InstanceStatus
from kiln.models.repository import Repository
from kiln.models.user import ApiToken, OAuthAccount, Role, User, UserSession, user_roles

__all__ = [
    "ApiToken",
    "AuditEvent",
    "BuildSource",
    "Deployment",
    "DeploymentStatus",
    "Host",
    "HostAuthMethod",
    "HostStatus",
    "Instance",
    "InstanceStatus",
    "OAuthAccount",
    "Repository",
    "Role",
    "User",
    "UserSession",
    "user_roles",
]
