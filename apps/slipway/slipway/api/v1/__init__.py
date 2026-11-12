from fastapi import APIRouter

from slipway.api.v1 import audit, auth, deployments, hosts, instances, repositories, roles, system, tokens, users

api_router = APIRouter()
for module in (system, auth, users, roles, tokens, hosts, repositories, instances, deployments, audit):
    api_router.include_router(module.router)
