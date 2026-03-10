"""Webhook endpoints per integration. PRD §8.4."""

from fastapi import APIRouter

from app.api.webhooks import aikido, linear

router = APIRouter()
router.include_router(aikido.router, prefix="/aikido", tags=["webhooks-aikido"])
router.include_router(linear.router, prefix="/linear", tags=["webhooks-linear"])
