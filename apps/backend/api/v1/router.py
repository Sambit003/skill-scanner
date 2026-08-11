from fastapi import APIRouter
from backend.api.v1.routers.scans import router as scans_router
from backend.api.v1.routers.rules import router as rules_router

api_v1_router = APIRouter()

api_v1_router.include_router(scans_router)
api_v1_router.include_router(rules_router)

@api_v1_router.get("/health", tags=["Health"])
async def health_check():
    return {"status": "healthy", "version": "1.0.0"}
