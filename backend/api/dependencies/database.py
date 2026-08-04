from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession
from backend.core.database import get_db_session
from backend.repositories.scan_repository import ScanRepository
from backend.services.scan_service import ScanService

def get_scan_repository(session: AsyncSession = Depends(get_db_session)) -> ScanRepository:
    return ScanRepository(session)

def get_scan_service(repo: ScanRepository = Depends(get_scan_repository)) -> ScanService:
    return ScanService(repo)
