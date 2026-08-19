from typing import Any, Dict, List, Optional, Protocol

class IScanRepository(Protocol):
    """Abstract interface defining persistence operations for asset scans."""

    async def create_scan_record(
        self,
        asset_target: str,
        repository_key: str,
        asset_type: str,
        scan_scope: str,
        include_readme: bool,
    ) -> str:
        """Create a new scan record in QUEUED state and return the scan_id."""
        ...

    async def get_scan_by_id(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Fetch a scan record and its findings by scan ID."""
        ...

    async def update_scan_status(self, scan_id: str, status: str, risk_score: Optional[int] = None) -> None:
        """Update the async status of a scan."""
        ...

    async def list_scans(
        self,
        limit: int = 50,
        offset: int = 0,
        target: Optional[str] = None,
        repository_key: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List historical scan records."""
        ...
