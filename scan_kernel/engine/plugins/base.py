from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from scan_kernel.engine.models import ScanConfig, ScanResult

class BaseAssetPlugin(ABC):
    """Abstract Base Class for all asset scanner plugins in the Scanner Engine."""

    @property
    @abstractmethod
    def asset_type(self) -> str:
        """The identifier for this asset type (e.g., 'agent_skill', 'mcp_server', 'model')."""
        pass

    @property
    @abstractmethod
    def supported_extensions(self) -> List[str]:
        """List of file extensions supported by this plugin."""
        pass

    @abstractmethod
    async def scan_async(self, config: ScanConfig) -> ScanResult:
        """Execute an asynchronous scan against the asset target."""
        pass

    @abstractmethod
    def scan_sync(self, config: ScanConfig) -> ScanResult:
        """Execute a synchronous scan against the asset target."""
        pass
