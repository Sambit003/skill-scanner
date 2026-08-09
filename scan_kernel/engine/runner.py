import asyncio
import logging
from typing import Dict, Optional, Type
from scan_kernel.engine.models import ScanConfig, ScanResult
from scan_kernel.engine.plugins.base import BaseAssetPlugin

logger = logging.getLogger(__name__)

class ScanEngine:
    """Core orchestrator for universal asset scanning across registered plugins."""

    _plugins: Dict[str, BaseAssetPlugin] = {}

    @classmethod
    def register_plugin(cls, plugin: BaseAssetPlugin) -> None:
        """Register a new asset plugin with the engine."""
        cls._plugins[plugin.asset_type] = plugin
        logger.info(f"Registered scanner plugin for asset type: {plugin.asset_type}")

    @classmethod
    def get_plugin(cls, asset_type: str) -> Optional[BaseAssetPlugin]:
        """Retrieve a registered plugin by asset type identifier (handles plural/singular aliases)."""
        if asset_type in cls._plugins:
            return cls._plugins[asset_type]
        normalized = asset_type.rstrip("s")
        if normalized in cls._plugins:
            return cls._plugins[normalized]
        if f"{asset_type}s" in cls._plugins:
            return cls._plugins[f"{asset_type}s"]
        return None

    @classmethod
    async def execute_async(cls, config: ScanConfig) -> ScanResult:
        """Asynchronously route and execute a scan against the appropriate asset plugin."""
        plugin = cls.get_plugin(config.asset_type)
        if not plugin:
            raise ValueError(
                f"No plugin registered for asset type '{config.asset_type}'. "
                f"Available asset types: {list(cls._plugins.keys())}"
            )
        return await plugin.scan_async(config)

    @classmethod
    def execute_sync(cls, config: ScanConfig) -> ScanResult:
        """Synchronous execution wrapper."""
        return asyncio.run(cls.execute_async(config))
