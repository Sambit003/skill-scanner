"""Shared constants for ScanKernel."""

import os
# Risk score threshold above which a scan is treated as unsafe.
RISK_THRESHOLD = 50

# Log level: from env or fallback (DEBUG, INFO, WARNING, ERROR).
SCAN_KERNEL_LOG_LEVEL = os.environ.get("SCAN_KERNEL_LOG_LEVEL", "WARNING")
