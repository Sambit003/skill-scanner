"""Machine-only stdin/stdout entrypoint for ScanKernel protocol v1."""

from __future__ import annotations

import asyncio
import json
import sys

from pydantic import TypeAdapter, ValidationError

from scan_kernel.engine.protocol import (
    EngineRequest,
    ScanRequest,
    error_envelope,
    execute_metadata_request,
    execute_request,
)

REQUEST_ADAPTER = TypeAdapter(EngineRequest)


def _write(payload: dict[str, object]) -> None:
    sys.stdout.write(json.dumps(payload, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def main() -> int:
    try:
        raw = json.load(sys.stdin)
        request = REQUEST_ADAPTER.validate_python(raw)
    except (json.JSONDecodeError, ValidationError, TypeError) as exc:
        _write(error_envelope("INVALID_REQUEST", str(exc)))
        return 2

    try:
        if isinstance(request, ScanRequest):
            response = asyncio.run(execute_request(request))
        else:
            response = execute_metadata_request(request)
        _write(response)
        return 0
    except ValueError as exc:
        _write(error_envelope("UNSUPPORTED_ASSET_TYPE", str(exc)))
        return 2
    except TimeoutError as exc:
        _write(error_envelope("TIMEOUT", str(exc) or "Scanner execution timed out"))
        return 3
    except Exception as exc:
        print(f"ScanKernel execution failed: {exc}", file=sys.stderr)
        _write(error_envelope("SCAN_FAILED", str(exc) or "Scanner execution failed"))
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
