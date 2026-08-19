import re
from urllib.parse import urlsplit


_SSH_TARGET = re.compile(r"^git@(?P<host>[^:]+):(?P<path>.+)$", re.IGNORECASE)


def repository_key(target: str) -> str:
    """Return a stable repository identity while preserving unknown targets."""
    value = target.strip().rstrip("/")
    ssh_match = _SSH_TARGET.match(value)
    if ssh_match:
        host = ssh_match.group("host").lower()
        path = _clean_path(ssh_match.group("path"))
        return _hosted_repository_key(host, path) or f"{host}/{path}".lower()

    parsed = urlsplit(value)
    if parsed.scheme and parsed.hostname:
        host = parsed.hostname.lower()
        path = _clean_path(parsed.path)
        hosted = _hosted_repository_key(host, path)
        if hosted:
            return hosted
        return f"{parsed.scheme.lower()}://{host}/{path}".rstrip("/").lower()

    return value.removesuffix(".git").lower()


def _clean_path(path: str) -> str:
    return path.strip("/").removesuffix(".git")


def _hosted_repository_key(host: str, path: str) -> str | None:
    parts = [part for part in path.split("/") if part]

    if host == "raw.githubusercontent.com":
        if len(parts) >= 2:
            return f"github.com/{parts[0]}/{parts[1]}".lower()
        return None

    if host == "github.com":
        if len(parts) >= 2:
            return f"{host}/{parts[0]}/{parts[1]}".lower()
        return None

    if host == "bitbucket.org":
        if len(parts) >= 2:
            return f"{host}/{parts[0]}/{parts[1]}".lower()
        return None

    if host == "gitlab.com":
        for marker in ("-", "blob", "raw"):
            if marker in parts:
                parts = parts[: parts.index(marker)]
                break
        if len(parts) >= 2:
            return f"{host}/{'/'.join(parts)}".lower()

    return None
