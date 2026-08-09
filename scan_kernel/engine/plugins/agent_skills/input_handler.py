"""
Input handler for ScanKernel.

Handles various input formats:
- Git repository URLs
- Raw file URLs
- Local zip files
- Single markdown files
- Local directories

Ported from legacy implementation.
"""

from __future__ import annotations

import ipaddress
import os
import re
import shutil
import socket
import subprocess
import tempfile
import zipfile
from pathlib import Path
from urllib.parse import urlparse

import httpx

from scan_kernel.engine.plugins.agent_skills.logging_config import get_logger

logger = get_logger(__name__)

ALLOWED_GIT_HOSTS = frozenset(
    {
        "github.com",
        "gitlab.com",
        "bitbucket.org",
    }
)

ALLOWED_DOWNLOAD_HOSTS = frozenset(
    {
        "github.com",
        "raw.githubusercontent.com",
        "gitlab.com",
        "bitbucket.org",
        "huggingface.co",
    }
)


GitHubTreeTarget = tuple[str, str, Path]


def _is_private_ip(host: str) -> bool:
    """Return True if host resolves to a private/reserved IP address."""
    try:
        addr = ipaddress.ip_address(host)
        return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved
    except ValueError:
        pass
    try:
        resolved = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for _, _, _, _, sockaddr in resolved:
            addr = ipaddress.ip_address(sockaddr[0])
            if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
                return True
    except (socket.gaierror, OSError):
        return True
    return False


class InputHandler:
    """
    Handles input resolution for different source types.

    Normalizes all inputs to a local directory path for scanning.
    """

    def __init__(self) -> None:
        self._temp_dir: Path | None = None

    def resolve(self, input_path: str) -> tuple[Path, str]:
        """
        Resolve input to a scannable directory.

        Args:
            input_path: Path or URL to resolve

        Returns:
            Tuple of (resolved_path, source_type)
            source_type is one of: "git", "url", "zip", "file", "directory"

        Raises:
            ValueError: If input type cannot be determined
            FileNotFoundError: If local path doesn't exist
        """
        input_path = input_path.strip()

        if self._is_git_url(input_path):
            return self._clone_git(input_path), "git"
        if self._is_file_url(input_path):
            return self._download_file(input_path), "url"
        if input_path.endswith(".zip"):
            return self._extract_zip(Path(input_path)), "zip"
        if input_path.endswith(".md"):
            return self._wrap_single_file(Path(input_path)), "file"
        if Path(input_path).is_dir():
            return Path(input_path).resolve(), "directory"
        if Path(input_path).is_file():
            return self._wrap_single_file(Path(input_path)), "file"
        raise ValueError(
            f"Cannot determine input type for: {input_path}\n"
            "Supported formats: Git URL, file URL, .zip file, .md file, or directory"
        )

    def cleanup(self) -> None:
        """Clean up temporary files created during resolution."""
        if self._temp_dir and self._temp_dir.exists():
            shutil.rmtree(self._temp_dir, ignore_errors=True)
            self._temp_dir = None

    def temp_dir_for_cleanup(self) -> Path | None:
        """Return the temp directory path if one was created (for caller to clean up after graph)."""
        return self._temp_dir

    def _get_temp_dir(self) -> Path:
        """Get or create a temporary directory for this session."""
        if not self._temp_dir:
            work_dir = os.environ.get("SCAN_KERNEL_WORK_DIR", "").strip()
            temp_root = Path(work_dir) if work_dir else None
            if temp_root is not None:
                temp_root.mkdir(parents=True, exist_ok=True)
            self._temp_dir = Path(
                tempfile.mkdtemp(prefix="scan_kernel_", dir=str(temp_root) if temp_root else None)
            )
        return self._temp_dir

    def _is_git_url(self, path: str) -> bool:
        """Check if path is a Git repository URL."""
        if not path.startswith(("http://", "https://", "git@")):
            return False
        parsed = urlparse(path)
        host = parsed.hostname or ""
        if any(allowed in host for allowed in ALLOWED_GIT_HOSTS):
            if "/raw/" in path or "/blob/" in path or path.endswith((".md", ".py", ".sh")):
                return False
            return True
        if path.endswith(".git"):
            return True
        return False

    def _is_file_url(self, path: str) -> bool:
        """Check if path is a direct file URL."""
        if not path.startswith(("http://", "https://")):
            return False
        return not self._is_git_url(path)

    def _extract_scp_host(self, url: str) -> str | None:
        """Return the host from an scp-style Git URL, or None if not scp form."""
        if "://" in url:
            return None
        m = re.match(r"^[^@/]+@([^:/]+):.+$", url)
        return m.group(1) if m else None

    def _validate_url_host(self, url: str, allowed_hosts: frozenset[str]) -> str:
        """Validate URL host against allowlist and SSRF protections.

        Returns the hostname on success, raises ValueError on blocked URLs.
        """
        parsed = urlparse(url)
        host = parsed.hostname or ""
        if not host:
            host = self._extract_scp_host(url) or ""
        if not host:
            raise ValueError(f"URL has no valid hostname: {url}")
        if not any(host == allowed or host.endswith("." + allowed) for allowed in allowed_hosts):
            raise ValueError(
                f"Host '{host}' is not in the allowed hosts list. Allowed: {sorted(allowed_hosts)}"
            )
        if _is_private_ip(host):
            raise ValueError(
                f"URL resolves to a private/internal IP address: {url}. "
                "This is blocked to prevent SSRF attacks."
            )
        return host

    def _clone_git(self, url: str) -> Path:
        """Clone a Git repository to a temporary directory."""
        tree_target = self._parse_github_tree_url(url)
        clone_url = tree_target[0] if tree_target else url
        self._validate_url_host(clone_url, ALLOWED_GIT_HOSTS)
        temp_dir = self._get_temp_dir()
        clone_dir = temp_dir / "repo"
        clone_cmd = ["git", "clone", "--depth", "1"]
        if tree_target:
            clone_cmd.extend(["--branch", tree_target[1], "--single-branch"])
        clone_cmd.extend([clone_url, str(clone_dir)])
        try:
            subprocess.run(
                clone_cmd,
                check=True,
                capture_output=True,
                timeout=60,
                shell=False,
            )
        except subprocess.CalledProcessError as e:
            logger.warning("Git clone failed for %s: %s", url, e)
            raise ValueError(f"Failed to clone repository: {e.stderr.decode()}") from e
        except subprocess.TimeoutExpired:
            logger.warning("Git clone timed out for %s", url)
            raise ValueError("Git clone timed out after 60 seconds") from None
        except FileNotFoundError:
            logger.warning("Git not found when cloning %s", url)
            raise ValueError(
                "Git is not installed. Please install git to scan repositories."
            ) from None
        if tree_target:
            subpath = tree_target[2]
            target_dir = (clone_dir / subpath).resolve()
            if not str(target_dir).startswith(str(clone_dir.resolve())):
                raise ValueError(f"GitHub tree path escapes repository root: {url}")
            if not target_dir.exists():
                raise ValueError(
                    f"GitHub tree path not found after clone: {subpath.as_posix()}"
                )
            if target_dir.is_file():
                return self._wrap_single_file(target_dir)
            return target_dir
        return clone_dir

    def _parse_github_tree_url(self, url: str) -> GitHubTreeTarget | None:
        """Parse GitHub web tree URLs into clone URL, ref, and repo-relative path.

        Supports URLs like:

        - https://github.com/org/repo/tree/main/path/to/skill
        - https://github.com/org/repo/tree/release/v1/path/to/skill

        GitHub branch and tag names may contain slashes, so this resolves remote
        refs and picks the longest ref prefix that matches the URL tail. If refs
        cannot be listed, it falls back to GitHub's common one-segment ref form.
        """
        parsed = urlparse(url)
        host = parsed.hostname or ""
        if host != "github.com":
            return None
        parts = [part for part in parsed.path.strip("/").split("/") if part]
        if len(parts) < 4 or parts[2] != "tree":
            return None

        owner, repo = parts[0], parts[1]
        tail = parts[3:]
        repo_url = f"{parsed.scheme or 'https'}://github.com/{owner}/{repo}.git"
        ref, subpath_parts = self._split_github_tree_ref(repo_url, tail)
        subpath = Path(*subpath_parts) if subpath_parts else Path(".")
        return repo_url, ref, subpath

    def _split_github_tree_ref(self, repo_url: str, tail: list[str]) -> tuple[str, list[str]]:
        """Split the tail after /tree/ into (ref, subpath_parts)."""
        if not tail:
            raise ValueError(f"GitHub tree URL is missing a branch/tag: {repo_url}")

        refs = self._list_remote_refs(repo_url)
        for ref in sorted(refs, key=lambda value: len(value.split("/")), reverse=True):
            ref_parts = ref.split("/")
            if tail[: len(ref_parts)] == ref_parts:
                return ref, tail[len(ref_parts) :]

        return tail[0], tail[1:]

    def _list_remote_refs(self, repo_url: str) -> list[str]:
        """Return branch/tag refs available on a remote repository."""
        try:
            result = subprocess.run(
                ["git", "ls-remote", "--heads", "--tags", repo_url],
                check=True,
                capture_output=True,
                timeout=30,
                shell=False,
                text=True,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as e:
            logger.debug("Could not list remote refs for %s: %s", repo_url, e)
            return []

        refs: list[str] = []
        for line in result.stdout.splitlines():
            fields = line.split()
            if len(fields) < 2:
                continue
            raw_ref = fields[1]
            if raw_ref.endswith("^{}"):
                continue
            if raw_ref.startswith("refs/heads/"):
                refs.append(raw_ref.removeprefix("refs/heads/"))
            elif raw_ref.startswith("refs/tags/"):
                refs.append(raw_ref.removeprefix("refs/tags/"))
        return refs

    def _download_file(self, url: str) -> Path:
        """Download a file from URL to a temporary directory."""
        self._validate_url_host(url, ALLOWED_DOWNLOAD_HOSTS)
        temp_dir = self._get_temp_dir()
        parsed = urlparse(url)
        filename = Path(parsed.path).name or "SKILL.md"
        try:
            with httpx.Client(follow_redirects=False, timeout=30) as client:
                response = client.get(url)
                response.raise_for_status()
                content = response.content
        except httpx.HTTPError as e:
            logger.warning("Download failed for %s: %s", url, e)
            raise ValueError(f"Failed to download file: {e}") from e
        if filename.endswith(".zip") or (
            response.headers.get("content-type", "").startswith("application/zip")
        ):
            zip_path = temp_dir / "download.zip"
            zip_path.write_bytes(content)
            return self._extract_zip(zip_path)
        file_path = temp_dir / filename
        file_path.write_bytes(content)
        return temp_dir

    def _extract_zip(self, zip_path: Path) -> Path:
        """Extract a zip file to a temporary directory with path traversal protection."""
        if not zip_path.exists():
            raise FileNotFoundError(f"Zip file not found: {zip_path}") from None
        temp_dir = self._get_temp_dir()
        extract_dir = temp_dir / "extracted"
        extract_dir.mkdir(exist_ok=True)
        try:
            with zipfile.ZipFile(zip_path, "r") as zf:
                for member in zf.namelist():
                    member_path = (extract_dir / member).resolve()
                    if not str(member_path).startswith(str(extract_dir.resolve())):
                        raise ValueError(
                            f"Zip entry '{member}' would escape extraction directory (zip-slip). "
                            "Archive is potentially malicious."
                        )
                zf.extractall(extract_dir)
        except zipfile.BadZipFile:
            logger.warning("Invalid zip or extract failed: %s", zip_path)
            raise ValueError(f"Invalid zip file: {zip_path}") from None
        contents = list(extract_dir.iterdir())
        if len(contents) == 1 and contents[0].is_dir():
            return contents[0]
        return extract_dir

    def _wrap_single_file(self, file_path: Path) -> Path:
        """Wrap a single file in a temporary directory for consistent handling."""
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}") from None
        temp_dir = self._get_temp_dir()
        dest = temp_dir / file_path.name
        shutil.copy2(file_path, dest)
        return temp_dir
