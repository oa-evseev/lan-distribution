"""Canonical snapshots and deliberately narrow TAR extraction."""

import contextlib
import grp
import hashlib
import io
import json
import os
import pwd
import re
import shutil
import stat
import tarfile
import tempfile
import uuid
from pathlib import Path, PurePosixPath
from typing import Any

from . import defaults
from .config import name

SERVICE_USER = "lan-distribution"
SERVICE_GROUP = "lan-distribution"


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def safe_path(value: str) -> PurePosixPath:
    path = PurePosixPath(value)
    if (
        not value
        or value.startswith("/")
        or "\\" in value
        or "\x00" in value
        or len(value.encode("utf-8")) > 4096
        or value.count("/") > 128
        or any(p in ("", ".", "..") for p in value.split("/"))
    ):
        raise ValueError(f"unsafe path: {value!r}")
    return path


def snapshot(source: Path, limit: int = defaults.MAX_FILE) -> tuple[dict[str, Any], bytes]:
    if not source.is_dir() or source.is_symlink():
        raise ValueError(f"dataset source is not a real directory: {source}")
    entries: list[dict[str, Any]] = []
    contents: dict[str, bytes] = {}
    total = 0

    def visit(directory_fd: int, prefix: str = "") -> None:
        nonlocal total
        with os.scandir(directory_fd) as iterator:
            names = sorted(entry.name for entry in iterator)
        for item in names:
            rel = f"{prefix}/{item}" if prefix else item
            safe_path(rel)
            st = os.stat(item, dir_fd=directory_fd, follow_symlinks=False)
            if stat.S_ISLNK(st.st_mode):
                raise ValueError(f"symlink is not allowed in source: {rel}")
            mode = stat.S_IMODE(st.st_mode) & 0o777
            if stat.S_ISDIR(st.st_mode):
                child_fd = os.open(
                    item, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory_fd
                )
                try:
                    opened = os.fstat(child_fd)
                    if (opened.st_dev, opened.st_ino) != (st.st_dev, st.st_ino):
                        raise ValueError("source changed during snapshot")
                    visit(child_fd, rel)
                finally:
                    os.close(child_fd)
                entries.append({"path": rel, "type": "dir", "mode": mode})
            elif stat.S_ISREG(st.st_mode):
                if st.st_nlink != 1:
                    raise ValueError(f"hard link is not allowed in source: {rel}")
                if st.st_size > limit or total + st.st_size > limit:
                    raise ValueError("dataset exceeds configured size limit")
                file_fd = os.open(item, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory_fd)
                try:
                    opened = os.fstat(file_fd)
                    if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (
                        st.st_dev,
                        st.st_ino,
                    ):
                        raise ValueError("source changed during snapshot")
                    with os.fdopen(file_fd, "rb", closefd=False) as stream:
                        data = stream.read(limit + 1)
                    after = os.fstat(file_fd)
                finally:
                    os.close(file_fd)
                if (
                    len(data) != st.st_size
                    or len(data) > limit
                    or (after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                    != (st.st_size, st.st_mtime_ns, st.st_ctime_ns)
                ):
                    raise ValueError("source changed during snapshot")
                total += len(data)
                contents[rel] = data
                entries.append(
                    {
                        "path": rel,
                        "type": "file",
                        "mode": mode,
                        "size": len(data),
                        "sha256": hashlib.sha256(data).hexdigest(),
                    }
                )
            else:
                raise ValueError(f"unsupported source entry: {rel}")
            if len(entries) > defaults.MAX_ENTRIES:
                raise ValueError("dataset has too many entries")

    source_fd = os.open(source, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        visit(source_fd)
    finally:
        os.close(source_fd)
    entries.sort(key=lambda x: x["path"])
    manifest: dict[str, Any] = {"entries": entries}
    manifest["version"] = hashlib.sha256(canonical(entries)).hexdigest()
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        for entry in entries:
            info = tarfile.TarInfo(entry["path"])
            info.mode = entry["mode"]
            info.mtime = 0
            if entry["type"] == "dir":
                info.type = tarfile.DIRTYPE
                archive.addfile(info)
            else:
                data = contents[entry["path"]]
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
    if len(output.getvalue()) > defaults.MAX_BODY:
        raise ValueError("archive exceeds request limit")
    return manifest, output.getvalue()


def _fsync_directory(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def published_root(state_dir: Path, dataset: str) -> Path:
    """Return the controlled store path after validating its sole dynamic component."""
    name(dataset)
    return state_dir / "datasets" / dataset


def _safe_directory(path: Path, mode: int = 0o700) -> None:
    if path.is_symlink():
        raise ValueError(f"managed store path is a symlink: {path}")
    path.mkdir(mode=mode, parents=True, exist_ok=True)
    if not path.is_dir() or path.is_symlink():
        raise ValueError(f"managed store path is not a directory: {path}")
    path.chmod(mode)


def service_identity() -> tuple[int, int]:
    """Return the uid/gid used by the installed server daemon."""
    return pwd.getpwnam(SERVICE_USER).pw_uid, grp.getgrnam(SERVICE_GROUP).gr_gid


def _set_owner(path: Path, identity: tuple[int, int]) -> None:
    """Set ownership without resolving a possible symlink at ``path``."""
    os.chown(path, *identity, follow_symlinks=False)


def _repair_ownership(path: Path, identity: tuple[int, int]) -> None:
    """Repair a managed tree without traversing symlinks or special files."""
    status = path.lstat()
    if stat.S_ISDIR(status.st_mode):
        with os.scandir(path) as entries:
            children = [Path(entry.path) for entry in entries]
        for child in children:
            _repair_ownership(child, identity)
    elif not (stat.S_ISREG(status.st_mode) or stat.S_ISLNK(status.st_mode)):
        raise ValueError(f"unsupported managed store entry: {path}")
    _set_owner(path, identity)


def current_published(state_dir: Path, dataset: str) -> Path | None:
    root = published_root(state_dir, dataset)
    current = root / "current"
    if not current.is_symlink():
        return None
    target = current.readlink().as_posix()
    if not re.fullmatch(r"versions/[0-9a-f]{64}", target):
        raise ValueError(f"published current link points outside versions: {current}")
    version = root / target
    if not version.is_dir() or version.is_symlink():
        raise ValueError(f"published current version is unavailable: {current}")
    return version


def publish(
    state_dir: Path,
    dataset: str,
    source: Path,
    limit: int = defaults.MAX_FILE,
    identity: tuple[int, int] | None = None,
) -> tuple[str, bool]:
    """Build a private immutable version, then atomically switch ``current``.

    The archive is deliberately re-extracted into the managed store: this reuses
    the protocol's validation and safe interim permission handling.
    """
    manifest, archive = snapshot(source, limit)
    version_id = str(manifest["version"])
    identity = identity or service_identity()
    root = published_root(state_dir, dataset)
    versions = root / "versions"
    _safe_directory(root)
    _safe_directory(versions)
    # This also repairs publications made before server-managed storage had a
    # service owner.  It is deliberately limited to this dataset's store.
    _repair_ownership(root, identity)
    old = current_published(state_dir, dataset)
    if old is not None and old.name == version_id:
        return version_id, False
    final = versions / version_id
    if final.exists() or final.is_symlink():
        if not final.is_dir() or final.is_symlink() or snapshot(final, limit)[0] != manifest:
            raise ValueError(f"published version is invalid: {version_id}")
    else:
        stage = Path(tempfile.mkdtemp(prefix=".stage-", dir=versions))
        try:
            stage.chmod(0o700)
            extract_verified(archive, manifest, stage)
            _repair_ownership(stage, identity)
            _fsync_directory(stage)
            os.rename(stage, final)
            _fsync_directory(versions)
        except BaseException:
            if stage.exists() and not stage.is_symlink():
                shutil.rmtree(stage)
            raise
    temporary = root / f".current-{uuid.uuid4().hex}"
    try:
        temporary.symlink_to(f"versions/{version_id}")
        _set_owner(temporary, identity)
        os.replace(temporary, root / "current")
        _fsync_directory(root)
    finally:
        if temporary.is_symlink():
            temporary.unlink()
    return version_id, True


def validate_manifest(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    if set(manifest) != {"entries", "version"}:
        raise ValueError("invalid manifest fields")
    entries = manifest.get("entries")
    if not isinstance(entries, list) or len(entries) > defaults.MAX_ENTRIES:
        raise ValueError("invalid manifest entries")
    if hashlib.sha256(canonical(entries)).hexdigest() != manifest.get("version"):
        raise ValueError("manifest version mismatch")
    seen: set[str] = set()
    types: dict[str, str] = {}
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
            raise ValueError("invalid manifest entry")
        path = str(safe_path(entry["path"]))
        if path in seen or entry.get("type") not in ("file", "dir"):
            raise ValueError("duplicate or invalid manifest entry")
        seen.add(path)
        types[path] = entry["type"]
        if type(entry.get("mode")) is not int or not 0 <= entry["mode"] <= 0o777:
            raise ValueError("invalid mode")
        if entry["type"] == "dir" and set(entry) != {"path", "type", "mode"}:
            raise ValueError("invalid directory metadata")
        if entry["type"] == "file" and (
            set(entry) != {"path", "type", "mode", "size", "sha256"}
            or not re.fullmatch(r"[0-9a-f]{64}", str(entry.get("sha256", "")))
            or type(entry.get("size")) is not int
            or entry["size"] < 0
            or entry["size"] > defaults.MAX_BODY
            or not isinstance(entry.get("sha256"), str)
        ):
            raise ValueError("invalid file metadata")
    for path in seen:
        parent = PurePosixPath(path).parent
        if str(parent) != "." and types.get(str(parent)) != "dir":
            raise ValueError("manifest has missing parent directory")
    if entries != sorted(entries, key=lambda x: x["path"]):
        raise ValueError("manifest is not canonical")
    return entries


def extract_verified(archive_bytes: bytes, manifest: dict[str, Any], destination: Path) -> None:
    if len(archive_bytes) > defaults.MAX_BODY:
        raise ValueError("archive exceeds size limit")
    if destination.is_symlink() or (destination.exists() and any(destination.iterdir())):
        raise ValueError("extraction destination must be empty")
    if not destination.exists():
        destination.mkdir(mode=0o700)
        destination.chmod(0o700)
    entries = validate_manifest(manifest)
    if sum(entry.get("size", 0) for entry in entries) > defaults.MAX_BODY:
        raise ValueError("manifest exceeds size limit")
    expected = {entry["path"]: entry for entry in entries}
    seen: set[str] = set()
    directory_fds: list[tuple[int, int]] = []
    with (
        contextlib.ExitStack() as cleanup,
        tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:") as archive,
    ):
        for member in archive:
            if member.name.endswith("//") or (member.name.endswith("/") and not member.isdir()):
                raise ValueError("noncanonical archive member path")
            rel = str(safe_path(member.name[:-1] if member.name.endswith("/") else member.name))
            entry = expected.get(rel)
            if entry is None or rel in seen or member.size > defaults.MAX_BODY:
                raise ValueError("unexpected archive member")
            seen.add(rel)
            target = destination.joinpath(*PurePosixPath(rel).parts)
            if any(part.is_symlink() for part in target.parents if part != destination.parent):
                raise ValueError("archive path traverses symlink")
            if entry["type"] == "dir" and member.isdir() and member.size == 0:
                if not target.parent.is_dir() or target.parent.is_symlink():
                    raise ValueError("archive directory parent is unavailable")
                target.mkdir(mode=0o700)
                # mkdir is filtered by umask.  Keep the staging tree private
                # while it is populated, irrespective of that process setting.
                target.chmod(0o700)
                fd = os.open(target, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                cleanup.callback(os.close, fd)
                directory_fds.append((fd, entry["mode"]))
            elif entry["type"] == "file" and member.isfile() and member.size == entry["size"]:
                if not target.parent.is_dir() or target.parent.is_symlink():
                    raise ValueError("archive file parent is unavailable")
                stream = archive.extractfile(member)
                if stream is None:
                    raise ValueError("missing file content")
                data = stream.read(defaults.MAX_BODY + 1)
                if (
                    hashlib.sha256(data).hexdigest() != entry["sha256"]
                    or len(data) != entry["size"]
                ):
                    raise ValueError("file checksum mismatch")
                # Do not let umask choose an interim, permissive mode.  An
                # empty mode is safe even for a final 0000 file; the already
                # open descriptor remains writable until it is closed.
                fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o000)
                try:
                    with os.fdopen(fd, "wb", closefd=False) as output:
                        output.write(data)
                        output.flush()
                        os.fsync(output.fileno())
                    os.fchmod(fd, entry["mode"])
                finally:
                    os.close(fd)
            else:
                raise ValueError("unsupported archive member")
        if seen != set(expected):
            raise ValueError("archive does not match manifest")
        for fd, mode in directory_fds:
            os.fchmod(fd, mode)
            os.fsync(fd)
