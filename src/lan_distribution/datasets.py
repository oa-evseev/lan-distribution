"""Canonical snapshots and deliberately narrow TAR extraction."""

import contextlib
import hashlib
import io
import json
import os
import re
import stat
import tarfile
from pathlib import Path, PurePosixPath
from typing import Any

from . import defaults


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
