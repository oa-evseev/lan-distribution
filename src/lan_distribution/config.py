"""Strict TOML configuration and dataset name validation."""

import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import defaults

NAME_RE = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")


class ConfigError(ValueError):
    pass


def name(value: str) -> str:
    if not NAME_RE.fullmatch(value):
        raise ConfigError(f"invalid dataset name: {value!r}")
    return value


def _keys(data: dict[str, Any], allowed: set[str]) -> None:
    extra = set(data) - allowed
    if extra:
        raise ConfigError(f"unknown configuration keys: {', '.join(sorted(extra))}")


def _table(data: dict[str, Any], key: str) -> dict[str, Any]:
    value = data.get(key, {})
    if not isinstance(value, dict):
        raise ConfigError(f"{key} must be a table")
    return value


def _absolute_path(value: Any, key: str) -> Path:
    if not isinstance(value, (str, Path)):
        raise ConfigError(f"{key} must be an absolute path string")
    path = Path(value)
    if not path.is_absolute():
        raise ConfigError(f"{key} must be absolute")
    return path


@dataclass(frozen=True)
class ServerConfig:
    state_dir: Path = defaults.SERVER_STATE
    runtime_dir: Path = defaults.RUNTIME
    source_root: Path = defaults.SOURCE
    host: str = "0.0.0.0"
    port: int = 9443
    instance_name: str = "lan-distribution"
    discovery: bool = True
    # A None source denotes a server-managed, published dataset.
    datasets: dict[str, Path | None] = field(default_factory=dict)
    max_dataset_bytes: int = defaults.MAX_FILE


@dataclass(frozen=True)
class DatasetConfig:
    target: Path | None = None
    post_update: tuple[str, ...] = ()
    retain: int = 2
    group: str | None = None


@dataclass(frozen=True)
class ClientConfig:
    state_dir: Path = defaults.CLIENT_STATE
    interval_seconds: int = 60
    datasets: dict[str, DatasetConfig] = field(default_factory=dict)


def _read(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as stream:
            data = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"cannot read {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError("configuration root must be a table")
    return data


def load_server(path: Path = defaults.SERVER_CONFIG) -> ServerConfig:
    data = _read(path)
    _keys(data, {"server", "datasets"})
    server = _table(data, "server")
    _keys(
        server,
        {
            "state_dir",
            "runtime_dir",
            "source_root",
            "host",
            "port",
            "instance_name",
            "discovery",
            "max_dataset_bytes",
        },
    )
    root = _absolute_path(server.get("source_root", defaults.SOURCE), "source_root")
    dataset_data = _table(data, "datasets")
    datasets: dict[str, Path | None] = {}
    for key, value in dataset_data.items():
        name(key)
        if isinstance(value, dict):
            _keys(value, {"published"})
            if value.get("published") is not True:
                raise ConfigError(f"dataset {key} must set published=true")
            datasets[key] = None
            continue
        if not isinstance(value, str):
            raise ConfigError(f"dataset {key} path must be a string or published table")
        path = Path(value)
        if not path.is_absolute() or not path.resolve(strict=False).is_relative_to(
            root.resolve(strict=False)
        ):
            raise ConfigError(f"dataset {key} path must be inside source_root")
        datasets[key] = path
    port = server.get("port", 9443)
    maximum = server.get("max_dataset_bytes", defaults.MAX_FILE)
    if type(port) is not int or not 1 <= port <= 65535:
        raise ConfigError("port must be between 1 and 65535")
    if type(maximum) is not int or not 1 <= maximum <= defaults.MAX_BODY:
        raise ConfigError("max_dataset_bytes must be 1..41943040")
    state_dir = _absolute_path(server.get("state_dir", defaults.SERVER_STATE), "state_dir")
    runtime_dir = _absolute_path(server.get("runtime_dir", defaults.RUNTIME), "runtime_dir")
    if not isinstance(server.get("host", "0.0.0.0"), str) or not isinstance(
        server.get("instance_name", "lan-distribution"), str
    ):
        raise ConfigError("host and instance_name must be strings")
    if type(server.get("discovery", True)) is not bool:
        raise ConfigError("discovery must be boolean")
    return ServerConfig(
        state_dir=state_dir,
        runtime_dir=runtime_dir,
        source_root=root,
        host=str(server.get("host", "0.0.0.0")),
        port=port,
        instance_name=str(server.get("instance_name", "lan-distribution")),
        discovery=server.get("discovery", True),
        datasets=datasets,
        max_dataset_bytes=maximum,
    )


def load_client(path: Path = defaults.CLIENT_CONFIG) -> ClientConfig:
    data = _read(path)
    _keys(data, {"client", "datasets"})
    client = _table(data, "client")
    _keys(client, {"state_dir", "interval_seconds"})
    state = _absolute_path(client.get("state_dir", defaults.CLIENT_STATE), "state_dir")
    interval = client.get("interval_seconds", 60)
    if type(interval) is not int or interval < 1:
        raise ConfigError("interval_seconds must be positive")
    datasets: dict[str, DatasetConfig] = {}
    for key, value in _table(data, "datasets").items():
        name(key)
        if not isinstance(value, dict):
            raise ConfigError(f"dataset {key} must be a table")
        _keys(value, {"target", "post_update", "retain", "group"})
        target = _absolute_path(value["target"], f"target for {key}") if "target" in value else None
        hook = value.get("post_update", [])
        if not isinstance(hook, list) or not all(isinstance(x, str) and x for x in hook):
            raise ConfigError(f"post_update for {key} must be an argv list")
        retain = value.get("retain", 2)
        if type(retain) is not int or retain < 1:
            raise ConfigError(f"retain for {key} must be positive")
        group = value.get("group")
        if group is not None and (not isinstance(group, str) or not group):
            raise ConfigError(f"group for {key} must be a nonempty name")
        datasets[key] = DatasetConfig(target, tuple(hook), retain, group)
    return ClientConfig(state, interval, datasets)
