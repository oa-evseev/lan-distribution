"""Installer contract checks without mutating the host."""

import configparser
import errno
import json
import os
import pty
import select
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
BASH = "/bin/bash"


def run_group_helper(
    tmp_path,
    *,
    user="alice",
    groups="users",
    reply=None,
    sudo_user=True,
    noninteractive=False,
    helper="manage_server_admin_group",
):
    """Run the installer helper against small account-management command doubles."""
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir(parents=True)
    (fake_bin / "id").write_text(
        "#!/bin/sh\n"
        'if [ "$1" = -u ]; then [ "$2" = "$TEST_USER" ]; exit; fi\n'
        'if [ "$1" = -nG ]; then echo "$TEST_GROUPS"; exit 0; fi\n'
        "exit 1\n"
    )
    (fake_bin / "usermod").write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$TEST_USERMOD_LOG"\n')
    for command in fake_bin.iterdir():
        command.chmod(0o755)
    log = tmp_path / "usermod.log"
    environment = os.environ | {
        "INSTALL_SH_SOURCE_ONLY": "1",
        "PATH": f"{fake_bin}:{os.environ['PATH']}",
        "TEST_USER": user,
        "TEST_GROUPS": groups,
        "TEST_USERMOD_LOG": str(log),
    }
    if sudo_user:
        environment["SUDO_USER"] = user
    else:
        environment.pop("SUDO_USER", None)
    if noninteractive:
        environment["NONINTERACTIVE"] = "1"
    command = f"source {ROOT / 'scripts/install.sh'}; {helper}"
    if reply is None:
        result = subprocess.run(
            [BASH, "-c", command], env=environment, input="", capture_output=True, text=True
        )
        output = result.stdout + result.stderr
    else:
        master, slave = pty.openpty()
        process = subprocess.Popen(
            [BASH, "-c", command],
            env=environment,
            stdin=slave,
            stdout=slave,
            stderr=slave,
        )
        os.close(slave)
        os.write(master, f"{reply}\n".encode())
        chunks = []
        while process.poll() is None:
            readable, _, _ = select.select([master], [], [], 0.1)
            if readable:
                try:
                    chunks.append(os.read(master, 4096))
                except OSError as error:
                    assert error.errno == errno.EIO
                    break
        try:
            chunks.append(os.read(master, 4096))
        except OSError as error:
            assert error.errno == errno.EIO
        os.close(master)
        result = process.wait()
        output = b"".join(chunks).decode()
        assert result == 0
    if reply is None:
        assert result.returncode == 0
    return output, log.read_text() if log.exists() else ""


def run_server_group_helper(tmp_path, **kwargs):
    return run_group_helper(tmp_path, **kwargs)


def run_client_group_helper(tmp_path, **kwargs):
    return run_group_helper(tmp_path, helper="manage_client_admin_group", **kwargs)


def test_systemd_units_match_installed_paths_and_privileges():
    for role in ("client", "server"):
        parser = configparser.ConfigParser(interpolation=None)
        parser.read(ROOT / f"systemd/lan-distribution-{role}.service")
        service = parser["Service"]
        assert service["ExecStart"] == (
            f"/opt/lan-distribution/venv/bin/lan-distribution-{role} run"
        )
        assert service["UMask"] == "0077"
        assert service["NoNewPrivileges"] == "yes"
        assert service["Restart"] == "on-failure"
    server = configparser.ConfigParser(interpolation=None)
    server.read(ROOT / "systemd/lan-distribution-server.service")
    assert server["Service"]["User"] == "lan-distribution"
    assert server["Service"]["Group"] == "lan-distribution"
    assert server["Service"]["RuntimeDirectory"] == "lan-distribution"
    assert "/var/lib/lan-distribution/server" in server["Service"]["ReadWritePaths"]
    client = configparser.ConfigParser(interpolation=None)
    client.read(ROOT / "systemd/lan-distribution-client.service")
    assert "User" not in client["Service"]  # root can update configured /etc targets
    assert client["Unit"]["ConditionPathExists"] == (
        "/var/lib/lan-distribution/client/credentials/current"
    )


def test_server_installer_adds_invoking_user_after_confirmation(tmp_path):
    output, usermod = run_server_group_helper(tmp_path, reply="Y")

    assert "Add current user 'alice' to group 'lan-distribution'" in output
    assert usermod == "-aG lan-distribution alice\n"
    assert "User 'alice' added to group 'lan-distribution'." in output
    assert "after the next login session" in output


def test_server_installer_leaves_user_unchanged_after_declining(tmp_path):
    output, usermod = run_server_group_helper(tmp_path, reply="n")

    assert not usermod
    assert "sudo lan-distribution status" in output
    assert "sudo lan-distribution open 2min" in output
    assert "sudo lan-distribution close" in output


def test_server_installer_skips_prompt_for_existing_group_member(tmp_path):
    output, usermod = run_server_group_helper(tmp_path, groups="users lan-distribution")

    assert not output
    assert not usermod


def test_server_installer_is_informational_when_stdin_is_not_a_terminal(tmp_path):
    output, usermod = run_server_group_helper(tmp_path)

    assert not usermod
    assert "User 'alice' is not in group 'lan-distribution'." in output
    assert "sudo lan-distribution status" in output


def test_server_installer_does_not_prompt_in_explicit_noninteractive_mode(tmp_path):
    output, usermod = run_server_group_helper(tmp_path, reply="Y", noninteractive=True)

    assert "Add current user" not in output
    assert not usermod
    assert "sudo lan-distribution status" in output


@pytest.mark.parametrize(("user", "sudo_user"), [("root", True), ("alice", False)])
def test_server_installer_does_not_guess_a_user(tmp_path, user, sudo_user):
    output, usermod = run_server_group_helper(tmp_path, user=user, sudo_user=sudo_user)

    assert not output
    assert not usermod


def test_server_installer_repeat_is_idempotent(tmp_path):
    _, first_usermod = run_server_group_helper(tmp_path / "first", reply="y")
    output, second_usermod = run_server_group_helper(
        tmp_path / "second", groups="users lan-distribution"
    )

    assert first_usermod == "-aG lan-distribution alice\n"
    assert not output
    assert not second_usermod


@pytest.mark.parametrize("reply", ["Y", ""])
def test_client_installer_adds_invoking_user_after_confirmation(tmp_path, reply):
    output, usermod = run_client_group_helper(tmp_path, reply=reply)

    assert "Add current user 'alice' to group 'lan-distribution'" in output
    assert "so client status/admin commands can be run without sudo? [Y/n]" in output
    assert usermod == "-aG lan-distribution alice\n"
    assert "User 'alice' added to group 'lan-distribution'." in output
    assert "after the next login session" in output


def test_client_installer_leaves_user_unchanged_after_declining(tmp_path):
    output, usermod = run_client_group_helper(tmp_path, reply="n")

    assert not usermod
    assert "sudo lan-distribution-client status" in output


def test_client_installer_skips_existing_group_member(tmp_path):
    output, usermod = run_client_group_helper(tmp_path, groups="users lan-distribution")

    assert not output
    assert not usermod


def test_client_installer_is_informational_when_noninteractive(tmp_path):
    output, usermod = run_client_group_helper(tmp_path)

    assert not usermod
    assert "User 'alice' is not in group 'lan-distribution'." in output
    assert "sudo lan-distribution-client status" in output


def test_client_installer_does_not_prompt_in_explicit_noninteractive_mode(tmp_path):
    output, usermod = run_client_group_helper(tmp_path, reply="Y", noninteractive=True)

    assert "Add current user" not in output
    assert not usermod
    assert "sudo lan-distribution-client status" in output


@pytest.mark.parametrize(("user", "sudo_user"), [("root", True), ("alice", False)])
def test_client_installer_does_not_guess_a_user(tmp_path, user, sudo_user):
    output, usermod = run_client_group_helper(tmp_path, user=user, sudo_user=sudo_user)

    assert not output
    assert not usermod


def test_client_installer_repeat_is_idempotent(tmp_path):
    _, first_usermod = run_client_group_helper(tmp_path / "first", reply="y")
    output, second_usermod = run_client_group_helper(
        tmp_path / "second", groups="users lan-distribution"
    )

    assert first_usermod == "-aG lan-distribution alice\n"
    assert not output
    assert not second_usermod


@pytest.mark.skipif(os.geteuid() != 0, reason="requires root to impersonate a group member")
def test_client_group_member_can_run_status_without_reading_private_key(tmp_path):
    """The installed group grants status access, not client-key access."""
    group_id = 42424
    member_uid = 65534
    tmp_path.chmod(0o755)
    state = tmp_path / "state"
    credentials = state / "credentials"
    generation = credentials / "generation"
    generation.mkdir(parents=True)
    state.chown(0, group_id)
    state.chmod(0o2710)
    credentials.chown(0, group_id)
    credentials.chmod(0o2710)
    generation.chown(0, group_id)
    generation.chmod(0o2710)
    trust = state / "trust.json"
    trust.write_text(json.dumps({"server_id": "server", "url": "https://server"}))
    trust.chown(0, group_id)
    trust.chmod(0o640)
    key = generation / "key.pem"
    key.write_text("private")
    key.chown(0, 0)
    key.chmod(0o600)
    (generation / "cert.pem").write_text("certificate")
    (generation / "client-id").write_text("client")
    (credentials / "current").symlink_to(generation.name)
    config = tmp_path / "client.toml"
    config.write_text(f'[client]\nstate_dir = "{state}"\n')

    def as_member(code):
        return subprocess.run(
            [sys.executable, "-c", code],
            env=os.environ | {"PYTHONPATH": f"{ROOT / 'src'}:{os.environ.get('PYTHONPATH', '')}"},
            preexec_fn=lambda: (
                os.setgroups([group_id]),
                os.setgid(group_id),
                os.setuid(member_uid),
            ),
            capture_output=True,
            text=True,
            check=False,
        )

    status = as_member(
        "import sys; from lan_distribution.cli import client_main; "
        f"sys.argv = ['lan-distribution-client', '--config', '{config}', 'status']; "
        "raise SystemExit(client_main())"
    )
    assert status.returncode == 0, status.stderr
    assert "Server ID: server" in status.stdout
    assert "Enrolled: yes" in status.stdout
    private = as_member(f"from pathlib import Path; Path('{key}').read_bytes()")
    assert private.returncode != 0
    assert "Permission denied" in private.stderr


@pytest.mark.parametrize(
    "roles",
    [(), ("client",), ("server",), ("client", "server")],
)
def test_uninstall_staged_roles(tmp_path, roles):
    bin_dir = tmp_path / "usr/local/bin"
    unit_dir = tmp_path / "etc/systemd/system"
    venv_bin = tmp_path / "opt/lan-distribution/venv/bin"
    for directory in (bin_dir, unit_dir, venv_bin):
        directory.mkdir(parents=True)
    preserved = [
        tmp_path / "etc/lan-distribution/client.toml",
        tmp_path / "var/lib/lan-distribution/client/credentials/keep",
        tmp_path / "srv/lan-distribution/shared-config/keep",
    ]
    for item in preserved:
        item.parent.mkdir(parents=True, exist_ok=True)
        item.write_text("synthetic")
    for role in roles:
        (unit_dir / f"lan-distribution-{role}.service").write_text("[Service]\n")
        (venv_bin / f"lan-distribution-{role}").write_text("synthetic")
        (bin_dir / f"lan-distribution-{role}").symlink_to(venv_bin / f"lan-distribution-{role}")
    if "server" in roles:
        (venv_bin / "lan-distribution").write_text("synthetic")
        (bin_dir / "lan-distribution").symlink_to(venv_bin / "lan-distribution")
    environment = os.environ | {"DESTDIR": str(tmp_path)}
    for _ in range(2):
        result = subprocess.run(
            [str(ROOT / "scripts/uninstall.sh")],
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr
    for role in roles:
        assert not (unit_dir / f"lan-distribution-{role}.service").exists()
        assert not (bin_dir / f"lan-distribution-{role}").is_symlink()
    for item in preserved:
        assert item.read_text() == "synthetic"


@pytest.mark.parametrize("artifact", ["binary", "unit", "config", "admin_binary"])
def test_uninstall_partial_install(tmp_path, artifact):
    bin_dir = tmp_path / "usr/local/bin"
    unit_dir = tmp_path / "etc/systemd/system"
    config_dir = tmp_path / "etc/lan-distribution"
    for directory in (bin_dir, unit_dir, config_dir):
        directory.mkdir(parents=True)
    if artifact == "binary":
        (bin_dir / "lan-distribution-client").symlink_to(
            tmp_path / "opt/lan-distribution/venv/bin/lan-distribution-client"
        )
    elif artifact == "unit":
        (unit_dir / "lan-distribution-client.service").write_text("[Service]\n")
    elif artifact == "admin_binary":
        (bin_dir / "lan-distribution").symlink_to(
            tmp_path / "opt/lan-distribution/venv/bin/lan-distribution"
        )
    else:
        (config_dir / "client.toml").write_text("[client]\n")
    result = subprocess.run(
        [str(ROOT / "scripts/uninstall.sh")],
        env=os.environ | {"DESTDIR": str(tmp_path)},
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert not (bin_dir / "lan-distribution-client").is_symlink()
    assert not (unit_dir / "lan-distribution-client.service").exists()
    assert not (bin_dir / "lan-distribution").is_symlink()
    if artifact == "config":
        assert (config_dir / "client.toml").exists()
