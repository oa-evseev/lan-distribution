#!/usr/bin/env bash
set -euo pipefail

print_sudo_admin_commands() {
    echo "Administrative commands can be run with sudo:"
    echo "sudo lan-distribution status"
    echo "sudo lan-distribution open 2min"
    echo "sudo lan-distribution close"
}

manage_server_admin_group() {
    local user="${SUDO_USER:-}" reply

    # A root login has no ordinary invoking user.  Do not infer one from the
    # environment or from the current directory.
    if [[ -z "$user" || "$user" == root ]] || ! id -u "$user" >/dev/null 2>&1; then
        return 0
    fi
    if id -nG "$user" | tr ' ' '\n' | grep -Fxq lan-distribution; then
        return 0
    fi
    if [[ ! -t 0 || "${NONINTERACTIVE:-}" == 1 || "${DEBIAN_FRONTEND:-}" == noninteractive ]]; then
        echo "User '$user' is not in group 'lan-distribution'."
        print_sudo_admin_commands
        return 0
    fi

    if ! read -r -p "Add current user '$user' to group 'lan-distribution'
so administrative commands can be run without sudo? [Y/n] " reply; then
        reply=n
    fi
    if [[ "${reply,,}" == n || "${reply,,}" == no ]]; then
        print_sudo_admin_commands
        return 0
    fi
    usermod -aG lan-distribution "$user"
    echo "User '$user' added to group 'lan-distribution'."
    echo "Group membership will take effect after the next login session."
}

print_sudo_client_commands() {
    echo "Client commands can be run with sudo:"
    echo "sudo lan-distribution-client status"
}

manage_client_admin_group() {
    local user="${SUDO_USER:-}" reply

    # A root login has no ordinary invoking user.  Do not infer one from the
    # environment or from the current directory.
    if [[ -z "$user" || "$user" == root ]] || ! id -u "$user" >/dev/null 2>&1; then
        return 0
    fi
    if id -nG "$user" | tr ' ' '\n' | grep -Fxq lan-distribution; then
        return 0
    fi
    if [[ ! -t 0 || "${NONINTERACTIVE:-}" == 1 || "${DEBIAN_FRONTEND:-}" == noninteractive ]]; then
        echo "User '$user' is not in group 'lan-distribution'."
        print_sudo_client_commands
        return 0
    fi

    if ! read -r -p "Add current user '$user' to group 'lan-distribution'
so client status/admin commands can be run without sudo? [Y/n] " reply; then
        reply=n
    fi
    if [[ "${reply,,}" == n || "${reply,,}" == no ]]; then
        print_sudo_client_commands
        return 0
    fi
    usermod -aG lan-distribution "$user"
    echo "User '$user' added to group 'lan-distribution'."
    echo "Group membership will take effect after the next login session."
}

secure_client_state() {
    local credentials="$state_dir/client/credentials"

    # Group members can read public enrollment status, but credential names
    # are not listable and private keys remain root-only.
    install -d -m 2710 -o root -g lan-distribution "$state_dir/client"
    if [[ -f "$state_dir/client/trust.json" ]]; then
        chown root:lan-distribution "$state_dir/client/trust.json"
        chmod 0640 "$state_dir/client/trust.json"
    fi
    if [[ -d "$credentials" ]]; then
        find "$credentials" -type d -exec chown root:lan-distribution {} + -exec chmod 2710 {} +
        find "$credentials" -type f -name key.pem -exec chown root:root {} + -exec chmod 0600 {} +
    fi
}

# Used by installer contract tests to load the small, host-facing helper
# without starting an installation.
if [[ "${INSTALL_SH_SOURCE_ONLY:-}" == 1 ]]; then
    return 0 2>/dev/null || exit 0
fi

role="${1:-}"
if [[ "$role" != client && "$role" != server ]]; then
    echo "Usage: $0 client|server" >&2
    exit 2
fi

# DESTDIR stages a runnable installation without root or systemd mutations.
root="${DESTDIR:-}"
if [[ -n "$root" ]]; then
    [[ "$root" == /* && "$root" != / ]] || { echo "DESTDIR must be an absolute non-root path" >&2; exit 2; }
    mkdir -p "$root"
elif (( EUID != 0 )); then
    command -v sudo >/dev/null || { echo "Missing prerequisite: sudo" >&2; exit 1; }
    exec sudo -- "$0" "$role"
fi
command -v python3 >/dev/null || { echo "Missing prerequisite: python3" >&2; exit 1; }
if [[ -z "$root" ]]; then
    command -v systemctl >/dev/null || { echo "Missing prerequisite: systemctl" >&2; exit 1; }
    if [[ "$role" == server ]]; then
        for tool in groupadd useradd usermod runuser; do
            command -v "$tool" >/dev/null || { echo "Missing prerequisite: $tool" >&2; exit 1; }
        done
    else
        for tool in groupadd usermod find; do
            command -v "$tool" >/dev/null || { echo "Missing prerequisite: $tool" >&2; exit 1; }
        done
    fi
fi
python3 -c 'import sys; assert sys.version_info >= (3, 12), "Python 3.12+ is required"'
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
path() { printf '%s%s' "$root" "$1"; }
venv="$(path /opt/lan-distribution/venv)"
bin_dir="$(path /usr/local/bin)"
config_dir="$(path /etc/lan-distribution)"
state_dir="$(path /var/lib/lan-distribution)"
unit_dir="$(path /etc/systemd/system)"
check_command_path() {
    local command_path="$1" target="$2"
    if [[ -e "$command_path" || -L "$command_path" ]]; then
        if [[ ! -L "$command_path" || "$(readlink "$command_path")" != "$target" ]]; then
            echo "Refusing to replace unrelated command: $command_path" >&2
            exit 1
        fi
    fi
}
if [[ "$role" == server ]]; then
    check_command_path "$bin_dir/lan-distribution" "$venv/bin/lan-distribution"
fi
check_command_path "$bin_dir/lan-distribution-$role" "$venv/bin/lan-distribution-$role"
if [[ ! -x "$venv/bin/python" ]]; then
    python3 -m venv "$venv"
fi
"$venv/bin/python" -m pip install --disable-pip-version-check "$repo_dir"
install -d -m 0755 "$config_dir" "$state_dir" "$bin_dir" "$unit_dir"
copy_default() {
    local source="$1" target="$2"
    if [[ ! -e "$target" && ! -L "$target" ]]; then
        install -m 0644 "$source" "$target"
        if [[ -n "$root" ]]; then
            python3 -c 'import pathlib,sys; p=pathlib.Path(sys.argv[1]); p.write_text(p.read_text().replace("\"/", "\"" + sys.argv[2] + "/"))' "$target" "$root"
        fi
    fi
}
if [[ -z "$root" ]] && ! getent group lan-distribution >/dev/null; then
    groupadd --system lan-distribution
fi
if [[ "$role" == server ]]; then
    if [[ -z "$root" ]] && ! id -u lan-distribution >/dev/null 2>&1; then
        useradd --system --gid lan-distribution --home-dir /var/lib/lan-distribution/server --shell /usr/sbin/nologin lan-distribution
    fi
    if [[ -z "$root" ]]; then
        install -d -m 0700 -o lan-distribution -g lan-distribution "$state_dir/server"
    else
        install -d -m 0700 "$state_dir/server"
    fi
    install -d -m 0755 "$(path /srv/lan-distribution)" "$(path /srv/lan-distribution/shared-config)"
    copy_default "$repo_dir/config/server.toml" "$config_dir/server.toml"
    "$venv/bin/python" -c 'import sys; from pathlib import Path; from lan_distribution.config import load_server; c=load_server(Path(sys.argv[1])); expected=(Path(sys.argv[2] + "/var/lib/lan-distribution/server"), Path(sys.argv[2] + "/run/lan-distribution")); sys.exit(0 if (c.state_dir,c.runtime_dir)==expected else "packaged server unit requires default state_dir and runtime_dir")' "$config_dir/server.toml" "$root"
    "$venv/bin/lan-distribution-server" --config "$config_dir/server.toml" validate
    if [[ -z "$root" ]]; then
        runuser -u lan-distribution -- "$venv/bin/lan-distribution-server" init
    else
        "$venv/bin/lan-distribution-server" --config "$config_dir/server.toml" init
    fi
    install -m 0644 "$repo_dir/systemd/lan-distribution-server.service" "$unit_dir/lan-distribution-server.service"
    ln -sfn "$venv/bin/lan-distribution-server" "$bin_dir/lan-distribution-server"
    ln -sfn "$venv/bin/lan-distribution" "$bin_dir/lan-distribution"
    echo "Server installed. Registration is closed. Discovery is enabled."
else
    if [[ -z "$root" ]]; then
        secure_client_state
    else
        install -d -m 0711 "$state_dir/client"
    fi
    copy_default "$repo_dir/config/client.toml" "$config_dir/client.toml"
    "$venv/bin/python" -c 'import sys; from pathlib import Path; from lan_distribution.config import load_client; c=load_client(Path(sys.argv[1])); sys.exit(0 if c.state_dir==Path(sys.argv[2] + "/var/lib/lan-distribution/client") else "packaged client unit requires default state_dir")' "$config_dir/client.toml" "$root"
    "$venv/bin/lan-distribution-client" --config "$config_dir/client.toml" validate
    if [[ -z "$root" ]]; then
        # validate constructs Client, so restore the installed group policy
        # before the unit or an interactive enrollment touches the state.
        secure_client_state
    fi
    install -m 0644 "$repo_dir/systemd/lan-distribution-client.service" "$unit_dir/lan-distribution-client.service"
    ln -sfn "$venv/bin/lan-distribution-client" "$bin_dir/lan-distribution-client"
fi
other=client
[[ "$role" == client ]] && other=server
if [[ ! -e "$unit_dir/lan-distribution-$other.service" && ! -L "$bin_dir/lan-distribution-$other" ]]; then
    rm -f "$venv/bin/lan-distribution-$other"
fi
if [[ ! -e "$unit_dir/lan-distribution-server.service" && ! -L "$bin_dir/lan-distribution-server" ]]; then
    rm -f "$venv/bin/lan-distribution"
fi
if [[ -n "$root" ]]; then
    echo "Staged $role installation in $root; no services were changed."
    exit 0
fi
systemctl daemon-reload
if [[ "$role" == server ]]; then
    systemctl enable --now lan-distribution-server.service
    manage_server_admin_group
else
    manage_client_admin_group
    if [[ -L "$state_dir/client/credentials/current" &&
          -f "$state_dir/client/credentials/current/cert.pem" &&
          -f "$state_dir/client/credentials/current/key.pem" ]]; then
        systemctl enable --now lan-distribution-client.service
        echo "Client already enrolled; service started."
        exit 0
    fi
    if ! read -r -p 'Discover lan-distribution servers on the local network? [Y/n] ' reply; then
        reply=n
    fi
    if [[ "${reply,,}" == n || "${reply,,}" == no ]]; then
        echo "Installed without enrollment. Later run: sudo lan-distribution-client enroll"
        exit 0
    fi
    "$venv/bin/lan-distribution-client" enroll
    if [[ -L "$state_dir/client/credentials/current" &&
          -f "$state_dir/client/credentials/current/cert.pem" &&
          -f "$state_dir/client/credentials/current/key.pem" ]]; then
        systemctl enable --now lan-distribution-client.service
        echo "Client service started."
    else
        echo "Installed without enrollment. Later run: sudo lan-distribution-client enroll"
    fi
fi
