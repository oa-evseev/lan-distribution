#!/usr/bin/env bash
set -euo pipefail
root="${DESTDIR:-}"
if [[ -n "$root" ]]; then
    [[ "$root" == /* && "$root" != / ]] || { echo "DESTDIR must be an absolute non-root path" >&2; exit 2; }
elif (( EUID != 0 )); then
    command -v sudo >/dev/null || { echo "Missing prerequisite: sudo" >&2; exit 1; }
    exec sudo -- "$0"
fi
path() { printf '%s%s' "$root" "$1"; }
venv="$(path /opt/lan-distribution/venv)"
bin_dir="$(path /usr/local/bin)"
unit_dir="$(path /etc/systemd/system)"
installed() {
    local role="$1" link="$bin_dir/lan-distribution-$1"
    if [[ -e "$unit_dir/lan-distribution-$role.service" || -L "$unit_dir/lan-distribution-$role.service" ||
          ( -L "$link" && "$(readlink "$link")" == "$venv/bin/lan-distribution-$role" ) ||
          -e "$venv/bin/lan-distribution-$role" ]]; then
        return 0
    fi
    if [[ "$role" == server &&
          ( ( -L "$bin_dir/lan-distribution" && "$(readlink "$bin_dir/lan-distribution")" == "$venv/bin/lan-distribution" ) ||
            -e "$venv/bin/lan-distribution" ) ]]; then
        return 0
    fi
    return 1
}
found=false
for role in client server; do
    if installed "$role"; then
        found=true
        if [[ -z "$root" ]]; then
            systemctl disable --now "lan-distribution-$role.service" 2>/dev/null || true
        fi
        rm -f "$unit_dir/lan-distribution-$role.service"
        link="$bin_dir/lan-distribution-$role"
        if [[ -L "$link" && "$(readlink "$link")" == "$venv/bin/lan-distribution-$role" ]]; then
            rm -f "$link"
        fi
        rm -f "$venv/bin/lan-distribution-$role"
        if [[ "$role" == server ]]; then
            link="$bin_dir/lan-distribution"
            if [[ -L "$link" && "$(readlink "$link")" == "$venv/bin/lan-distribution" ]]; then
                rm -f "$link"
            fi
            rm -f "$venv/bin/lan-distribution"
        fi
    fi
done
if ! $found; then
    echo "lan-distribution is not installed."
    exit 0
fi
if [[ -z "$root" ]]; then
    systemctl daemon-reload
fi
if ! installed client && ! installed server; then
    link="$bin_dir/lan-distribution"
    if [[ -L "$link" && "$(readlink "$link")" == "$venv/bin/lan-distribution" ]]; then
        rm -f "$link"
    fi
    if [[ -d "$venv" ]]; then
        rm -rf -- "$venv"
    fi
fi
echo "Removed installed program files and units. Config, state, and datasets were preserved."
