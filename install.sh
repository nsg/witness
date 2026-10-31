#!/usr/bin/env bash
#
# Install or update witness from the latest GitHub release.
#
#   curl -fsSL https://raw.githubusercontent.com/nsg/witness/master/install.sh | bash
#
# An existing witness found in PATH is updated in place. Otherwise the binary
# goes to WITNESS_INSTALL_DIR, or the first of ~/.local/bin and ~/bin that is
# in PATH.
#
# With --service, also set up a systemd service that keeps a witness session
# connected to a relay and starts it at boot:
#
#   curl -fsSL https://raw.githubusercontent.com/nsg/witness/master/install.sh | bash -s -- --service
#
# Run as root it is a system service running as root, and a new binary goes to
# /usr/local/bin. Run as any other user it is a systemd user service running as
# that user. A relay key is generated unless the key file already exists.
# Options:
#
#   --relay <url>      relay to connect to, defaults to DEFAULT_RELAY below
#   --key-file <path>  relay key file, defaults to ~/.config/witness/relay.key

set -euo pipefail

BASE_URL="https://github.com/nsg/witness/releases/latest/download"
DEFAULT_RELAY="https://witness.k8s.junkpile.se"

# Release builds as "minimum glibc:asset", newest glibc first. The first one
# this system's glibc satisfies is used.
BUILDS=(2.39:witness-linux-glibc 2.35:witness-linux-glibc2.35 2.31:witness-linux-glibc2.31)

SERVICE=""
RELAY=""
KEY_FILE=""
UPDATED=""

die() {
    echo "install.sh: $*" >&2
    exit 1
}

in_path() {
    case ":$PATH:" in
        *":$1:"*) return 0 ;;
        *) return 1 ;;
    esac
}

# Print the glibc version of this system, such as 2.35.
glibc_version() {
    local version
    version=$(getconf GNU_LIBC_VERSION 2>/dev/null) ||
        version=$(ldd --version 2>/dev/null | head -n 1) || true
    grep -oE '[0-9]+\.[0-9]+$' <<<"$version" || die "could not detect glibc, only glibc systems are supported"
}

# Print the release build to use for the given glibc version.
select_asset() {
    local build
    for build in "${BUILDS[@]}"; do
        if [ "$(printf '%s\n' "${build%%:*}" "$1" | sort -V | head -n 1)" = "${build%%:*}" ]; then
            echo "${build#*:}"
            return
        fi
    done
    die "glibc $1 is too old, ${BUILDS[-1]%%:*} or newer is required"
}

# Print where the binary should be installed.
target_path() {
    local existing dir
    if [ -n "${WITNESS_INSTALL_DIR:-}" ]; then
        echo "$WITNESS_INSTALL_DIR/witness"
    elif existing=$(type -P witness); then
        realpath "$existing"
    elif [ -n "$SERVICE" ] && [ "$(id -u)" = 0 ]; then
        echo /usr/local/bin/witness
    else
        for dir in "$HOME/.local/bin" "$HOME/bin"; do
            if in_path "$dir"; then
                echo "$dir/witness"
                return
            fi
        done
        echo "$HOME/.local/bin/witness"
    fi
}

install_binary() {
    local target=$1 glibc asset dir sums expected installed=""
    glibc=$(glibc_version)
    asset=$(select_asset "$glibc")
    dir=$(dirname "$target")

    sums=$(curl -fsSL "$BASE_URL/sha256sums.txt") || die "could not fetch the release checksums"
    expected=$(awk -v name="$asset" '$2 == name { print $1 }' <<<"$sums")
    [ -n "$expected" ] || die "no checksum published for $asset"

    if [ -f "$target" ]; then
        installed=$(sha256sum "$target" | cut -d' ' -f1)
        if [ "$installed" = "$expected" ]; then
            echo "witness is already up to date at $target ($asset for glibc $glibc)"
            return
        fi
    fi

    mkdir -p "$dir"
    [ -w "$dir" ] || die "$dir is not writable, rerun as a user that can write there"

    # Download next to the target so the final rename is atomic, which also
    # lets it replace a binary that is currently running.
    TMP=$(mktemp "$dir/.witness.XXXXXX")
    trap 'rm -f "$TMP"' EXIT

    curl -fsSL "$BASE_URL/$asset" -o "$TMP" || die "could not download $asset"
    [ "$(sha256sum "$TMP" | cut -d' ' -f1)" = "$expected" ] || die "checksum mismatch for $asset"

    chmod 755 "$TMP"
    mv "$TMP" "$target"
    UPDATED=1
    if [ -n "$installed" ]; then
        echo "Updated $target ($asset for glibc $glibc)"
    else
        echo "Installed $target ($asset for glibc $glibc)"
    fi
    if ! [ "$(type -P witness)" -ef "$target" ]; then
        echo "Note: $dir is not in your PATH"
    fi
}

# Die if the value holds characters that systemd or the shell in ExecStart
# would reinterpret.
require_plain() {
    case "$2" in
        *[!A-Za-z0-9_./:@+-]*) die "$1 cannot go in the service unit: $2" ;;
    esac
}

# Start this user's service manager and keep it running without a login, so
# the service also starts at boot.
start_user_manager() {
    local user attempt
    user=$(id -un)
    loginctl enable-linger "$user" ||
        echo "Warning: the service will stop at logout and not start at boot, until an admin runs: loginctl enable-linger $user" >&2

    export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
    for attempt in 1 2 3 4 5 6 7 8 9 10; do
        systemctl --user daemon-reload 2>/dev/null && return
        [ "$attempt" = 10 ] || sleep 1
    done
    die "could not reach the systemd user manager of $user"
}

# Print the service unit.
service_unit() {
    local target=$1 relay=$2 key_file=$3 wanted_by=$4
    cat <<EOF
[Unit]
Description=witness session (agent access over relay)
Documentation=https://github.com/nsg/witness
Wants=network-online.target
After=network-online.target
# Never give up restarting.
StartLimitIntervalSec=0

[Service]
Type=simple
WorkingDirectory=%h
Environment=HOME=%h
Environment=TERM=xterm-256color

# A login shell gives witness and the shell it wraps the environment of a
# normal login. Nobody can press Ctrl-G here, so auto-approve is what lets the
# session run anything: whoever holds the relay key can run commands as this
# user.
ExecStart=/bin/bash -lc 'exec $target run --relay $relay --relay-key-file $key_file --auto-approve'

# There is no terminal. stdout mirrors the shell's terminal, so discard it to
# keep command output out of the journal. stderr has the banner and errors.
StandardInput=null
StandardOutput=null
StandardError=journal

# The wrapped shell ending ends witness; bring it back.
Restart=always
RestartSec=5

# An interactive bash ignores SIGTERM but exits on SIGHUP, as it would when a
# terminal closes.
SendSIGHUP=yes
TimeoutStopSec=15

# Commands behave as in a login shell, so there is no sandboxing here.
TasksMax=infinity

[Install]
WantedBy=$wanted_by
EOF
}

install_service() {
    local target relay=${RELAY:-$DEFAULT_RELAY} key_file unit_dir wanted_by unit run_as new_unit=""
    local -a systemctl=(systemctl)
    target=$(realpath "$1")
    key_file=$(realpath -m "${KEY_FILE:-$HOME/.config/witness/relay.key}")

    case "$relay" in
        http://* | https://*) ;;
        *) die "the relay URL must start with http:// or https://" ;;
    esac
    require_plain "the relay URL" "$relay"
    require_plain "the binary path" "$target"
    require_plain "the key file path" "$key_file"

    if [ "$(id -u)" = 0 ]; then
        run_as=root
        unit_dir=/etc/systemd/system
        wanted_by=multi-user.target
    else
        run_as="$(id -un), as a systemd user service"
        systemctl+=(--user)
        unit_dir=$HOME/.config/systemd/user
        wanted_by=default.target
        start_user_manager
    fi
    unit=$unit_dir/witness.service

    # Replacing a live unit or its key would cut off whoever is connected, and
    # restarting ends the session this script may well be running in.
    if "${systemctl[@]}" is-enabled --quiet witness.service 2>/dev/null; then
        echo "witness.service is already enabled, leaving it as it is"
        if [ -n "$UPDATED" ]; then
            echo "It runs the new binary after: ${systemctl[*]} restart witness.service"
        fi
        return
    fi

    if [ ! -e "$unit" ]; then
        if [ -s "$key_file" ]; then
            echo "Using the relay key in $key_file"
        else
            # A new file, as an existing empty one may be readable by others.
            (
                umask 077
                mkdir -p "$(dirname "$key_file")"
                key_tmp=$(mktemp "$key_file.XXXXXX")
                "$target" key >"$key_tmp"
                mv "$key_tmp" "$key_file"
            )
            echo "Generated a relay key in $key_file"
        fi

        mkdir -p "$unit_dir"
        service_unit "$target" "$relay" "$key_file" "$wanted_by" >"$unit"
        new_unit=1
    fi
    "${systemctl[@]}" daemon-reload
    "${systemctl[@]}" enable --now witness.service

    sleep 2
    "${systemctl[@]}" is-active --quiet witness.service ||
        die "witness.service did not start, see: ${systemctl[*]} status witness.service"
    echo "witness.service is running as $run_as"
    if [ -n "$new_unit" ]; then
        echo
        echo "On the agent host, connect with a copy of $key_file:"
        echo "  witness connect $relay --relay-key-file relay.key"
    fi
}

parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --service) SERVICE=1 ;;
            --relay)
                [ $# -ge 2 ] || die "--relay needs a URL"
                RELAY=$2
                shift
                ;;
            --key-file)
                [ $# -ge 2 ] || die "--key-file needs a path"
                KEY_FILE=$2
                shift
                ;;
            *) die "unknown option $1" ;;
        esac
        shift
    done
    if [ -z "$SERVICE" ] && [ -n "$RELAY$KEY_FILE" ]; then
        die "--relay and --key-file only apply with --service"
    fi
}

main() {
    parse_args "$@"

    [ "$(uname -s)" = Linux ] || die "only Linux is supported"
    [ "$(uname -m)" = x86_64 ] || die "only x86_64 is supported, this is $(uname -m)"
    if [ -n "$SERVICE" ]; then
        [ -d /run/systemd/system ] || die "--service needs a system running systemd"
        # HOME may still be the invoking user's under sudo.
        HOME=$(getent passwd "$(id -u)" | cut -d: -f6) || die "could not find the home directory of this user"
    fi

    local target
    target=$(target_path)
    install_binary "$target"
    if [ -n "$SERVICE" ]; then
        install_service "$target"
    fi
}

main "$@"
