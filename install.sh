#!/usr/bin/env bash
#
# Install or update witness from the latest GitHub release.
#
#   curl -fsSL https://raw.githubusercontent.com/nsg/witness/master/install.sh | bash
#
# An existing witness found in PATH is updated in place. Otherwise the binary
# goes to WITNESS_INSTALL_DIR, or the first of ~/.local/bin and ~/bin that is
# in PATH.

set -euo pipefail

BASE_URL="https://github.com/nsg/witness/releases/latest/download"

# Release builds as "minimum glibc:asset", newest glibc first. The first one
# this system's glibc satisfies is used.
BUILDS=(2.39:witness-linux-glibc 2.35:witness-linux-glibc2.35)

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

main() {
    [ "$(uname -s)" = Linux ] || die "only Linux is supported"
    [ "$(uname -m)" = x86_64 ] || die "only x86_64 is supported, this is $(uname -m)"

    local glibc asset target dir sums expected installed=""
    glibc=$(glibc_version)
    asset=$(select_asset "$glibc")
    target=$(target_path)
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
    if [ -n "$installed" ]; then
        echo "Updated $target ($asset for glibc $glibc)"
    else
        echo "Installed $target ($asset for glibc $glibc)"
    fi
    if ! [ "$(type -P witness)" -ef "$target" ]; then
        echo "Note: $dir is not in your PATH"
    fi
}

main "$@"
