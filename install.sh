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

# Release builds, newest glibc first. The first one that runs here is used.
ASSETS=(witness-linux-glibc witness-linux-glibc2.35)

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

    local target dir sums asset expected current=""
    target=$(target_path)
    dir=$(dirname "$target")

    sums=$(curl -fsSL "$BASE_URL/sha256sums.txt") || die "could not fetch the release checksums"

    if [ -f "$target" ]; then
        current=$(sha256sum "$target" | cut -d' ' -f1)
        if grep -q "^$current " <<<"$sums"; then
            echo "witness is already up to date at $target"
            return
        fi
    fi

    mkdir -p "$dir"
    [ -w "$dir" ] || die "$dir is not writable, rerun as a user that can write there"

    # Download next to the target so the final rename is atomic, which also
    # lets it replace a binary that is currently running.
    TMP=$(mktemp "$dir/.witness.XXXXXX")
    trap 'rm -f "$TMP"' EXIT

    for asset in "${ASSETS[@]}"; do
        expected=$(awk -v name="$asset" '$2 == name { print $1 }' <<<"$sums")
        [ -n "$expected" ] || die "no checksum published for $asset"

        curl -fsSL "$BASE_URL/$asset" -o "$TMP" || die "could not download $asset"
        [ "$(sha256sum "$TMP" | cut -d' ' -f1)" = "$expected" ] || die "checksum mismatch for $asset"

        chmod 755 "$TMP"
        if "$TMP" --version >/dev/null 2>&1; then
            mv "$TMP" "$target"
            if [ -n "$current" ]; then
                echo "Updated $target ($asset)"
            else
                echo "Installed $target ($asset)"
            fi
            if ! [ "$(type -P witness)" -ef "$target" ]; then
                echo "Note: $dir is not in your PATH"
            fi
            return
        fi
    done

    die "no release build runs on this system, glibc 2.35 or newer is required"
}

main "$@"
