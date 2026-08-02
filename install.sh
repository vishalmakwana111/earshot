#!/bin/sh
# earshot installer.
#
#   curl --proto '=https' --tlsv1.2 -LsSf \
#     https://github.com/vishalmakwana111/earshot/releases/latest/download/earshot-installer.sh | sh
#
# Downloads the prebuilt binary for this machine, verifies its checksum against
# the release's SHA256SUMS, and puts it on your PATH. No toolchain, no build.
#
# Environment:
#   EARSHOT_VERSION   tag to install (default: latest)
#   EARSHOT_BIN_DIR   install directory (default: $CARGO_HOME/bin, else ~/.local/bin)
#   EARSHOT_NO_VERIFY set to skip checksum verification (not recommended)
#   EARSHOT_BASE_URL  override the download root (used by this repo's tests;
#                     same precedent as rustup's RUSTUP_UPDATE_ROOT)
#
# POSIX sh on purpose: this has to run under dash and busybox ash, not just bash.

set -eu

REPO="vishalmakwana111/earshot"
BIN="earshot"

say() { printf '%s\n' "$*"; }
err() { printf 'error: %s\n' "$*" >&2; exit 1; }

need() {
    command -v "$1" >/dev/null 2>&1 || err "this installer needs '$1'"
}

# --- work out which artifact this machine wants -----------------------------

detect_target() {
    os=$(uname -s)
    arch=$(uname -m)
    case "$os" in
        Linux)  os_part=unknown-linux-gnu ;;
        Darwin) os_part=apple-darwin ;;
        MINGW*|MSYS*|CYGWIN*)
            err "on Windows use PowerShell and grab the .zip from https://github.com/$REPO/releases, or run: cargo install earshot" ;;
        *) err "unsupported operating system: $os" ;;
    esac
    case "$arch" in
        x86_64|amd64) arch_part=x86_64 ;;
        aarch64|arm64) arch_part=aarch64 ;;
        *) err "unsupported architecture: $arch (try: cargo install earshot)" ;;
    esac
    printf '%s-%s' "$arch_part" "$os_part"
}

# --- where to put it --------------------------------------------------------

detect_bin_dir() {
    if [ -n "${EARSHOT_BIN_DIR:-}" ]; then
        printf '%s' "$EARSHOT_BIN_DIR"
    elif [ -n "${CARGO_HOME:-}" ] && [ -d "$CARGO_HOME/bin" ]; then
        printf '%s' "$CARGO_HOME/bin"
    elif [ -d "$HOME/.cargo/bin" ]; then
        printf '%s' "$HOME/.cargo/bin"
    else
        printf '%s' "$HOME/.local/bin"
    fi
}

# --- fetch ------------------------------------------------------------------

fetch() {
    # $1 url, $2 destination
    if command -v curl >/dev/null 2>&1; then
        case "$1" in
            # An explicit EARSHOT_BASE_URL may be a local test server; the
            # default GitHub path stays pinned to TLS 1.2+.
            http://*) curl -fLsS "$1" -o "$2" ;;
            *) curl --proto '=https' --tlsv1.2 -fLsS "$1" -o "$2" ;;
        esac
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$2" "$1"
    else
        err "this installer needs curl or wget"
    fi
}

verify() {
    # $1 archive path, $2 checksums file, $3 archive basename
    if [ -n "${EARSHOT_NO_VERIFY:-}" ]; then
        say "  (skipping checksum verification at your request)"
        return 0
    fi
    expected=$(awk -v f="$3" '$2 == f || $2 == "*"f { print $1 }' "$2" | head -1)
    [ -n "$expected" ] || err "no checksum for $3 in SHA256SUMS"

    if command -v sha256sum >/dev/null 2>&1; then
        actual=$(sha256sum "$1" | awk '{print $1}')
    elif command -v shasum >/dev/null 2>&1; then
        actual=$(shasum -a 256 "$1" | awk '{print $1}')
    else
        say "  (no sha256 tool found; cannot verify)"
        return 0
    fi

    [ "$expected" = "$actual" ] \
        || err "checksum mismatch for $3
  expected $expected
  actual   $actual
Refusing to install. This could be a corrupted download or a tampered asset."
    say "  checksum ok"
}

main() {
    need tar
    need awk
    need uname

    target=$(detect_target)
    bin_dir=$(detect_bin_dir)
    version=${EARSHOT_VERSION:-latest}

    if [ -n "${EARSHOT_BASE_URL:-}" ]; then
        base="$EARSHOT_BASE_URL"
    elif [ "$version" = latest ]; then
        base="https://github.com/$REPO/releases/latest/download"
    else
        base="https://github.com/$REPO/releases/download/$version"
    fi

    archive="$BIN-$target.tar.gz"
    say "earshot installer"
    say "  target:  $target"
    say "  version: $version"
    say "  into:    $bin_dir"

    tmp=$(mktemp -d 2>/dev/null || mktemp -d -t earshot)
    # Clean up whatever happens, including on failure.
    trap 'rm -rf "$tmp"' EXIT HUP INT TERM

    say "  downloading $archive"
    fetch "$base/$archive" "$tmp/$archive" \
        || err "could not download $base/$archive
Check that a release exists for this platform: https://github.com/$REPO/releases"

    if fetch "$base/SHA256SUMS" "$tmp/SHA256SUMS" 2>/dev/null; then
        verify "$tmp/$archive" "$tmp/SHA256SUMS" "$archive"
    else
        say "  (no SHA256SUMS published; cannot verify)"
    fi

    tar -xzf "$tmp/$archive" -C "$tmp"
    # The archive holds a single directory named after the target.
    found=$(find "$tmp" -type f -name "$BIN" -perm -u+x 2>/dev/null | head -1)
    [ -n "$found" ] || found=$(find "$tmp" -type f -name "$BIN" | head -1)
    [ -n "$found" ] || err "archive did not contain a '$BIN' binary"

    mkdir -p "$bin_dir"
    # Install via a temporary name then move, so an interrupted copy cannot
    # leave a half-written binary where a working one used to be.
    cp "$found" "$bin_dir/$BIN.tmp.$$"
    chmod 755 "$bin_dir/$BIN.tmp.$$"
    mv -f "$bin_dir/$BIN.tmp.$$" "$bin_dir/$BIN"

    say "  installed $bin_dir/$BIN"
    "$bin_dir/$BIN" --version 2>/dev/null || true

    case ":${PATH}:" in
        *":$bin_dir:"*) ;;
        *)
            say ""
            say "$bin_dir is not on your PATH. Add it:"
            say "  export PATH=\"$bin_dir:\$PATH\""
            ;;
    esac
}

main "$@"
