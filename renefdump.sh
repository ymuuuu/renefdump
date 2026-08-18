#!/usr/bin/env bash
# renefdump - PC-side wrapper for the renefdump Lua agent script.
#
# Runs the whole job end to end: resolves the renef client, spawns (or
# attaches to) the target app, loads the Lua dumper inside it via the renef
# client (which ships the script's source over the socket - the .lua file is
# never copied to the device), then pulls the device-side dump to the host.
#
# Usage:
#   ./renefdump.sh <package>              # spawn the app, dump, pull
#   ./renefdump.sh -a <pid>               # attach to a running pid instead
#   ./renefdump.sh -o <dir> <package>     # local output parent (default: ./dumps)
#   ./renefdump.sh -r <path> <package>    # path to the renef client binary
#   ./renefdump.sh -k <package>           # keep the dump on the device (skip cleanup)
set -eu
set -o pipefail

usage() {
  cat <<'EOF'
Usage:
  ./renefdump.sh <package>              # spawn the app, dump, pull
  ./renefdump.sh -a <pid>               # attach to a running pid instead
  ./renefdump.sh -o <dir> <package>     # local output parent (default: ./dumps)
  ./renefdump.sh -r <path> <package>    # path to the renef client binary
  ./renefdump.sh -k <package>           # keep the dump on the device (skip cleanup)
EOF
}

MODE=spawn
TARGET=""
OUT_PARENT=./dumps
RENEF=""
KEEP=0

while [ "$#" -gt 0 ]; do
  case "$1" in
    -a)
      MODE=attach
      shift
      if [ "$#" -eq 0 ]; then
        echo "error: -a requires a pid" >&2
        usage >&2
        exit 1
      fi
      TARGET="$1"
      shift
      ;;
    -o)
      shift
      if [ "$#" -eq 0 ]; then
        echo "error: -o requires a directory" >&2
        usage >&2
        exit 1
      fi
      OUT_PARENT="$1"
      shift
      ;;
    -r)
      shift
      if [ "$#" -eq 0 ]; then
        echo "error: -r requires a path" >&2
        usage >&2
        exit 1
      fi
      RENEF="$1"
      shift
      ;;
    -k)
      KEEP=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    -*)
      echo "error: unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
    *)
      if [ -n "$TARGET" ]; then
        echo "error: unexpected extra argument: $1" >&2
        usage >&2
        exit 1
      fi
      TARGET="$1"
      shift
      ;;
  esac
done

if [ -z "$TARGET" ]; then
  usage >&2
  exit 1
fi

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
LUA_SCRIPT="$SCRIPT_DIR/scripts/examples/renefdump.lua"

# 1. Resolve the renef client binary.
resolve_renef() {
  if [ -n "$RENEF" ]; then
    if [ ! -x "$RENEF" ]; then
      echo "error: renef binary not found or not executable: $RENEF" >&2
      return 1
    fi
    printf '%s\n' "$RENEF"
    return 0
  fi
  if [ -n "${RENEF_BIN:-}" ] && [ -x "$RENEF_BIN" ]; then
    printf '%s\n' "$RENEF_BIN"
    return 0
  fi
  if [ -x ./build/renef ]; then
    printf '%s\n' ./build/renef
    return 0
  fi
  if [ -x ../renef/build/renef ]; then
    printf '%s\n' ../renef/build/renef
    return 0
  fi
  if command -v renef >/dev/null 2>&1; then
    printf '%s\n' "$(command -v renef)"
    return 0
  fi
  echo "error: renef client not found. Checked: -r <path>, \$RENEF_BIN, ./build/renef, ../renef/build/renef, and renef on PATH" >&2
  return 1
}

RENEF_BIN=$(resolve_renef)
echo "[*] renef client: $RENEF_BIN"

# 2. Verify adb is present and exactly one device is connected.
verify_adb() {
  if ! command -v adb >/dev/null 2>&1; then
    echo "error: adb not found on PATH" >&2
    return 1
  fi
  if ! adb get-state >/dev/null 2>&1; then
    echo "error: adb cannot reach a device (adb get-state failed)" >&2
    return 1
  fi
  local ndev
  ndev=$(adb devices | awk 'NR>1 && $2=="device" {n++} END {print n+0}')
  if [ "$ndev" -ne 1 ]; then
    echo "error: expected exactly one connected device, found $ndev" >&2
    return 1
  fi
}

verify_adb

# 3. Target label used for the run directory name.
target_label() {
  if [ "$MODE" = spawn ]; then
    printf '%s\n' "$TARGET"
    return 0
  fi
  # First NUL-delimited field of /proc/<pid>/cmdline, minus any
  # ":<subprocess>" suffix (Android names them "com.foo:remote"); fall
  # back to pid<N>.
  local cmdline
  cmdline=$(adb shell cat /proc/"$TARGET"/cmdline 2>/dev/null | tr '\0' '\n' | head -n 1)
  if [ -z "$cmdline" ]; then
    printf 'pid%s\n' "$TARGET"
    return 0
  fi
  cmdline=$(printf '%s\n' "$cmdline" | sed -e 's/:.*$//' -e 's|/|_|g')
  if [ -z "$cmdline" ]; then
    printf 'pid%s\n' "$TARGET"
  else
    printf '%s\n' "$cmdline"
  fi
}

LABEL=$(target_label)
RUN_NAME="$LABEL-$(date +%Y%m%d-%H%M%S)"
DEV_DIR="/data/local/tmp/renefdump/$RUN_NAME"

echo "[*] run: $RUN_NAME"
echo "[*] device dir: $DEV_DIR"

# 4. Root the adb daemon (tolerate failure: already root, or the build does
#    not support it), then create the per-run device directory.
adb root >/dev/null 2>&1 || true
adb shell "mkdir -p '$DEV_DIR' && chmod 777 '$DEV_DIR'"

# 5. Build a temporary Lua: a RENEFDUMP_OUT_DIR override line in front of the
#    script's own source. Removed by the trap on any exit path.
TMP_LUA_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_LUA_DIR"' EXIT
TMP_LUA="$TMP_LUA_DIR/renefdump.lua"
{
  printf 'RENEFDUMP_OUT_DIR = "%s"\n' "$DEV_DIR"
  cat "$LUA_SCRIPT"
} > "$TMP_LUA"

# 6. Run the client one-shot; feed 'exit' so it does not sit in the REPL.
#    Its output goes straight to the terminal so progress shows live.
if [ "$MODE" = attach ]; then
  echo "[*] renef -a $TARGET -l <tmp.lua>"
  printf 'exit\n' | "$RENEF_BIN" -a "$TARGET" -l "$TMP_LUA"
else
  echo "[*] renef -s $TARGET -l <tmp.lua>"
  printf 'exit\n' | "$RENEF_BIN" -s "$TARGET" -l "$TMP_LUA"
fi

# 7. The dump must have produced files on the device. A silent empty pull is
#    the worst possible outcome, so fail loudly before pulling.
NFILES=$(adb shell "ls -1 '$DEV_DIR' 2>/dev/null" | wc -l) || NFILES=0
if [ "$NFILES" -eq 0 ]; then
  echo "error: the client run produced no files in $DEV_DIR - nothing to pull" >&2
  exit 1
fi
echo "[*] $NFILES files on device"

# 8. Pull the run directory into the local output parent.
mkdir -p "$OUT_PARENT"
LOCAL_DIR="$OUT_PARENT/$RUN_NAME"
adb pull "$DEV_DIR" "$LOCAL_DIR"

# Some adb versions create <dest>/<remote-dirname> instead of copying the
# contents directly into <dest>; normalize so the layout is
# $LOCAL_DIR/*.data with no doubled directory level.
if [ -d "$LOCAL_DIR/$RUN_NAME" ]; then
  mv "$LOCAL_DIR/$RUN_NAME" "$LOCAL_DIR.tmp"
  rmdir "$LOCAL_DIR"
  mv "$LOCAL_DIR.tmp" "$LOCAL_DIR"
fi

# 9. Remove the device copy unless -k.
if [ "$KEEP" -eq 0 ]; then
  adb shell "rm -rf '$DEV_DIR'"
  echo "[*] removed device copy: $DEV_DIR"
else
  echo "[*] kept device copy: $DEV_DIR"
fi

# 10. Summary.
NFILES_LOCAL=$(find "$LOCAL_DIR" -maxdepth 1 -name '*.data' -type f | wc -l)
SIZE_LOCAL=$(du -sh "$LOCAL_DIR" | cut -f1)
echo
echo "[+] dump complete:"
echo "    local:  $LOCAL_DIR"
echo "    files:  $NFILES_LOCAL .data files"
echo "    size:   $SIZE_LOCAL"
echo "    strings:"
echo "      strings -n 8 $LOCAL_DIR/*.data | sort -u > $LOCAL_DIR/strings.txt"
