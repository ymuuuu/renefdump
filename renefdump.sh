#!/usr/bin/env bash
# renefdump - PC-side wrapper for the renefdump Lua agent script.
#
# Runs the whole job end to end: resolves the renef client, spawns (or
# attaches to) the target app, loads the Lua dumper inside it via the renef
# client (which ships the script's source over the socket - the .lua file is
# never copied to the device), then pulls the device-side dump to the host.
#
# The dump lands in the app's own private directory (the only place an
# untrusted_app may write under SELinux), which plain adb pull cannot read,
# so retrieval goes through `adb shell su`: the files are staged to
# /data/local/tmp and pulled from there. Root is therefore required.
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

# 3. Root is required to retrieve the dump from the app's private directory.
#    Do not rely on `adb root` (KernelSU devices do not need it and may not
#    support it); `su` is the retrieval path.
check_root() {
  local id
  id=$(adb shell su -c id 2>/dev/null) || true
  case "$id" in
    *uid=0*)
      return 0
      ;;
  esac
  echo "error: root required: the dump lands in the app's private directory, which adb pull cannot read" >&2
  echo "       ('adb shell su -c id' did not report uid=0). Ensure a root manager such as KernelSU is active." >&2
  return 1
}

check_root
echo "[*] root: confirmed (su works)"

# 4. Target label. In spawn mode it is the package argument; in attach mode
#    the first NUL-delimited field of /proc/<pid>/cmdline, minus any
#    ":<subprocess>" suffix (Android names them "com.foo:remote"); fall back
#    to pid<N>. This matches what the Lua script derives on-device, so the
#    candidate app directories line up.
target_label() {
  if [ "$MODE" = spawn ]; then
    printf '%s\n' "$TARGET"
    return 0
  fi
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

PKG=$(target_label)
echo "[*] run target: $PKG"

# 5. Run the client one-shot; feed 'exit' so it does not sit in the REPL.
#    Its output goes straight to the terminal so progress shows live. The
#    script is passed directly - it picks its own output directory on-device.
if [ "$MODE" = attach ]; then
  echo "[*] renef -a $TARGET -l renefdump.lua"
  printf 'exit\n' | "$RENEF_BIN" -a "$TARGET" -l "$LUA_SCRIPT"
else
  echo "[*] renef -s $TARGET -l renefdump.lua"
  printf 'exit\n' | "$RENEF_BIN" -s "$TARGET" -l "$LUA_SCRIPT"
fi

# 6. The wrapper never learns the pid the script used, so it cannot know the
#    prefix. It locates the run by globbing our marker across the candidate
#    app directories, in the same order the script tries them. Spawn mode
#    cannot query /proc/<pid>/cmdline before the run, so this glob is the
#    only option. The literal `renefdump-` prefix is what keeps the app's own
#    files out of the match.
APP_DIR_CANDIDATES="/data/data/$PKG/cache /data/user/0/$PKG/cache /data/data/$PKG/files /data/data/$PKG"

find_app_dir() {
  # $1 = filename glob inside the app dir, e.g. 'renefdump-*_maps.txt'
  local dir
  for dir in $APP_DIR_CANDIDATES; do
    if adb shell su -c "ls '$dir'/$1 2>/dev/null" | grep -q .; then
      printf '%s\n' "$dir"
      return 0
    fi
  done
  return 1
}

# 7. The dump must have started before we wait for completion. maps.txt is
#    written before any range is dumped, so its absence shortly after the
#    client returns means the script never got that far (size cap exceeded,
#    no writable app directory, unreadable maps - all abort without writing).
echo "[*] confirming the dump started..."
MAPS_DIR=""
START_WAIT=0
while [ -z "$MAPS_DIR" ]; do
  sleep 2
  START_WAIT=$((START_WAIT + 2))
  MAPS_DIR=$(find_app_dir 'renefdump-*_maps.txt' || true)
  if [ "$START_WAIT" -ge 20 ]; then
    echo "error: the dump never started - no renefdump-*_maps.txt in any app directory after ${START_WAIT}s." >&2
    echo "       The script aborted before dumping. Check the client output above:" >&2
    echo "       a size cap, no writable app directory, or unreadable maps." >&2
    exit 1
  fi
done

# 8. The dump must signal completion before we pull: the Lua writes a DONE
#    sentinel as its very last action, so its presence means the dump ran to
#    completion. The client returning does NOT mean that (it stops relaying
#    after ~5 s of silence), so wait for the sentinel - 2 s polls, 30 min
#    ceiling. The newest DONE wins, so a run left behind by -k is not
#    mistaken for this one.
echo "[*] waiting for the dump to signal completion (DONE sentinel)..."
WAIT_SECS=0
while ! adb shell su -c "ls -t '$MAPS_DIR'/renefdump-*_DONE 2>/dev/null" | grep -q .; do
  sleep 2
  WAIT_SECS=$((WAIT_SECS + 2))
  if [ $((WAIT_SECS % 30)) -eq 0 ]; then
    echo "[*] still waiting for the dump to finish (${WAIT_SECS}s)..."
  fi
  if [ "$WAIT_SECS" -ge 1800 ]; then
    echo "error: no completion signal (DONE) after 30 minutes - refusing to pull a possibly truncated dump" >&2
    exit 1
  fi
done
echo "[*] dump complete signal received"

# `ls <dir>/<glob>` prints full paths, and adb shell terminates lines with
# CRLF, so reduce to a bare basename before deriving the prefix from it.
DONE_NAME=$(adb shell su -c "ls -t '$MAPS_DIR'/renefdump-*_DONE 2>/dev/null" \
  | head -n 1 | tr -d '\r' | sed 's|.*/||')
PREFIX="${DONE_NAME%DONE}"     # "renefdump-<pid>-<ts>_"
case "$PREFIX" in
  renefdump-*_) ;;
  *)
    echo "error: could not derive the run prefix from device sentinel '$DONE_NAME'" >&2
    exit 1
    ;;
esac

# The device staging directory is named after the run's own prefix, but the
# local directory keeps the package-and-date convention the operator asked for.
STAGE_NAME="${PREFIX%_}"                       # renefdump-<pid>-<ts>
RUN_NAME="$PKG-$(date +%Y%m%d-%H%M%S)"         # com.example.app-20260818-143022
echo "[*] run: $RUN_NAME"
echo "[*] app dir: $MAPS_DIR"

# 9. The dump must have produced files on the device. A silent empty pull is
#    the worst possible outcome, so fail loudly before staging.
NFILES=$(adb shell su -c "ls -1 '$MAPS_DIR'/${PREFIX}* 2>/dev/null" | wc -l) || NFILES=0
if [ "$NFILES" -eq 0 ]; then
  echo "error: the run produced no files in $MAPS_DIR for prefix $PREFIX - nothing to pull" >&2
  exit 1
fi
echo "[*] $NFILES files on device"

# 10. Stage the files where adb pull can reach them, then pull.
adb shell su -c "mkdir -p /data/local/tmp/$STAGE_NAME && cp '$MAPS_DIR'/${PREFIX}* /data/local/tmp/$STAGE_NAME/ && chmod -R 777 /data/local/tmp/$STAGE_NAME"
mkdir -p "$OUT_PARENT"
LOCAL_DIR="$OUT_PARENT/$RUN_NAME"
adb pull "/data/local/tmp/$STAGE_NAME" "$LOCAL_DIR"

# Some adb versions create <dest>/<remote-dirname> instead of copying the
# contents directly into <dest>; normalize so the layout is
# $LOCAL_DIR/*.data with no doubled directory level.
if [ -d "$LOCAL_DIR/$STAGE_NAME" ]; then
  mv "$LOCAL_DIR/$STAGE_NAME" "$LOCAL_DIR.tmp"
  rmdir "$LOCAL_DIR"
  mv "$LOCAL_DIR.tmp" "$LOCAL_DIR"
fi

# 11. Remove the device copies unless -k.
if [ "$KEEP" -eq 0 ]; then
  adb shell su -c "rm -rf /data/local/tmp/$STAGE_NAME '$MAPS_DIR'/${PREFIX}*"
  echo "[*] removed device copies (staging and app dir)"
else
  adb shell su -c "rm -rf /data/local/tmp/$STAGE_NAME"
  echo "[*] kept device copy in the app's private directory: $MAPS_DIR/${PREFIX}*"
fi

# 12. Summary.
NFILES_LOCAL=$(find "$LOCAL_DIR" -maxdepth 1 -name '*.data' -type f | wc -l)
SIZE_LOCAL=$(du -sh "$LOCAL_DIR" | cut -f1)
echo
echo "[+] dump complete:"
echo "    local:  $LOCAL_DIR"
echo "    files:  $NFILES_LOCAL .data files"
echo "    size:   $SIZE_LOCAL"
echo "    strings:"
echo "      strings -n 8 $LOCAL_DIR/*.data | sort -u > $LOCAL_DIR/strings.txt"