# renefdump

Memory dumper for [renef](https://github.com/Ahmeth4n/renef), the Android ARM64
instrumentation toolkit. A port of [fridump3](https://github.com/rootbsd/fridump3) to
renef's Lua agent, for targets that detect Frida but not renef.

Single file, no dependencies: `scripts/examples/renefdump.lua`.

## Usage

Copy the script into a renef checkout (or run it from this repo's path), then:

```
adb forward tcp:1907 tcp:1907
adb root
adb shell mkdir -p /data/local/tmp/renefdump && adb shell chmod 777 /data/local/tmp/renefdump
./build/renef
renef> attach <pid>
renef> l scripts/examples/renefdump.lua
```

The output directory must exist before the script runs — the script never executes a shell
(see below), so it cannot create it itself. The dump is written on the device. The script
prints the commands to pull it:

```
  mkdir -p ./dump
  adb exec-out "cd /data/local/tmp/renefdump && tar cf - 12847-1755512400_*" | tar xf - -C ./dump
  adb shell "rm -f /data/local/tmp/renefdump/12847-1755512400_*"
```

`adb pull` cannot glob, so the run's files are tarred on the device and streamed to the host.

## Configuration

Edit the `M.config` table at the top of the script — renef's `l` command passes no arguments.

| Key | Default | Meaning |
|---|---|---|
| `OUT_DIR` | `/data/local/tmp/renefdump` | Output directory; must already exist (create it from the host) |
| `PERMS_FILTER` | `"rw"` | `"rw"` = writable ranges only (fridump default), `"r"` = every readable range |
| `SKIP_FILE_BACKED` | `false` | `true` limits the dump to anon/heap/stack |
| `MAX_TOTAL_MB` | `1024` | Abort if the selection is larger |
| `SPLIT_MB` | `256` | Split a single range above this into `.partN` files |
| `CHUNK_KB` | `1024` | Read granularity |
| `VERBOSE` | `false` | Log every range |

## Output

All runs share `OUT_DIR`; each run's files carry a `<pid>-<timestamp>_` prefix. One file per
memory range, named `<prefix><start>-<end>_<perms>_<label>.data`, e.g.
`12847-1755512400_7f8a2c0000-7f8a2e0000_rw-p_heap.data`, plus a `<prefix>maps.txt` copy of
`/proc/self/maps`. A range above `SPLIT_MB` becomes `.part0`, `.part1`, … which `cat` back
together in order.

Every file is exactly `end - start` bytes. Unreadable chunks are zero-filled rather than
dropped, so offsets in the dump always match addresses in the maps — a gap shows up as a run
of zero bytes, not as missing data.

Unlike fridump3, the filename identifies the mapping a hit came from, and there are no
routine split boundaries cutting a string in half.

Run `strings` on the host after pulling — it is faster and better than anything the agent
could do on the device:

```
strings -n 8 dump/*.data | sort -u > strings.txt
```

## Why /proc/self/mem

renef's `Memory.read()` and `File.write()` dereference the address directly with no fault
guard, so one unreadable page kills the target process. `/proc/self/mem` returns a read
error instead. The agent runs inside the target, so `self` is the target.

## No shell, by design

The script never calls `os.execute` or `io.popen`. Executing a shell from inside an app
process can be blocked by SELinux, and Lua has no `mkdir` binding to fall back on. Directory
creation and cleanup are done from the host with `adb`; on the device the script only writes
files and calls `os.remove` (a stdlib call, not a shell). If `OUT_DIR` is missing, the script
aborts and prints the exact `adb root` / `mkdir` / `chmod` commands to fix it.

## Testing

```
lua tests/test_renefdump.lua
```

Unit tests cover the maps parser, range filter, filename sanitization, split arithmetic,
space guards, the missing-directory guard, and the dump loop (against a synthetic memory
file, including zero-filled gaps). Device verification is manual — see
`docs/manual-test.md`.
